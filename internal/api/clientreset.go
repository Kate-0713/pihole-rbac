// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/clientreset"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

// The handlers translate between the API's shapes and clientreset.Service. The rules service checks settings.manage
// itself, in its transaction; preview, run and a target's history check clientreset.run on the target here.

var errNoClientReset = errors.New("api: no client reset service configured")

const (
	defaultRunPage = 50
	maxRunPage     = 200
)

func rulesJSON(st clientreset.Settings) gen.ClientResetRules {
	out := gen.ClientResetRules{
		Rules:     make([]gen.ClientResetRule, 0, len(st.Rules)),
		Instances: make([]gen.ClientResetChoice, 0, len(st.Instances)),
		Groups:    make([]gen.ClientResetChoice, 0, len(st.Groups)),
	}
	for _, r := range st.Rules {
		out.Rules = append(out.Rules, gen.ClientResetRule{
			Scope: gen.ClientResetScope(r.Scope), Id: r.ScopeID, Name: r.ScopeName, CommentPrefix: r.Prefix,
			GroupMatch: gen.ClientResetMatch(r.Match), PiholeGroups: nonNilStrings(r.Groups),
		})
	}
	for _, c := range st.Instances {
		out.Instances = append(out.Instances, gen.ClientResetChoice{Id: c.ID, Name: c.Name})
	}
	for _, c := range st.Groups {
		out.Groups = append(out.Groups, gen.ClientResetChoice{Id: c.ID, Name: c.Name})
	}
	return out
}

func (s *Server) GetClientResetRules(ctx context.Context, _ gen.GetClientResetRulesRequestObject) (gen.GetClientResetRulesResponseObject, error) {
	if s.ClientReset == nil {
		return nil, errNoClientReset
	}
	st, err := s.ClientReset.Rules(ctx)
	if err != nil {
		return nil, err
	}
	return gen.GetClientResetRules200JSONResponse(rulesJSON(st)), nil
}

func (s *Server) SetClientResetRules(ctx context.Context, req gen.SetClientResetRulesRequestObject) (gen.SetClientResetRulesResponseObject, error) {
	if s.ClientReset == nil {
		return nil, errNoClientReset
	}
	if req.Body == nil {
		return nil, invalid("body", "The request body is missing.")
	}
	in := make([]clientreset.RuleInput, 0, len(req.Body.Rules))
	for _, r := range req.Body.Rules {
		in = append(in, clientreset.RuleInput{
			Scope: string(r.Scope), ID: r.Id, Prefix: r.CommentPrefix, Match: clientreset.Match(r.GroupMatch), Groups: r.PiholeGroups,
		})
	}
	st, err := s.ClientReset.SetRules(ctx, actor(ctx), in)
	if err != nil {
		return nil, err
	}
	return gen.SetClientResetRules200JSONResponse(rulesJSON(st)), nil
}

// clientResetTarget parses a {target} and checks the session holds clientreset.run on it. A target the user holds
// nothing on is a 403 whether or not it exists, as for every target.
func (s *Server) clientResetTarget(ctx context.Context, raw string) (rbac.Target, error) {
	if s.ClientReset == nil {
		return rbac.Target{}, errNoClientReset
	}
	t, err := rbac.ParseTarget(raw)
	if err != nil {
		return rbac.Target{}, invalid("target", `The target must be "i-<id>" for an instance or "g-<id>" for a mirrored group.`)
	}
	if err := s.authorize(ctx, rbac.ClientResetRun, t); err != nil {
		return rbac.Target{}, err
	}
	return t, nil
}

func (s *Server) PreviewClientReset(ctx context.Context, req gen.PreviewClientResetRequestObject) (gen.PreviewClientResetResponseObject, error) {
	t, err := s.clientResetTarget(ctx, req.Target)
	if err != nil {
		return nil, err
	}
	p, err := s.ClientReset.Preview(ctx, t)
	if err != nil {
		return nil, err
	}
	return gen.PreviewClientReset200JSONResponse(gen.ClientResetPreview{
		Target: p.Target, TargetName: p.TargetName, Rules: p.Rules, Instances: instanceResultsJSON(p.Instances),
	}), nil
}

// RunClientReset runs the target's rules and answers with the run as recorded, whatever its status. The gate gives
// this route a longer write deadline, since a run can take longer than the server's usual one.
func (s *Server) RunClientReset(ctx context.Context, req gen.RunClientResetRequestObject) (gen.RunClientResetResponseObject, error) {
	t, err := s.clientResetTarget(ctx, req.Target)
	if err != nil {
		return nil, err
	}
	run, err := s.ClientReset.Run(ctx, actor(ctx), clientreset.TriggerManual, t)
	if err != nil {
		return nil, err
	}
	s.pokeDrift(ctx, target{t: t})
	return gen.RunClientReset200JSONResponse(runJSON(run)), nil
}

func (s *Server) ListTargetClientResetRuns(ctx context.Context, req gen.ListTargetClientResetRunsRequestObject) (gen.ListTargetClientResetRunsResponseObject, error) {
	t, err := s.clientResetTarget(ctx, req.Target)
	if err != nil {
		return nil, err
	}
	out, err := s.runPage(ctx, t.String(), req.Params.Limit, req.Params.Cursor)
	if err != nil {
		return nil, err
	}
	n, err := s.ClientReset.RuleCount(ctx, t)
	if err != nil {
		return nil, err
	}
	out.Rules = &n
	return gen.ListTargetClientResetRuns200JSONResponse(out), nil
}

func (s *Server) ListClientResetRuns(ctx context.Context, req gen.ListClientResetRunsRequestObject) (gen.ListClientResetRunsResponseObject, error) {
	if s.ClientReset == nil {
		return nil, errNoClientReset
	}
	out, err := s.runPage(ctx, "", req.Params.Limit, req.Params.Cursor)
	if err != nil {
		return nil, err
	}
	return gen.ListClientResetRuns200JSONResponse(out), nil
}

// runPage reads a page of runs, newest first, for one target or every one (""). The cursor is the ID of the previous
// page's last run; IDs only grow, so a page never repeats or skips runs started meanwhile.
func (s *Server) runPage(ctx context.Context, target string, limitP *int, cursor *string) (gen.ClientResetRunList, error) {
	limit := defaultRunPage
	if limitP != nil {
		limit = *limitP
	}
	if limit < 1 || limit > maxRunPage {
		return gen.ClientResetRunList{}, invalid("limit", "The limit is 1 to %d.", maxRunPage)
	}
	var before int64
	if cursor != nil && *cursor != "" {
		var err error
		if before, err = decodeRunCursor(*cursor); err != nil {
			return gen.ClientResetRunList{}, invalid("cursor", "That cursor isn't one this server gave out.")
		}
	}
	runs, err := s.ClientReset.Runs(ctx, target, before, limit+1) // one more says whether there is another page
	if err != nil {
		return gen.ClientResetRunList{}, err
	}
	out := gen.ClientResetRunList{Runs: make([]gen.ClientResetRun, 0, min(len(runs), limit))}
	if len(runs) > limit {
		runs = runs[:limit]
		c := encodeRunCursor(runs[len(runs)-1].ID)
		out.NextCursor = &c
	}
	for _, r := range runs {
		out.Runs = append(out.Runs, runJSON(r))
	}
	return out, nil
}

func encodeRunCursor(id int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte("r:" + strconv.FormatInt(id, 10)))
}

func decodeRunCursor(c string) (int64, error) {
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return 0, err
	}
	n, ok := strings.CutPrefix(string(b), "r:")
	if !ok {
		return 0, errors.New("bad cursor")
	}
	id, err := strconv.ParseInt(n, 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("bad cursor")
	}
	return id, nil
}

func runJSON(r clientreset.Run) gen.ClientResetRun {
	out := gen.ClientResetRun{
		Id: r.ID, StartedAt: r.StartedAt.UTC(), Trigger: gen.ClientResetRunTrigger(r.Trigger), Username: r.Username,
		Target: r.Target, TargetName: r.TargetName, Status: gen.ClientResetRunStatus(r.Status),
		Rules: r.Summary.Rules, Instances: instanceResultsJSON(r.Summary.Instances),
	}
	if !r.FinishedAt.IsZero() {
		f := r.FinishedAt.UTC()
		out.FinishedAt = &f
	}
	if r.Summary.Error != "" {
		e := r.Summary.Error
		out.Error = &e
	}
	return out
}

func instanceResultsJSON(rs []clientreset.InstanceResult) []gen.ClientResetInstanceResult {
	out := make([]gen.ClientResetInstanceResult, 0, len(rs))
	for _, r := range rs {
		ir := gen.ClientResetInstanceResult{
			InstanceId: r.InstanceID, Instance: r.Instance, Primary: r.Primary,
			Status: gen.ClientResetInstanceResultStatus(r.Status), Unchanged: r.Unchanged,
			Reset: make([]gen.ClientResetChange, 0, len(r.Reset)), Failed: make([]gen.ClientResetFailure, 0, len(r.Failed)),
			Problems: make([]gen.ClientResetProblem, 0, len(r.Problems)),
		}
		if r.Code != "" {
			c := r.Code
			ir.Code = &c
		}
		for _, c := range r.Reset {
			ir.Reset = append(ir.Reset, gen.ClientResetChange{
				Client: c.Client, Comment: c.Comment, Prefix: c.Prefix,
				GroupsBefore: nonNilStrings(c.Before), GroupsAfter: nonNilStrings(c.After),
			})
		}
		for _, f := range r.Failed {
			ir.Failed = append(ir.Failed, gen.ClientResetFailure{Client: f.Client, Comment: f.Comment, Prefix: f.Prefix, Code: f.Code})
		}
		for _, p := range r.Problems {
			pr := gen.ClientResetProblem{Prefix: p.Prefix, Code: gen.ClientResetProblemCode(p.Code)}
			if len(p.Missing) > 0 {
				m := p.Missing
				pr.Missing = &m
			}
			ir.Problems = append(ir.Problems, pr)
		}
		out = append(out, ir)
	}
	return out
}
