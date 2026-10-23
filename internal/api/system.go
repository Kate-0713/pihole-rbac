// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"io/fs"
	"slices"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
)

var errNoSecrets = errors.New("api: no secrets manager configured")

// ListSecrets says which secrets are set and where each came from, never their values. An instance in the database
// whose password variable doesn't exist at all is listed as not set, so the System page can say what to define.
func (s *Server) ListSecrets(ctx context.Context, _ gen.ListSecretsRequestObject) (gen.ListSecretsResponseObject, error) {
	if s.Secrets == nil {
		return nil, errNoSecrets
	}
	status := s.Secrets.Status()
	envNames, err := s.Store.Read().ListInstanceEnvNames(ctx)
	if err != nil {
		return nil, err
	}
	known := make(map[string]bool, len(status))
	for _, st := range status {
		known[st.Name] = true
	}
	for _, env := range envNames {
		if name := secrets.InstanceVar(env); !known[name] {
			status = append(status, secrets.Status{Name: name})
		}
	}

	out := make([]gen.SecretStatus, 0, len(status))
	for _, st := range status {
		item := gen.SecretStatus{Name: st.Name, Kind: gen.SecretStatusKind(secrets.KindOf(st.Name)), Set: st.Set}
		if st.Set {
			src := gen.SecretStatusSource(st.Source)
			item.Source = &src
		}
		out = append(out, item)
	}
	return gen.ListSecrets200JSONResponse{Secrets: out}, nil
}

// ReloadSecrets re-reads the secrets that came from *_FILE variables and audits what changed and what failed. A
// secret that failed keeps its old value, so a partial failure is still a 200 that names it.
func (s *Server) ReloadSecrets(ctx context.Context, _ gen.ReloadSecretsRequestObject) (gen.ReloadSecretsResponseObject, error) {
	if s.Secrets == nil {
		return nil, errNoSecrets
	}
	ri := info(ctx)
	res := s.Secrets.Reload()

	out := gen.ReloadResult{
		Changed:      append([]string{}, res.Changed...),
		Failed:       make([]gen.ReloadFailure, 0, len(res.Failed)),
		SessionEnded: slices.Contains(res.Changed, secrets.VarSessionKey),
	}
	failedNames := make([]string, 0, len(res.Failed))
	for _, f := range res.Failed {
		out.Failed = append(out.Failed, gen.ReloadFailure{Name: f.Name, Message: reloadMessage(f)})
		failedNames = append(failedNames, f.Name)
	}

	// Names only; the error texts can quote file paths, which stay out of the audit log.
	entry := audit.Entry{
		UserID: ri.sess.UserID, Username: ri.sess.Username, Action: audit.ActionConfigReload, IP: ri.ip,
		Detail: map[string]any{"changed": out.Changed, "failed": failedNames},
	}
	if len(res.Failed) > 0 {
		entry.Err = errors.New("some secrets failed to reload")
	}
	if err := s.Audit.Record(ctx, s.Store, entry); err != nil {
		return nil, err
	}
	return gen.ReloadSecrets200JSONResponse(out), nil
}

// reloadMessage is a failure's error text without the file's path, which the secrets endpoints keep to themselves:
// "PIHOLE_RBAC_LDAP_BIND_PASSWORD_FILE: no such file or directory".
func reloadMessage(f secrets.Failure) string {
	var pe *fs.PathError
	if errors.As(f.Err, &pe) {
		return f.Name + "_FILE: " + pe.Err.Error()
	}
	return f.Err.Error()
}
