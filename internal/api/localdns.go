// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/instances"
	"github.com/Kate-0713/pihole-rbac/internal/localdns"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// Local DNS records and CNAMEs, which Pi-hole keeps as strings in two config arrays (see internal/localdns). A record
// is matched by its key, never by Pi-hole's string, and a request names an existing one by its fields or by the
// string as read. The app builds every string it adds; the only strings it sends that it didn't build are ones it has
// just read, to delete them.
//
// Every write reads the instance first. Host records fan out as other writes do. Every CNAME change restarts FTL, so
// a CNAME write waits for each instance to answer again, and through a mirrored group goes one member at a time, the
// primary first, so the group never restarts at once.

const (
	maxReasonRunes = 200
	// cnameWriteLimit bounds a CNAME write through a mirrored group, inside the server's 60-second write timeout.
	cnameWriteLimit = 45 * time.Second
	// reasonRows is how many of an instance's newest local DNS audit rows are read for the records' reasons.
	reasonRows = 5000

	codeStopped   = "stopped"
	codeTimeLimit = "time_limit"
)

// dnsKind is what differs between host records and CNAMEs.
type dnsKind struct {
	kind             string // instances.LocalDNSRecord or LocalDNSCNAME
	what             string // for messages
	add, update, del string // audit actions
	values           func(*piholeapi.LocalDNS) []string
	key              func(value string) string
	restarts         bool // a change restarts FTL
	lockedOf         func(*piholeapi.LocalDNS) bool
	addOne           func(ctx context.Context, c *piholeapi.Client, value string, restart bool) error
	deleteOne        func(ctx context.Context, c *piholeapi.Client, value string, restart bool) error
}

var (
	hostKind = dnsKind{
		kind: instances.LocalDNSRecord, what: "local DNS record",
		add: audit.ActionDNSRecordAdd, update: audit.ActionDNSRecordUpdate, del: audit.ActionDNSRecordDelete,
		values:   func(d *piholeapi.LocalDNS) []string { return d.Hosts },
		key:      func(v string) string { return localdns.ParseHost(v).Key },
		lockedOf: func(d *piholeapi.LocalDNS) bool { return d.HostsLocked },
		addOne: func(ctx context.Context, c *piholeapi.Client, v string, _ bool) error {
			return c.AddHostRecord(ctx, v)
		},
		deleteOne: func(ctx context.Context, c *piholeapi.Client, v string, _ bool) error {
			return c.DeleteHostRecord(ctx, v)
		},
	}
	cnameKind = dnsKind{
		kind: instances.LocalDNSCNAME, what: "CNAME",
		add: audit.ActionCNAMEAdd, update: audit.ActionCNAMEUpdate, del: audit.ActionCNAMEDelete,
		values:   func(d *piholeapi.LocalDNS) []string { return d.CNAMEs },
		key:      func(v string) string { return localdns.ParseCNAME(v).Key },
		restarts: true,
		lockedOf: func(d *piholeapi.LocalDNS) bool { return d.CNAMEsLocked },
		addOne: func(ctx context.Context, c *piholeapi.Client, v string, restart bool) error {
			return c.AddCNAME(ctx, v, restart)
		},
		deleteOne: func(ctx context.Context, c *piholeapi.Client, v string, restart bool) error {
			return c.DeleteCNAME(ctx, v, restart)
		},
	}
)

// matching is every string in cur with key: usually one, but Pi-hole matches strings exactly, so two spellings of one
// record can both be there.
func (k dnsKind) matching(cur *piholeapi.LocalDNS, key string) []string {
	var out []string
	for _, v := range k.values(cur) {
		if k.key(v) == key {
			out = append(out, v)
		}
	}
	return out
}

// ListLocalDNS reads the records and CNAMEs: an instance's, or a mirrored group's primary's, with every member read
// for whether the app can change it.
func (s *Server) ListLocalDNS(ctx context.Context, req gen.ListLocalDNSRequestObject) (gen.ListLocalDNSResponseObject, error) {
	tg, err := s.resolveTarget(ctx, req.Target, rbac.LocalDNSView)
	if err != nil {
		return nil, err
	}
	n := len(tg.members)
	reads, outs, errs := make([]*piholeapi.LocalDNS, n), make([]outcome, n), make([]error, n)
	var wg sync.WaitGroup
	for i, m := range tg.members {
		wg.Go(func() {
			outs[i], errs[i] = s.write(ctx, m, func(ctx context.Context, c *piholeapi.Client) error {
				var err error
				reads[i], err = c.GetLocalDNS(ctx)
				return err
			})
		})
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	if !outs[0].ok() {
		return nil, outs[0].err
	}
	reasons, err := s.localDNSReasons(ctx, tg.primary().id)
	if err != nil {
		return nil, err
	}
	primary := reads[0]
	out := gen.LocalDNS{
		Records: []gen.DNSRecord{}, Cnames: []gen.CNAMERecord{}, Instances: []gen.LocalDNSInstance{},
		ReasonRequired: s.reasonRequired(),
	}
	for _, v := range primary.Hosts {
		h := localdns.ParseHost(v)
		r := gen.DNSRecord{Key: h.Key, Value: h.Value, Hostnames: nonNilStrings(h.Hostnames), Marks: dnsMarks(h.Marks)}
		if h.IP.IsValid() {
			ip := h.IP.String()
			r.Ip = &ip
		}
		if h.Comment != "" {
			r.Comment = &h.Comment
		}
		r.Reason = reasons[reasonKey{hostKind.kind, h.Key}]
		out.Records = append(out.Records, r)
	}
	for _, v := range primary.CNAMEs {
		c := localdns.ParseCNAME(v)
		r := gen.CNAMERecord{Key: c.Key, Value: c.Value, Aliases: nonNilStrings(c.Aliases), Marks: dnsMarks(c.Marks), Ttl: c.TTL}
		if c.Target != "" {
			r.Target = &c.Target
		}
		if c.Comment != "" {
			r.Comment = &c.Comment
		}
		r.Reason = reasons[reasonKey{cnameKind.kind, c.Key}]
		out.Cnames = append(out.Cnames, r)
	}
	for i, m := range tg.members {
		li := gen.LocalDNSInstance{Instance: m.name, InstanceId: m.id, Writable: "unknown"}
		if d := reads[i]; outs[i].ok() && d != nil {
			li.RecordsLocked, li.CnamesLocked = d.HostsLocked, d.CNAMEsLocked
			switch {
			case !d.AppSudo:
				li.Writable = "app_sudo_off"
			case d.ReadOnly:
				li.Writable = "locked"
			default:
				li.Writable = "ok"
			}
		}
		out.Instances = append(out.Instances, li)
	}
	if tg.isGroup() {
		out.Members = memberReads(tg, outs, nil)
		if rep, ok := s.driftReport(tg); ok && rep.PrimaryOK {
			drifted := rep.LocalDNSDrifted()
			out.Drifted = &drifted
		}
	}
	return gen.ListLocalDNS200JSONResponse(out), nil
}

func dnsMarks(marks []string) []gen.LocalDNSMark {
	out := make([]gen.LocalDNSMark, 0, len(marks))
	for _, m := range marks {
		out = append(out, gen.LocalDNSMark(m))
	}
	return out
}

type reasonKey struct{ kind, key string }

// localDNSReasons reads the latest reason for each record changed through the app on instance id: the newest add or
// change of its key, unless a delete of it is newer. A change that failed after adding the new record (added) still
// counts, since the record is there.
func (s *Server) localDNSReasons(ctx context.Context, id int64) (map[reasonKey]*gen.LocalDNSReason, error) {
	out := map[reasonKey]*gen.LocalDNSReason{}
	if s.Store == nil {
		return out, nil
	}
	rows, err := s.Store.Read().ListLocalDNSChanges(ctx, db.ListLocalDNSChangesParams{
		InstanceID: sql.NullInt64{Int64: id, Valid: true}, RowLimit: reasonRows,
	})
	if err != nil {
		return nil, err
	}
	done := map[reasonKey]bool{}
	for _, r := range rows {
		kind := hostKind.kind
		if strings.HasPrefix(r.Action, "cname_") {
			kind = cnameKind.kind
		}
		k := reasonKey{kind, r.RecordKey}
		if done[k] {
			continue
		}
		done[k] = true
		if strings.HasSuffix(r.Action, "_delete") {
			continue
		}
		out[k] = &gen.LocalDNSReason{Reason: r.Reason, By: r.Username, At: time.UnixMilli(r.At).UTC()}
	}
	return out, nil
}

// reasonRequired is the general setting, on when there are no settings (in tests).
func (s *Server) reasonRequired() bool {
	return s.LoginSettings == nil || s.LoginSettings.LocalDNSReasonRequired()
}

// checkReason checks a change's reason: trimmed, at most maxReasonRunes, plain text, and given while the setting
// requires one.
func (s *Server) checkReason(r *string) (string, error) {
	v := ""
	if r != nil {
		v = strings.TrimSpace(*r)
	}
	if err := checkText("reason", v, maxReasonRunes); err != nil {
		return "", err
	}
	if v == "" && s.reasonRequired() {
		return "", invalid("reason", "Give a reason for the change.")
	}
	return v, nil
}

// checkDirectoryName refuses, until confirm, a name that is or falls under a directory domain: Pi-hole answers local
// records before forwarding anything, so one there can shadow a real name. It returns whether the name was under one,
// for the audit row.
func (s *Server) checkDirectoryName(field, name string, confirm *gen.Confirm) (bool, error) {
	var baseDN string
	var extra []string
	if s.LoginSettings != nil {
		baseDN, extra = s.LoginSettings.LDAPBaseDN(), s.LoginSettings.LocalDNSExtraDomains()
	}
	domain, under := localdns.UnderDomain(name, localdns.DirectoryDomains(baseDN, extra))
	if !under {
		return false, nil
	}
	if confirm != nil && *confirm {
		return true, nil
	}
	return true, &rbac.Error{
		Code: rbac.CodeConfirmation,
		Message: fmt.Sprintf("%s is in the directory's domain %s. A local record there answers before the directory's own DNS, "+
			"and can hide a real name. Send it again with confirm=true to save it anyway.", name, domain),
		Details: map[string]any{"field": field, "domain": domain},
	}
}

// fieldRefused reports a localdns refusal as a validation error on its field.
func fieldRefused(err error) error {
	var fe *localdns.FieldError
	if errors.As(err, &fe) {
		return invalid(fe.Field, "%s.", fe.Message)
	}
	return err
}

// hostRefKey is the key of the record a request names: by Pi-hole's string, or by its address and hostname. The
// fields aren't held to the rules for new records, since an existing one may have any name Pi-hole accepts.
func hostRefKey(field string, r gen.DNSRecordRef) (string, error) {
	switch {
	case r.Value != nil && (r.Ip != nil || r.Hostname != nil):
		return "", invalid(field, "Name the record by its value, or by its ip and hostname, not both.")
	case r.Value != nil:
		if err := checkRefValue(field, *r.Value); err != nil {
			return "", err
		}
		return localdns.ParseHost(*r.Value).Key, nil
	case r.Ip == nil || r.Hostname == nil:
		return "", invalid(field, "Name the record by its value, or by its ip and hostname.")
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(*r.Ip))
	if err != nil {
		return "", invalid(field+".ip", "The address isn't a valid IPv4 or IPv6 address.")
	}
	name := strings.TrimSpace(*r.Hostname)
	if err := checkRefName(field+".hostname", name); err != nil {
		return "", err
	}
	return localdns.HostKey(ip, []string{name}), nil
}

// cnameRefKey is hostRefKey for a CNAME.
func cnameRefKey(field string, r gen.CNAMERef) (string, error) {
	switch {
	case r.Value != nil && (r.Alias != nil || r.Target != nil || r.Ttl != nil):
		return "", invalid(field, "Name the CNAME by its value, or by its alias, target and TTL, not both.")
	case r.Value != nil:
		if err := checkRefValue(field, *r.Value); err != nil {
			return "", err
		}
		return localdns.ParseCNAME(*r.Value).Key, nil
	case r.Alias == nil || r.Target == nil:
		return "", invalid(field, "Name the CNAME by its value, or by its alias, target and TTL.")
	}
	alias, target := strings.TrimSpace(*r.Alias), strings.TrimSpace(*r.Target)
	if err := checkRefName(field+".alias", alias); err != nil {
		return "", err
	}
	if err := checkRefName(field+".target", target); err != nil {
		return "", err
	}
	return localdns.CNAMEKey([]string{alias}, target, r.Ttl), nil
}

func checkRefValue(field, v string) error {
	if v == "" {
		return invalid(field+".value", "The value can't be empty.")
	}
	if strings.ContainsAny(v, "\r\n") {
		return invalid(field+".value", "The value can't contain line breaks.")
	}
	return checkText(field+".value", strings.ReplaceAll(v, "\t", " "), 1024)
}

func checkRefName(field, name string) error {
	if name == "" || strings.ContainsAny(name, " \t,#") {
		return invalid(field, "The name is empty, or has spaces, commas or # in it.")
	}
	return checkText(field, name, localdns.MaxNameLength)
}

// dnsMember is one member's part of a local DNS write, as the handler plans it from a fresh read.
type dnsMember struct {
	ops            []piholeapi.CNAMEOp // in order; nothing to send when empty
	thenDeletes    bool                // ops[0] adds and the rest delete: a failed add stops them (a change)
	alreadyPresent bool
	detail         map[string]any
}

// dnsResult is how one member's part of a local DNS write went, past its outcome.
type dnsResult struct {
	sent, alreadyPresent, added, restartPending bool
	detail                                      map[string]any
}

// apply sends a member's ops. A change adds first and deletes after, and stops if the add fails, so the old record is
// never removed without the new one in place. CNAME ops restart FTL once, at the end; if the deletes after a change's
// add all fail, FTL is restarted anyway so the new CNAME is served. It returns the member's error, whether the new
// record was added before a later failure, and whether (and from when) FTL was asked to restart.
func (k dnsKind) apply(ctx context.Context, c *piholeapi.Client, p dnsMember) (err error, added, restarted bool, since time.Time) {
	ignore := func(err error) error { // a delete of something already gone
		var se *piholeapi.StatusError
		if errors.As(err, &se) && se.Code == 404 {
			return nil
		}
		return err
	}
	ops := p.ops
	if p.thenDeletes {
		since = time.Now()
		if err := k.addOne(ctx, c, ops[0].Value, len(ops) == 1); err != nil && !errors.Is(err, piholeapi.ErrAlreadyPresent) {
			return err, false, false, since
		}
		if len(ops) == 1 {
			return nil, false, k.restarts, since
		}
		ops = ops[1:]
	}
	var errs []error
	if k.restarts {
		errs, restarted, since = c.ApplyCNAMEs(ctx, ops)
	} else {
		for _, op := range ops {
			if op.Delete {
				errs = append(errs, c.DeleteHostRecord(ctx, op.Value))
			} else {
				errs = append(errs, c.AddHostRecord(ctx, op.Value))
			}
		}
	}
	for _, e := range errs {
		if e = ignore(e); e != nil && err == nil {
			err = e
		}
	}
	if p.thenDeletes {
		added = err != nil
		if k.restarts && !restarted {
			since, restarted = time.Now(), true
			_ = c.RestartDNS(ctx) // the new CNAME is saved; this makes FTL serve it
		}
	}
	return err, added, restarted, since
}

// dnsWrite runs a local DNS write on every member of tg, planned for each by plan from a fresh read of it, and audits
// each member it sent something to as action. Host records go to every member at once; CNAMEs one member at a time,
// each waited for, stopping at the first member that fails or doesn't come back.
func (s *Server) dnsWrite(ctx context.Context, tg target, k dnsKind, action string, plan func(m instanceRef, cur *piholeapi.LocalDNS) (dnsMember, error)) ([]gen.LocalDNSWriteResult, bool, error) {
	n := len(tg.members)
	res := make([]dnsResult, n)
	deadline := time.Now().Add(cnameWriteLimit)
	member := func(ctx context.Context, i int, m instanceRef, c *piholeapi.Client) error {
		res[i] = dnsResult{}
		cur, err := c.GetLocalDNS(ctx)
		if err != nil {
			return err
		}
		p, err := plan(m, cur)
		if err != nil {
			return err
		}
		res[i].alreadyPresent, res[i].detail = p.alreadyPresent, p.detail
		if len(p.ops) == 0 {
			return nil
		}
		res[i].sent = true
		err, added, restarted, since := k.apply(ctx, c, p)
		res[i].added = added
		if restarted {
			wait := min(piholeapi.RestartWait, time.Until(deadline))
			if !tg.isGroup() {
				wait = piholeapi.RestartWait
			}
			if c.WaitRestarted(ctx, since, max(wait, time.Second)) != nil && ctx.Err() == nil {
				res[i].restartPending = true
			}
		}
		return err
	}

	var outs []outcome
	var err error
	if !k.restarts || !tg.isGroup() {
		outs, err = s.fanOut(ctx, tg, member)
	} else {
		outs, err = s.rollOut(ctx, tg, deadline, member,
			func(i int) bool { return res[i].sent },
			func(i int) bool { return res[i].restartPending })
	}
	for i, m := range tg.members {
		if res[i].sent {
			d := res[i].detail
			if res[i].added {
				d["added"] = true
			}
			if res[i].restartPending {
				d["restart_pending"] = true
			}
			s.auditPihole(ctx, m, action, outs[i].callErr, d)
		}
	}
	s.pokeDrift(ctx, tg)
	if err != nil {
		return nil, false, err
	}
	results := resultsOf(outs, func(i int, o outcome, st gen.WriteStatus, we *gen.WriteError) gen.LocalDNSWriteResult {
		r := gen.LocalDNSWriteResult{Instance: o.ref.name, InstanceId: o.ref.id, Status: st, Error: we}
		if res[i].alreadyPresent && o.ok() {
			r.AlreadyPresent = ptrTrue()
		}
		if res[i].added {
			r.Added = ptrTrue()
		}
		if res[i].restartPending {
			r.RestartPending = ptrTrue()
		}
		return r
	})
	multi, err := s.finishWrite(ctx, outs, results)
	return results, multi, err
}

func ptrTrue() *bool { t := true; return &t }

// rollOut is fanOut one member at a time, in order, for writes that restart FTL: a member that fails, or that
// stopped(i) says didn't come back, stops the write, and the members after it are skipped with code stopped; once
// deadline has passed the rest are skipped with code time_limit. A member that couldn't be used at all before
// anything was sent to it (sent(i) false: unreachable, its password refused, not set up) is skipped and the write goes
// on, as a gravity run does.
func (s *Server) rollOut(ctx context.Context, tg target, deadline time.Time, fn func(ctx context.Context, i int, m instanceRef, c *piholeapi.Client) error, sent, stopped func(i int) bool) ([]outcome, error) {
	outs := make([]outcome, len(tg.members))
	var reqErr error
	stop := ""
	for i, m := range tg.members {
		switch {
		case stop == "" && time.Now().After(deadline):
			stop = codeTimeLimit
		}
		if stop != "" {
			msg := fmt.Sprintf("Pi-hole %q wasn't changed: an earlier member failed, so the change stopped there.", m.name)
			if stop == codeTimeLimit {
				msg = fmt.Sprintf("Pi-hole %q wasn't changed: the change ran out of time. Try again for this member.", m.name)
			}
			outs[i] = outcome{ref: m, err: &piholeFailure{Instance: m.name, Err: &memberError{code: stop, message: msg}}}
			continue
		}
		var err error
		outs[i], err = s.write(ctx, m, func(ctx context.Context, c *piholeapi.Client) error { return fn(ctx, i, m, c) })
		if err != nil {
			reqErr, stop = err, codeStopped
			continue
		}
		if !outs[i].ok() && !sent(i) && memberDown(outs[i].err.Err) {
			outs[i].ran = false // reported as skipped
			continue
		}
		if (outs[i].ran && !outs[i].ok()) || stopped(i) {
			stop = codeStopped
		}
	}
	return outs, reqErr
}

// memberDown reports whether err means the instance couldn't be used at all, rather than refusing a request.
func memberDown(err error) bool {
	switch instances.Kind(err) {
	case piholeapi.CodeUnreachable, piholeapi.CodeAuthRejected, instances.CodePasswordMissing, instances.CodeMisconfigured:
		return true
	}
	return false
}

// dnsAnswer is how the write handlers return: 200 or 207.
func dnsAnswer[T any](results []gen.LocalDNSWriteResult, multi bool, err error, ok, partial func(gen.LocalDNSWriteResults) T) (T, error) {
	var zero T
	if err != nil {
		return zero, err
	}
	if multi {
		return partial(gen.LocalDNSWriteResults{Results: results}), nil
	}
	return ok(gen.LocalDNSWriteResults{Results: results}), nil
}

// dnsAdd adds value (with key) through tg. An instance that already has the record is a 409 for an instance target;
// a member of a mirrored group that has it is left alone and its result says already_present.
func (s *Server) dnsAdd(ctx context.Context, tg target, k dnsKind, key, value string, detail map[string]any) ([]gen.LocalDNSWriteResult, bool, error) {
	return s.dnsWrite(ctx, tg, k, k.add, func(m instanceRef, cur *piholeapi.LocalDNS) (dnsMember, error) {
		d := cloneDetail(detail)
		if len(k.matching(cur, key)) > 0 {
			if !tg.isGroup() {
				return dnsMember{}, &rbac.Error{
					Code:    rbac.CodeConflict,
					Message: fmt.Sprintf("Pi-hole %q already has that %s.", m.name, k.what),
					Details: map[string]any{"instance": m.name},
				}
			}
			return dnsMember{alreadyPresent: true, detail: d}, nil
		}
		return dnsMember{ops: []piholeapi.CNAMEOp{{Value: value}}, detail: d}, nil
	})
}

// dnsUpdate replaces the record with fromKey by value (with toKey) through tg: add, then delete every string with
// fromKey. A target or primary without the record is a 404; a member without it fails with not_found.
func (s *Server) dnsUpdate(ctx context.Context, tg target, k dnsKind, fromKey, toKey, value string, detail map[string]any) ([]gen.LocalDNSWriteResult, bool, error) {
	if err := s.dnsPrimaryHas(ctx, tg, k, fromKey); err != nil {
		return nil, false, err
	}
	return s.dnsWrite(ctx, tg, k, k.update, func(m instanceRef, cur *piholeapi.LocalDNS) (dnsMember, error) {
		old := k.matching(cur, fromKey)
		if len(old) == 0 {
			return dnsMember{}, tg.missing(m, fmt.Sprintf("There's no such %s on %s.", k.what, m.name))
		}
		d := cloneDetail(detail)
		d["key_before"], d["values_before"] = fromKey, old
		if fromKey == toKey {
			return dnsMember{detail: d}, nil // nothing to change
		}
		p := dnsMember{thenDeletes: true, detail: d, ops: []piholeapi.CNAMEOp{{Value: value}}}
		for _, v := range old {
			p.ops = append(p.ops, piholeapi.CNAMEOp{Delete: true, Value: v})
		}
		return p, nil
	})
}

// dnsDelete deletes every string with key through tg. A target or primary without the record is a 404; a member
// without it is already as asked.
func (s *Server) dnsDelete(ctx context.Context, tg target, k dnsKind, key string, detail map[string]any) ([]gen.LocalDNSWriteResult, bool, error) {
	if err := s.dnsPrimaryHas(ctx, tg, k, key); err != nil {
		return nil, false, err
	}
	return s.dnsWrite(ctx, tg, k, k.del, func(m instanceRef, cur *piholeapi.LocalDNS) (dnsMember, error) {
		old := k.matching(cur, key)
		if len(old) == 0 {
			if tg.isGroup() {
				return dnsMember{}, nil
			}
			return dnsMember{}, tg.missing(m, fmt.Sprintf("There's no such %s on %s.", k.what, m.name))
		}
		d := cloneDetail(detail)
		d["values"] = old
		p := dnsMember{detail: d}
		for _, v := range old {
			p.ops = append(p.ops, piholeapi.CNAMEOp{Delete: true, Value: v})
		}
		return p, nil
	})
}

// dnsPrimaryHas checks, through a mirrored group, that the primary has the record with key.
func (s *Server) dnsPrimaryHas(ctx context.Context, tg target, k dnsKind, key string) error {
	if !tg.isGroup() {
		return nil
	}
	return s.primaryHas(ctx, tg, "such "+k.what, func(ctx context.Context, c *piholeapi.Client) (bool, error) {
		cur, err := c.GetLocalDNS(ctx)
		if err != nil {
			return false, err
		}
		return len(k.matching(cur, key)) > 0, nil
	})
}

func cloneDetail(d map[string]any) map[string]any {
	out := make(map[string]any, len(d)+3)
	for k, v := range d {
		out[k] = v
	}
	return out
}

// dnsTarget resolves a local DNS write's target, narrowed by ?members=.
func (s *Server) dnsTarget(ctx context.Context, raw string, members *gen.Members) (target, error) {
	tg, err := s.resolveTarget(ctx, raw, rbac.LocalDNSEdit)
	if err != nil {
		return target{}, err
	}
	return tg.only(members)
}

func (s *Server) AddDNSRecord(ctx context.Context, req gen.AddDNSRecordRequestObject) (gen.AddDNSRecordResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, invalid("body", "The request body is missing.")
	}
	h, err := localdns.NewHost(b.Ip, b.Hostname)
	if err != nil {
		return nil, fieldRefused(err)
	}
	reason, err := s.checkReason(b.Reason)
	if err != nil {
		return nil, err
	}
	tg, err := s.dnsTarget(ctx, req.Target, req.Params.Members)
	if err != nil {
		return nil, err
	}
	under, err := s.checkDirectoryName("hostname", h.Hostnames[0], req.Params.Confirm)
	if err != nil {
		return nil, err
	}
	detail := map[string]any{"key": h.Key, "value": h.Value, "ip": h.IP.String(), "hostname": h.Hostnames[0], "reason": reason}
	if under {
		detail["directory_domain"] = true
	}
	results, multi, err := s.dnsAdd(ctx, tg, hostKind, h.Key, h.Value, detail)
	return dnsAnswer(results, multi, err,
		func(r gen.LocalDNSWriteResults) gen.AddDNSRecordResponseObject {
			return gen.AddDNSRecord200JSONResponse(r)
		},
		func(r gen.LocalDNSWriteResults) gen.AddDNSRecordResponseObject {
			return gen.AddDNSRecord207JSONResponse(r)
		})
}

func (s *Server) UpdateDNSRecord(ctx context.Context, req gen.UpdateDNSRecordRequestObject) (gen.UpdateDNSRecordResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, invalid("body", "The request body is missing.")
	}
	fromKey, err := hostRefKey("from", b.From)
	if err != nil {
		return nil, err
	}
	h, err := localdns.NewHost(b.To.Ip, b.To.Hostname)
	if err != nil {
		return nil, fieldRefused(prefixField(err, "to."))
	}
	reason, err := s.checkReason(b.Reason)
	if err != nil {
		return nil, err
	}
	tg, err := s.dnsTarget(ctx, req.Target, req.Params.Members)
	if err != nil {
		return nil, err
	}
	under, err := s.checkDirectoryName("to.hostname", h.Hostnames[0], req.Params.Confirm)
	if err != nil {
		return nil, err
	}
	detail := map[string]any{"key": h.Key, "value": h.Value, "ip": h.IP.String(), "hostname": h.Hostnames[0], "reason": reason}
	if under {
		detail["directory_domain"] = true
	}
	results, multi, err := s.dnsUpdate(ctx, tg, hostKind, fromKey, h.Key, h.Value, detail)
	return dnsAnswer(results, multi, err,
		func(r gen.LocalDNSWriteResults) gen.UpdateDNSRecordResponseObject {
			return gen.UpdateDNSRecord200JSONResponse(r)
		},
		func(r gen.LocalDNSWriteResults) gen.UpdateDNSRecordResponseObject {
			return gen.UpdateDNSRecord207JSONResponse(r)
		})
}

func (s *Server) DeleteDNSRecord(ctx context.Context, req gen.DeleteDNSRecordRequestObject) (gen.DeleteDNSRecordResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, invalid("body", "The request body is missing.")
	}
	key, err := hostRefKey("record", b.Record)
	if err != nil {
		return nil, err
	}
	reason, err := s.checkReason(b.Reason)
	if err != nil {
		return nil, err
	}
	tg, err := s.dnsTarget(ctx, req.Target, req.Params.Members)
	if err != nil {
		return nil, err
	}
	results, multi, err := s.dnsDelete(ctx, tg, hostKind, key, map[string]any{"key": key, "reason": reason})
	return dnsAnswer(results, multi, err,
		func(r gen.LocalDNSWriteResults) gen.DeleteDNSRecordResponseObject {
			return gen.DeleteDNSRecord200JSONResponse(r)
		},
		func(r gen.LocalDNSWriteResults) gen.DeleteDNSRecordResponseObject {
			return gen.DeleteDNSRecord207JSONResponse(r)
		})
}

func cnameDetail(c localdns.CNAME, reason string) map[string]any {
	d := map[string]any{"key": c.Key, "value": c.Value, "alias": c.Aliases[0], "target": c.Target, "reason": reason}
	if c.TTL != nil {
		d["ttl"] = *c.TTL
	}
	return d
}

func (s *Server) AddCNAME(ctx context.Context, req gen.AddCNAMERequestObject) (gen.AddCNAMEResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, invalid("body", "The request body is missing.")
	}
	c, err := localdns.NewCNAME(b.Alias, b.Target, b.Ttl)
	if err != nil {
		return nil, fieldRefused(err)
	}
	reason, err := s.checkReason(b.Reason)
	if err != nil {
		return nil, err
	}
	tg, err := s.dnsTarget(ctx, req.Target, req.Params.Members)
	if err != nil {
		return nil, err
	}
	under, err := s.checkDirectoryName("alias", c.Aliases[0], req.Params.Confirm)
	if err != nil {
		return nil, err
	}
	detail := cnameDetail(c, reason)
	if under {
		detail["directory_domain"] = true
	}
	results, multi, err := s.dnsAdd(ctx, tg, cnameKind, c.Key, c.Value, detail)
	return dnsAnswer(results, multi, err,
		func(r gen.LocalDNSWriteResults) gen.AddCNAMEResponseObject { return gen.AddCNAME200JSONResponse(r) },
		func(r gen.LocalDNSWriteResults) gen.AddCNAMEResponseObject { return gen.AddCNAME207JSONResponse(r) })
}

func (s *Server) UpdateCNAME(ctx context.Context, req gen.UpdateCNAMERequestObject) (gen.UpdateCNAMEResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, invalid("body", "The request body is missing.")
	}
	fromKey, err := cnameRefKey("from", b.From)
	if err != nil {
		return nil, err
	}
	c, err := localdns.NewCNAME(b.To.Alias, b.To.Target, b.To.Ttl)
	if err != nil {
		return nil, fieldRefused(prefixField(err, "to."))
	}
	reason, err := s.checkReason(b.Reason)
	if err != nil {
		return nil, err
	}
	tg, err := s.dnsTarget(ctx, req.Target, req.Params.Members)
	if err != nil {
		return nil, err
	}
	under, err := s.checkDirectoryName("to.alias", c.Aliases[0], req.Params.Confirm)
	if err != nil {
		return nil, err
	}
	detail := cnameDetail(c, reason)
	if under {
		detail["directory_domain"] = true
	}
	results, multi, err := s.dnsUpdate(ctx, tg, cnameKind, fromKey, c.Key, c.Value, detail)
	return dnsAnswer(results, multi, err,
		func(r gen.LocalDNSWriteResults) gen.UpdateCNAMEResponseObject {
			return gen.UpdateCNAME200JSONResponse(r)
		},
		func(r gen.LocalDNSWriteResults) gen.UpdateCNAMEResponseObject {
			return gen.UpdateCNAME207JSONResponse(r)
		})
}

func (s *Server) DeleteCNAME(ctx context.Context, req gen.DeleteCNAMERequestObject) (gen.DeleteCNAMEResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, invalid("body", "The request body is missing.")
	}
	key, err := cnameRefKey("cname", b.Cname)
	if err != nil {
		return nil, err
	}
	reason, err := s.checkReason(b.Reason)
	if err != nil {
		return nil, err
	}
	tg, err := s.dnsTarget(ctx, req.Target, req.Params.Members)
	if err != nil {
		return nil, err
	}
	results, multi, err := s.dnsDelete(ctx, tg, cnameKind, key, map[string]any{"key": key, "reason": reason})
	return dnsAnswer(results, multi, err,
		func(r gen.LocalDNSWriteResults) gen.DeleteCNAMEResponseObject {
			return gen.DeleteCNAME200JSONResponse(r)
		},
		func(r gen.LocalDNSWriteResults) gen.DeleteCNAMEResponseObject {
			return gen.DeleteCNAME207JSONResponse(r)
		})
}

// prefixField puts prefix in front of a localdns refusal's field ("to.hostname").
func prefixField(err error, prefix string) error {
	var fe *localdns.FieldError
	if errors.As(err, &fe) {
		return &localdns.FieldError{Field: prefix + fe.Field, Message: fe.Message}
	}
	return err
}

// localDNSKinds lists the kinds of local DNS entry for the drift report and reconcile.
var localDNSKinds = []string{instances.LocalDNSRecord, instances.LocalDNSCNAME}

func validLocalDNSKind(k string) bool { return slices.Contains(localDNSKinds, k) }
