// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/dhcp"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

// DHCP: leases, static leases and settings of a Pi-hole (see internal/dhcp). DHCP isn't mirrored: reads through a
// mirrored group are merged from its members, each row naming its instance, and a write through one is refused.
// Every settings change and every static lease change restarts FTL, so the app waits for the instance to answer
// again. Deleting a lease isn't a config write and waits for nothing.

// dhcpSettingKeys maps the names this API uses to FTL's, for the settings an environment variable can fix.
var dhcpSettingKeys = []struct{ api, ftl string }{
	{"active", "active"}, {"start", "start"}, {"end", "end"}, {"router", "router"}, {"netmask", "netmask"},
	{"lease_time", "leaseTime"}, {"ipv6", "ipv6"}, {"rapid_commit", "rapidCommit"}, {"multi_dns", "multiDNS"},
	{"ignore_unknown_clients", "ignoreUnknownClients"},
}

// dhcpTarget resolves a DHCP write's target: an instance only.
func (s *Server) dhcpTarget(ctx context.Context, raw string, p rbac.Permission) (target, error) {
	tg, err := s.resolveTarget(ctx, raw, p)
	if err != nil {
		return target{}, err
	}
	if tg.isGroup() {
		return target{}, invalid("target", "DHCP isn't mirrored. Choose a Pi-hole, not a mirrored group.")
	}
	return tg, nil
}

func dhcpWritable(d *piholeapi.DHCP) gen.DHCPWritable {
	switch {
	case !d.AppSudo:
		return "app_sudo_off"
	case d.ReadOnly:
		return "locked"
	}
	return "ok"
}

func settingsOf(d *piholeapi.DHCP) dhcp.Settings {
	return dhcp.Settings{
		Active: d.Active, Start: d.Start, End: d.End, Router: d.Router, Netmask: d.Netmask, LeaseTime: d.LeaseTime,
		IPv6: d.IPv6, RapidCommit: d.RapidCommit, MultiDNS: d.MultiDNS, IgnoreUnknownClients: d.IgnoreUnknownClients,
	}
}

func genSettings(s dhcp.Settings) gen.DHCPSettings {
	return gen.DHCPSettings{
		Active: s.Active, Start: s.Start, End: s.End, Router: s.Router, Netmask: s.Netmask, LeaseTime: s.LeaseTime,
		Ipv6: s.IPv6, RapidCommit: s.RapidCommit, MultiDns: s.MultiDNS, IgnoreUnknownClients: s.IgnoreUnknownClients,
	}
}

func lockedSettings(d *piholeapi.DHCP) []string {
	out := []string{}
	for _, k := range dhcpSettingKeys {
		if d.Locked[k.ftl] {
			out = append(out, k.api)
		}
	}
	return out
}

// dhcpReadAll reads every member of tg with fn and answers how each went. An instance target that fails, or a
// mirrored group none of whose members answer, fails the request.
func (s *Server) dhcpReadAll(ctx context.Context, tg target, fn func(ctx context.Context, i int, c *piholeapi.Client) error) ([]outcome, error) {
	outs, err := s.fanOut(ctx, tg, func(ctx context.Context, i int, _ instanceRef, c *piholeapi.Client) error {
		return fn(ctx, i, c)
	})
	if err != nil {
		return nil, err
	}
	if !anyOK(outs) {
		return nil, firstFailure(outs)
	}
	return outs, nil
}

// GetDHCP reads the settings of the instance, or of each enabled member of a mirrored group.
func (s *Server) GetDHCP(ctx context.Context, req gen.GetDHCPRequestObject) (gen.GetDHCPResponseObject, error) {
	tg, err := s.resolveTarget(ctx, req.Target, rbac.DHCPView)
	if err != nil {
		return nil, err
	}
	reads := make([]*piholeapi.DHCP, len(tg.members))
	outs, err := s.dhcpReadAll(ctx, tg, func(ctx context.Context, i int, c *piholeapi.Client) error {
		var err error
		reads[i], err = c.GetDHCP(ctx)
		return err
	})
	if err != nil {
		return nil, err
	}
	out := gen.DHCPSettingsRead{Instances: []gen.DHCPInstance{}, Members: memberReads(tg, outs, nil)}
	for i, m := range tg.members {
		if d := reads[i]; outs[i].ok() && d != nil {
			out.Instances = append(out.Instances, gen.DHCPInstance{
				Instance: m.name, InstanceId: m.id, Writable: dhcpWritable(d), Locked: lockedSettings(d),
				Settings: genSettings(settingsOf(d)),
			})
		}
	}
	return gen.GetDHCP200JSONResponse(out), nil
}

// ListDHCPLeases reads the leases of the instance, or of each member of a mirrored group that has DHCP on.
func (s *Server) ListDHCPLeases(ctx context.Context, req gen.ListDHCPLeasesRequestObject) (gen.ListDHCPLeasesResponseObject, error) {
	tg, err := s.resolveTarget(ctx, req.Target, rbac.DHCPView)
	if err != nil {
		return nil, err
	}
	n := len(tg.members)
	leases, active := make([][]piholeapi.Lease, n), make([]bool, n)
	var mu sync.Mutex
	outs, err := s.dhcpReadAll(ctx, tg, func(ctx context.Context, i int, c *piholeapi.Client) error {
		d, err := c.GetDHCP(ctx)
		if err != nil {
			return err
		}
		ls, err := c.GetLeases(ctx)
		if err != nil {
			return err
		}
		mu.Lock()
		leases[i], active[i] = ls, d.Active
		mu.Unlock()
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := gen.DHCPLeases{Leases: []gen.DHCPLease{}, Instances: []gen.DHCPLeaseSource{}, Members: memberReads(tg, outs, nil)}
	for i, m := range tg.members {
		if !outs[i].ok() {
			continue
		}
		// An instance's leases are shown as Pi-hole holds them, stale or not, with `active` saying so; a member's of a
		// mirrored group are left out while its DHCP is off, since the lease file may be old.
		include := !tg.isGroup() || active[i]
		out.Instances = append(out.Instances, gen.DHCPLeaseSource{Instance: m.name, InstanceId: m.id, Active: active[i], Included: include})
		if !include {
			continue
		}
		rows := slices.Clone(leases[i])
		slices.SortStableFunc(rows, func(a, b piholeapi.Lease) int {
			x, ex := netip.ParseAddr(a.IP)
			y, ey := netip.ParseAddr(b.IP)
			if ex != nil || ey != nil {
				return cmp.Compare(a.IP, b.IP)
			}
			return x.Compare(y)
		})
		for _, l := range rows {
			r := gen.DHCPLease{Instance: m.name, InstanceId: m.id, Ip: l.IP, Ipv6: l.IsIPv6(), Expires: &l.Expires}
			if l.HWAddr != "" && l.HWAddr != "*" {
				r.Hwaddr = &l.HWAddr
			}
			if l.Name != "" {
				r.Name = &l.Name
			}
			if l.ClientID != "" {
				r.ClientId = &l.ClientID
			}
			out.Leases = append(out.Leases, r)
		}
	}
	return gen.ListDHCPLeases200JSONResponse(out), nil
}

func genStatic(st dhcp.Static) gen.DHCPStaticLease {
	r := gen.DHCPStaticLease{Key: st.Key, Value: st.Value, Marks: []gen.DHCPStaticMark{}}
	for _, m := range st.Marks {
		r.Marks = append(r.Marks, gen.DHCPStaticMark(m))
	}
	if st.MAC != "" {
		r.Mac = &st.MAC
	}
	if st.IP != "" {
		r.Ip = &st.IP
	}
	if st.Hostname != "" {
		r.Hostname = &st.Hostname
	}
	return r
}

func parseStatics(hosts []string) []dhcp.Static {
	out := make([]dhcp.Static, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, dhcp.ParseStatic(h))
	}
	return out
}

// ListDHCPStaticLeases reads the static leases of the instance, or of each enabled member of a mirrored group.
func (s *Server) ListDHCPStaticLeases(ctx context.Context, req gen.ListDHCPStaticLeasesRequestObject) (gen.ListDHCPStaticLeasesResponseObject, error) {
	tg, err := s.resolveTarget(ctx, req.Target, rbac.DHCPView)
	if err != nil {
		return nil, err
	}
	reads := make([]*piholeapi.DHCP, len(tg.members))
	outs, err := s.dhcpReadAll(ctx, tg, func(ctx context.Context, i int, c *piholeapi.Client) error {
		var err error
		reads[i], err = c.GetDHCP(ctx)
		return err
	})
	if err != nil {
		return nil, err
	}
	out := gen.DHCPStaticLeases{Instances: []gen.DHCPStaticInstance{}, Members: memberReads(tg, outs, nil)}
	for i, m := range tg.members {
		d := reads[i]
		if !outs[i].ok() || d == nil {
			continue
		}
		in := gen.DHCPStaticInstance{
			Instance: m.name, InstanceId: m.id, Writable: dhcpWritable(d), Locked: d.Locked["hosts"],
			StaticLeases: []gen.DHCPStaticLease{},
		}
		if p, _, ok := dhcp.Subnet(settingsOf(d)); ok {
			ps := p.String()
			in.Subnet = &ps
		}
		for _, st := range parseStatics(d.Hosts) {
			in.StaticLeases = append(in.StaticLeases, genStatic(st))
		}
		out.Instances = append(out.Instances, in)
	}
	return gen.ListDHCPStaticLeases200JSONResponse(out), nil
}

// dhcpRun is what a write function reports of its instance.
type dhcpRun struct {
	sent, unchanged, added, restartPending bool
	detail                                 map[string]any
}

// waitRestarted waits for FTL to answer again after a write that restarted it; if it hasn't in time, the result
// says restart_pending.
func (r *dhcpRun) waitRestarted(ctx context.Context, c *piholeapi.Client, since time.Time) {
	if c.WaitRestarted(ctx, since, piholeapi.RestartWait) != nil && ctx.Err() == nil {
		r.restartPending = true
	}
}

// dhcpWrite runs a write on the instance of tg through fn, which reads it, checks the change, sends it (setting
// r.sent) and fills in r. A write that sent something is audited as action, whether it succeeded or not; one that
// didn't (refused, or nothing to change) isn't.
func (s *Server) dhcpWrite(ctx context.Context, tg target, action string, fn func(ctx context.Context, m instanceRef, c *piholeapi.Client, r *dhcpRun) error) (gen.DHCPWriteResults, error) {
	var r dhcpRun
	outs, err := s.fanOut(ctx, tg, func(ctx context.Context, _ int, m instanceRef, c *piholeapi.Client) error {
		return fn(ctx, m, c, &r)
	})
	if r.sent {
		d := r.detail
		if d == nil {
			d = map[string]any{}
		}
		if r.added {
			d["added"] = true
		}
		if r.restartPending {
			d["restart_pending"] = true
		}
		s.auditPihole(ctx, tg.members[0], action, outs[0].callErr, d)
	}
	if err != nil {
		return gen.DHCPWriteResults{}, err
	}
	results := resultsOf(outs, func(_ int, o outcome, st gen.WriteStatus, we *gen.WriteError) gen.DHCPWriteResult {
		res := gen.DHCPWriteResult{Instance: o.ref.name, InstanceId: o.ref.id, Status: st, Error: we}
		if o.ok() {
			if r.unchanged {
				res.Unchanged = ptrTrue()
			}
		}
		if r.added {
			res.Added = ptrTrue()
		}
		if r.restartPending {
			res.RestartPending = ptrTrue()
		}
		return res
	})
	if _, err := s.finishWrite(ctx, outs, results); err != nil {
		return gen.DHCPWriteResults{}, err
	}
	return gen.DHCPWriteResults{Results: results}, nil
}

// checkDHCPWritable refuses, before anything is sent, a Pi-hole that won't let the app change its config: the app
// would only get Pi-hole's refusal, and a change that restarted FTL isn't one to start when it can't succeed.
func checkDHCPWritable(d *piholeapi.DHCP) error {
	switch {
	case !d.AppSudo:
		return piholeapi.ErrAppSudoOff
	case d.ReadOnly:
		return piholeapi.ErrConfigLocked
	}
	return nil
}

// DeleteDHCPLease deletes a lease.
func (s *Server) DeleteDHCPLease(ctx context.Context, req gen.DeleteDHCPLeaseRequestObject) (gen.DeleteDHCPLeaseResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, invalid("body", "The request body is missing.")
	}
	a, err := netip.ParseAddr(strings.TrimSpace(b.Ip))
	if err != nil || a.Zone() != "" {
		return nil, invalid("ip", "The address isn't a valid IPv4 or IPv6 address.")
	}
	ip := a.String()
	tg, err := s.dhcpTarget(ctx, req.Target, rbac.DHCPEdit)
	if err != nil {
		return nil, err
	}
	res, err := s.dhcpWrite(ctx, tg, audit.ActionDHCPLeaseDelete, func(ctx context.Context, m instanceRef, c *piholeapi.Client, r *dhcpRun) error {
		leases, err := c.GetLeases(ctx)
		if err != nil {
			return err
		}
		i := slices.IndexFunc(leases, func(l piholeapi.Lease) bool { return l.IP == ip })
		if i < 0 {
			return tg.missing(m, fmt.Sprintf("%s has no lease for %s.", m.name, ip))
		}
		l := leases[i]
		r.detail = map[string]any{"ip": ip, "mac": l.HWAddr, "name": l.Name}
		r.sent = true
		err = c.DeleteLease(ctx, ip)
		var se *piholeapi.StatusError
		if errors.As(err, &se) && se.Code == http.StatusNotFound {
			return tg.missing(m, fmt.Sprintf("%s has no lease for %s.", m.name, ip)) // gone since it was read
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.DeleteDHCPLease200JSONResponse(res), nil
}

// staticRefKey is the key of the static lease a request names: by Pi-hole's string, or by its MAC and address.
func staticRefKey(field string, r gen.DHCPStaticLeaseRef) (string, error) {
	switch {
	case r.Value != nil && (r.Mac != nil || r.Ip != nil):
		return "", invalid(field, "Name the lease by its value, or by its mac and ip, not both.")
	case r.Value != nil:
		if err := checkRefValue(field, *r.Value); err != nil {
			return "", err
		}
		return dhcp.ParseStatic(*r.Value).Key, nil
	case r.Mac == nil || r.Ip == nil:
		return "", invalid(field, "Name the lease by its value, or by its mac and ip.")
	}
	hw, err := net.ParseMAC(strings.TrimSpace(*r.Mac))
	if err != nil {
		return "", invalid(field+".mac", "The hardware address isn't valid.")
	}
	a, err := netip.ParseAddr(strings.TrimSpace(*r.Ip))
	if err != nil {
		return "", invalid(field+".ip", "The address isn't a valid IPv4 address.")
	}
	return dhcp.StaticKey(hw.String(), a.String()), nil
}

func staticsWithKey(hosts []string, key string) []string {
	var out []string
	for _, h := range hosts {
		if dhcp.ParseStatic(h).Key == key {
			out = append(out, h)
		}
	}
	return out
}

// staticConflict refuses a lease that shares its MAC or address with another, not counting the leases in without.
func staticConflict(m instanceRef, hosts []string, without []string, st dhcp.Static, prefix string) error {
	var others []dhcp.Static
	for _, h := range hosts {
		if !slices.Contains(without, h) {
			others = append(others, dhcp.ParseStatic(h))
		}
	}
	field, other, found := dhcp.Conflict(others, st.MAC, st.IP)
	if !found {
		return nil
	}
	what := "hardware address"
	if field == "ip" {
		what = "address"
	}
	return &rbac.Error{
		Code:    rbac.CodeConflict,
		Message: fmt.Sprintf("Pi-hole %q already has a static lease with that %s.", m.name, what),
		Details: map[string]any{"instance": m.name, "field": prefix + field, "lease": other.Value},
	}
}

// applyStatic adds add (when not empty) and deletes dels, as one change: Pi-hole restarts once, on the last. It stops
// at the first failure; if something was changed by then and FTL hasn't been restarted, it is, so the change is served.
// A delete of something already gone isn't a failure.
func applyStatic(ctx context.Context, c *piholeapi.Client, r *dhcpRun, add string, dels []string) error {
	type op struct {
		value string
		del   bool
	}
	var ops []op
	if add != "" {
		ops = append(ops, op{value: add})
	}
	for _, d := range dels {
		ops = append(ops, op{value: d, del: true})
	}
	since := time.Now()
	changed, restarted := false, false
	var err error
	for i, o := range ops {
		last := i == len(ops)-1
		if o.del {
			err = c.DeleteStaticLease(ctx, o.value, last)
			var se *piholeapi.StatusError
			if errors.As(err, &se) && se.Code == http.StatusNotFound {
				err = nil
			}
		} else {
			err = c.AddStaticLease(ctx, o.value, last)
			if errors.Is(err, piholeapi.ErrAlreadyPresent) {
				err = nil
			}
		}
		if err != nil {
			if add != "" && o.del && changed {
				r.added = true
			}
			break
		}
		changed = true
		restarted = last
	}
	if err != nil && changed && !restarted {
		since = time.Now()
		if c.RestartDNS(ctx) == nil {
			restarted = true
		}
	}
	if restarted {
		r.waitRestarted(ctx, c, since)
	}
	return err
}

// AddDHCPStaticLease adds a static lease.
func (s *Server) AddDHCPStaticLease(ctx context.Context, req gen.AddDHCPStaticLeaseRequestObject) (gen.AddDHCPStaticLeaseResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, invalid("body", "The request body is missing.")
	}
	tg, err := s.dhcpTarget(ctx, req.Target, rbac.DHCPEdit)
	if err != nil {
		return nil, err
	}
	hostname := ""
	if b.Hostname != nil {
		hostname = *b.Hostname
	}
	res, err := s.dhcpWrite(ctx, tg, audit.ActionDHCPStaticAdd, func(ctx context.Context, m instanceRef, c *piholeapi.Client, r *dhcpRun) error {
		cur, err := c.GetDHCP(ctx)
		if err != nil {
			return err
		}
		set := settingsOf(cur)
		st, err := dhcp.NewStatic(b.Mac, b.Ip, hostname, &set)
		if err != nil {
			return fieldRefused(err)
		}
		if err := staticConflict(m, cur.Hosts, nil, st, ""); err != nil {
			return err
		}
		if err := checkStaticWritable(cur); err != nil {
			return err
		}
		r.detail = map[string]any{"key": st.Key, "value": st.Value, "mac": st.MAC, "ip": st.IP, "hostname": st.Hostname}
		r.sent = true
		return applyStatic(ctx, c, r, st.Value, nil)
	})
	if err != nil {
		return nil, err
	}
	return gen.AddDHCPStaticLease200JSONResponse(res), nil
}

func checkStaticWritable(d *piholeapi.DHCP) error {
	if err := checkDHCPWritable(d); err != nil {
		return err
	}
	if d.Locked["hosts"] {
		return piholeapi.ErrConfigLocked
	}
	return nil
}

// UpdateDHCPStaticLease replaces a static lease.
func (s *Server) UpdateDHCPStaticLease(ctx context.Context, req gen.UpdateDHCPStaticLeaseRequestObject) (gen.UpdateDHCPStaticLeaseResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, invalid("body", "The request body is missing.")
	}
	fromKey, err := staticRefKey("from", b.From)
	if err != nil {
		return nil, err
	}
	tg, err := s.dhcpTarget(ctx, req.Target, rbac.DHCPEdit)
	if err != nil {
		return nil, err
	}
	hostname := ""
	if b.To.Hostname != nil {
		hostname = *b.To.Hostname
	}
	res, err := s.dhcpWrite(ctx, tg, audit.ActionDHCPStaticUpdate, func(ctx context.Context, m instanceRef, c *piholeapi.Client, r *dhcpRun) error {
		cur, err := c.GetDHCP(ctx)
		if err != nil {
			return err
		}
		old := staticsWithKey(cur.Hosts, fromKey)
		if len(old) == 0 {
			return tg.missing(m, fmt.Sprintf("There's no such static lease on %s.", m.name))
		}
		set := settingsOf(cur)
		st, err := dhcp.NewStatic(b.To.Mac, b.To.Ip, hostname, &set)
		if err != nil {
			return fieldRefused(prefixField(err, "to."))
		}
		if len(old) == 1 && old[0] == st.Value {
			r.unchanged = true
			return nil
		}
		if err := staticConflict(m, cur.Hosts, old, st, "to."); err != nil {
			return err
		}
		if err := checkStaticWritable(cur); err != nil {
			return err
		}
		r.detail = map[string]any{
			"key_before": fromKey, "values_before": old,
			"key": st.Key, "value": st.Value, "mac": st.MAC, "ip": st.IP, "hostname": st.Hostname,
		}
		add := st.Value
		var dels []string
		for _, v := range old {
			if v == st.Value {
				add = "" // already there; only the other spellings go
				continue
			}
			dels = append(dels, v)
		}
		r.sent = true
		return applyStatic(ctx, c, r, add, dels)
	})
	if err != nil {
		return nil, err
	}
	return gen.UpdateDHCPStaticLease200JSONResponse(res), nil
}

// DeleteDHCPStaticLease deletes a static lease.
func (s *Server) DeleteDHCPStaticLease(ctx context.Context, req gen.DeleteDHCPStaticLeaseRequestObject) (gen.DeleteDHCPStaticLeaseResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, invalid("body", "The request body is missing.")
	}
	key, err := staticRefKey("lease", b.Lease)
	if err != nil {
		return nil, err
	}
	tg, err := s.dhcpTarget(ctx, req.Target, rbac.DHCPEdit)
	if err != nil {
		return nil, err
	}
	res, err := s.dhcpWrite(ctx, tg, audit.ActionDHCPStaticDelete, func(ctx context.Context, m instanceRef, c *piholeapi.Client, r *dhcpRun) error {
		cur, err := c.GetDHCP(ctx)
		if err != nil {
			return err
		}
		old := staticsWithKey(cur.Hosts, key)
		if len(old) == 0 {
			return tg.missing(m, fmt.Sprintf("There's no such static lease on %s.", m.name))
		}
		if err := checkStaticWritable(cur); err != nil {
			return err
		}
		r.detail = map[string]any{"key": key, "values": old}
		r.sent = true
		return applyStatic(ctx, c, r, "", old)
	})
	if err != nil {
		return nil, err
	}
	return gen.DeleteDHCPStaticLease200JSONResponse(res), nil
}

// dhcpChange is one setting that a change alters.
type dhcpChange struct {
	name     string // the API's name
	from, to any
	confirm  bool // needs confirm=true
}

// dhcpChanges lists the settings that differ between old and cur, in a fixed order.
func dhcpChanges(old, cur dhcp.Settings) []dhcpChange {
	var out []dhcpChange
	add := func(name string, from, to any, confirm bool) {
		if from != to {
			out = append(out, dhcpChange{name, from, to, confirm})
		}
	}
	add("active", old.Active, cur.Active, true)
	add("start", old.Start, cur.Start, true)
	add("end", old.End, cur.End, true)
	add("router", old.Router, cur.Router, true)
	add("netmask", old.Netmask, cur.Netmask, true)
	add("lease_time", old.LeaseTime, cur.LeaseTime, false)
	add("ipv6", old.IPv6, cur.IPv6, false)
	add("rapid_commit", old.RapidCommit, cur.RapidCommit, false)
	add("multi_dns", old.MultiDNS, cur.MultiDNS, false)
	add("ignore_unknown_clients", old.IgnoreUnknownClients, cur.IgnoreUnknownClients, true)
	return out
}

func describeChange(c dhcpChange) string {
	if c.name == "active" {
		if c.to == true {
			return "Turn DHCP on"
		}
		return "Turn DHCP off"
	}
	show := func(v any) string {
		if s, ok := v.(string); ok && s == "" {
			return "(empty)"
		}
		if b, ok := v.(bool); ok {
			if b {
				return "on"
			}
			return "off"
		}
		return fmt.Sprint(v)
	}
	return fmt.Sprintf("%s: %s to %s", c.name, show(c.from), show(c.to))
}

// otherDHCPActive names the other enabled instances that have DHCP on, as far as they can be read.
func (s *Server) otherDHCPActive(ctx context.Context, self int64) []string {
	insts, err := s.Instances.List(ctx)
	if err != nil {
		return nil
	}
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		out = []string{}
	)
	for _, in := range insts {
		if !in.Enabled || in.ID == self {
			continue
		}
		wg.Go(func() {
			var on bool
			err := s.Instances.Pool.Do(ctx, in.ID, func(ctx context.Context, c *piholeapi.Client) error {
				d, err := c.GetDHCP(ctx)
				if err == nil {
					on = d.Active
				}
				return err
			})
			if err == nil && on {
				mu.Lock()
				out = append(out, in.Name)
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	slices.Sort(out)
	return out
}

// UpdateDHCPSettings changes the DHCP settings of an instance.
func (s *Server) UpdateDHCPSettings(ctx context.Context, req gen.UpdateDHCPSettingsRequestObject) (gen.UpdateDHCPSettingsResponseObject, error) {
	b := req.Body
	if b == nil {
		return nil, invalid("body", "The request body is missing.")
	}
	tg, err := s.dhcpTarget(ctx, req.Target, rbac.DHCPConfig)
	if err != nil {
		return nil, err
	}
	confirmed := req.Params.Confirm != nil && *req.Params.Confirm
	res, err := s.dhcpWrite(ctx, tg, audit.ActionDHCPSettingsUpdate, func(ctx context.Context, m instanceRef, c *piholeapi.Client, r *dhcpRun) error {
		cur, err := c.GetDHCP(ctx)
		if err != nil {
			return err
		}
		old := settingsOf(cur)
		next := old
		setString := func(dst *string, v *string) {
			if v != nil {
				*dst = *v
			}
		}
		setBool := func(dst *bool, v *bool) {
			if v != nil {
				*dst = *v
			}
		}
		setBool(&next.Active, b.Active)
		setString(&next.Start, b.Start)
		setString(&next.End, b.End)
		setString(&next.Router, b.Router)
		setString(&next.Netmask, b.Netmask)
		setString(&next.LeaseTime, b.LeaseTime)
		setBool(&next.IPv6, b.Ipv6)
		setBool(&next.RapidCommit, b.RapidCommit)
		setBool(&next.MultiDNS, b.MultiDns)
		setBool(&next.IgnoreUnknownClients, b.IgnoreUnknownClients)
		next = dhcp.Normalize(next)
		if err := dhcp.CheckSettings(next); err != nil {
			return fieldRefused(err)
		}
		changes := dhcpChanges(old, next)
		if len(changes) == 0 {
			r.unchanged = true
			return nil
		}
		if err := checkDHCPWritable(cur); err != nil {
			return err
		}
		keys := map[string]string{}
		for _, k := range dhcpSettingKeys {
			keys[k.api] = k.ftl
		}
		for _, ch := range changes {
			if cur.Locked[keys[ch.name]] {
				return piholeapi.ErrConfigLocked
			}
		}
		if !confirmed {
			var summary []string
			needs := false
			for _, ch := range changes {
				needs = needs || ch.confirm
				summary = append(summary, describeChange(ch))
			}
			if needs {
				details := map[string]any{"summary": summary, "instance": m.name}
				msg := fmt.Sprintf("This restarts DNS and DHCP on Pi-hole %q, and nothing is answered while it does: %s. "+
					"Send it again with confirm=true to go ahead.", m.name, strings.Join(summary, "; "))
				if !old.Active && next.Active {
					if others := s.otherDHCPActive(ctx, m.id); len(others) > 0 {
						details["other_active"] = others
						msg += fmt.Sprintf(" DHCP is already on for %s: two DHCP servers on one network hand out clashing addresses.", quoted(others))
					}
				}
				return &rbac.Error{Code: rbac.CodeConfirmation, Message: msg, Details: details}
			}
		}
		patch := piholeapi.DHCPPatch{}
		detail := map[string]any{}
		for _, ch := range changes {
			detail[ch.name] = map[string]any{"from": ch.from, "to": ch.to}
			switch ch.name {
			case "active":
				patch.Active = &next.Active
			case "start":
				patch.Start = &next.Start
			case "end":
				patch.End = &next.End
			case "router":
				patch.Router = &next.Router
			case "netmask":
				patch.Netmask = &next.Netmask
			case "lease_time":
				patch.LeaseTime = &next.LeaseTime
			case "ipv6":
				patch.IPv6 = &next.IPv6
			case "rapid_commit":
				patch.RapidCommit = &next.RapidCommit
			case "multi_dns":
				patch.MultiDNS = &next.MultiDNS
			case "ignore_unknown_clients":
				patch.IgnoreUnknownClients = &next.IgnoreUnknownClients
			}
		}
		r.detail = map[string]any{"changes": detail}
		r.sent = true
		since := time.Now()
		if err := c.PatchDHCP(ctx, patch, true); err != nil {
			return err
		}
		r.waitRestarted(ctx, c, since)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return gen.UpdateDHCPSettings200JSONResponse(res), nil
}
