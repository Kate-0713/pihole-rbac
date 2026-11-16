// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/api/gen"
	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
)

var dhcpOn = piholetest.DHCPSettings{
	Active: true, Start: "192.168.1.100", End: "192.168.1.200", Router: "192.168.1.1", Netmask: "255.255.255.0", LeaseTime: "24h",
}

var dhcpOff = piholetest.DHCPSettings{
	Start: "192.168.1.100", End: "192.168.1.200", Router: "192.168.1.1", Netmask: "255.255.255.0", LeaseTime: "24h",
}

func TestDHCPReads(t *testing.T) {
	te := newDNSEnv(t)
	te.ph.SetDHCP(dhcpOn)
	te.ph.SetStaticLeases([]string{"AA:BB:CC:00:00:01,192.168.1.10,nas", "aa:bb:cc:00:00:02,192.168.1.11,tv,12h", "garbage line"})
	te.ph.SetLeases([]piholetest.DHCPLease{
		{Expires: 2000000000, HWAddr: "aa:bb:cc:00:00:09", IP: "192.168.1.120", Name: "*", ClientID: "*"},
		{Expires: 0, HWAddr: "aa:bb:cc:00:00:08", IP: "192.168.1.20", Name: "laptop", ClientID: "01:aa"},
		{Expires: 2000000001, HWAddr: "12345", IP: "fd00::5", Name: "*", ClientID: "*"},
	})

	out := decode[gen.DHCPSettingsRead](t, te.admin.do(http.MethodGet, te.path("/dhcp"), nil))
	if len(out.Instances) != 1 || out.Members != nil {
		t.Fatalf("settings %+v", out)
	}
	in := out.Instances[0]
	if in.Writable != "ok" || !in.Settings.Active || in.Settings.Start != "192.168.1.100" || in.Settings.LeaseTime != "24h" || len(in.Locked) != 0 {
		t.Errorf("instance %+v", in)
	}

	leases := decode[gen.DHCPLeases](t, te.admin.do(http.MethodGet, te.path("/dhcp/leases"), nil))
	var ips []string
	for _, l := range leases.Leases {
		ips = append(ips, l.Ip)
	}
	if !slices.Equal(ips, []string{"192.168.1.20", "192.168.1.120", "fd00::5"}) {
		t.Errorf("leases in order %v", ips)
	}
	if l := leases.Leases[0]; l.Name == nil || *l.Name != "laptop" || l.ClientId == nil || l.Expires == nil || *l.Expires != 0 || l.Ipv6 {
		t.Errorf("lease with a name %+v", l)
	}
	if l := leases.Leases[1]; l.Name != nil || l.ClientId != nil || l.Hwaddr == nil {
		t.Errorf("lease without one %+v", l)
	}
	if l := leases.Leases[2]; !l.Ipv6 {
		t.Errorf("IPv6 lease %+v", l)
	}
	if len(leases.Instances) != 1 || !leases.Instances[0].Active || !leases.Instances[0].Included {
		t.Errorf("sources %+v", leases.Instances)
	}

	// With DHCP off an instance still shows what the lease file holds.
	te.ph.SetDHCP(dhcpOff)
	leases = decode[gen.DHCPLeases](t, te.admin.do(http.MethodGet, te.path("/dhcp/leases"), nil))
	if len(leases.Leases) != 3 || leases.Instances[0].Active || !leases.Instances[0].Included {
		t.Errorf("leases with DHCP off %+v", leases)
	}

	st := decode[gen.DHCPStaticLeases](t, te.admin.do(http.MethodGet, te.path("/dhcp/static-leases"), nil))
	if len(st.Instances) != 1 || st.Instances[0].Subnet == nil || *st.Instances[0].Subnet != "192.168.1.0/24" {
		t.Fatalf("static leases %+v", st)
	}
	type row struct{ key, marks string }
	var got []row
	for _, l := range st.Instances[0].StaticLeases {
		m := ""
		for _, k := range l.Marks {
			m += string(k) + ","
		}
		got = append(got, row{l.Key, m})
	}
	want := []row{{"aa:bb:cc:00:00:01|192.168.1.10", ""}, {"aa:bb:cc:00:00:02|192.168.1.11", "extra_fields,"}, {"garbage line", "unparsed,"}}
	if !slices.Equal(got, want) {
		t.Errorf("static leases %v, want %v", got, want)
	}
	if l := st.Instances[0].StaticLeases[0]; l.Value != "AA:BB:CC:00:00:01,192.168.1.10,nas" || l.Mac == nil || *l.Mac != "aa:bb:cc:00:00:01" || l.Hostname == nil || *l.Hostname != "nas" {
		t.Errorf("first static lease %+v", l)
	}

	for _, c := range []struct {
		setup func()
		want  string
	}{
		{func() { te.ph.SetAppSudo(false) }, "app_sudo_off"},
		{func() { te.ph.SetAppSudo(true); te.ph.SetConfigReadOnly(true) }, "locked"},
		{func() { te.ph.SetConfigReadOnly(false); te.ph.LockDHCP("start", "leaseTime", "hosts") }, "ok"},
	} {
		c.setup()
		in := decode[gen.DHCPSettingsRead](t, te.admin.do(http.MethodGet, te.path("/dhcp"), nil)).Instances[0]
		if string(in.Writable) != c.want {
			t.Errorf("writable %s, want %s", in.Writable, c.want)
		}
	}
	in = decode[gen.DHCPSettingsRead](t, te.admin.do(http.MethodGet, te.path("/dhcp"), nil)).Instances[0]
	if !slices.Equal(in.Locked, []string{"start", "lease_time"}) {
		t.Errorf("locked %v", in.Locked)
	}
	if s := decode[gen.DHCPStaticLeases](t, te.admin.do(http.MethodGet, te.path("/dhcp/static-leases"), nil)); !s.Instances[0].Locked {
		t.Errorf("static leases not locked: %+v", s.Instances[0])
	}
	if w := te.piholeWrites(); len(w) != 0 {
		t.Errorf("reads wrote %v", w)
	}
}

func TestDHCPLeaseDelete(t *testing.T) {
	te := newDNSEnv(t)
	te.ph.SetDHCP(dhcpOn)
	te.ph.SetLeases([]piholetest.DHCPLease{
		{Expires: 2000000000, HWAddr: "aa:bb:cc:00:00:09", IP: "192.168.1.120", Name: "phone", ClientID: "*"},
		{Expires: 2000000000, HWAddr: "aa:bb:cc:00:00:08", IP: "192.168.1.121", Name: "*", ClientID: "*"},
	})
	path := te.path("/dhcp/leases")
	restarts := te.ph.Restarts()

	res := te.admin.do(http.MethodDelete, path, gen.DHCPLeaseRef{Ip: " 192.168.1.120 "})
	mustStatus(t, res, http.StatusOK)
	if got := summarise(results(t, res)); !slices.Equal(got, []string{"pihole1:ok"}) {
		t.Errorf("results %v", got)
	}
	if te.ph.LeaseDeletes() != 1 || len(te.ph.Leases()) != 1 || te.ph.Restarts() != restarts {
		t.Errorf("deletes %d, leases %v, restarts %d", te.ph.LeaseDeletes(), te.ph.Leases(), te.ph.Restarts()-restarts)
	}
	row, d := te.lastAudit()
	if row.Action != audit.ActionDHCPLeaseDelete || d["ip"] != "192.168.1.120" || d["mac"] != "aa:bb:cc:00:00:09" || d["name"] != "phone" {
		t.Errorf("audit %s %v", row.Action, d)
	}

	for _, c := range []struct {
		name string
		ip   string
		code string
		set  func()
	}{
		{"a lease it doesn't have", "192.168.1.50", "not_found", nil},
		{"not an address", "192.168.1.x", "validation_failed", nil},
		{"an address with a zone", "fe80::1%eth0", "validation_failed", nil},
		{"DHCP off", "192.168.1.121", "pihole_dhcp_off", func() { te.ph.SetDHCP(dhcpOff) }},
		{"a busy resolver", "192.168.1.121", "pihole_busy", func() { te.ph.SetDHCP(dhcpOn); te.ph.SetLeaseBusy(true) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.set != nil {
				c.set()
			}
			deletes, audits := te.ph.LeaseDeletes(), te.auditCount()
			res := te.admin.do(http.MethodDelete, path, gen.DHCPLeaseRef{Ip: c.ip})
			if res.errorCode() != c.code {
				t.Fatalf("%d %s, want %s", res.Code, res.Body, c.code)
			}
			if c.code == "validation_failed" || c.code == "not_found" {
				if te.ph.LeaseDeletes() != deletes || te.auditCount() != audits {
					t.Errorf("a refused request was sent or audited")
				}
				return
			}
			if res.Code != http.StatusConflict || te.auditCount() != audits+1 {
				t.Errorf("status %d, audits %d", res.Code, te.auditCount()-audits)
			}
			if _, d := te.lastAudit(); d["error_code"] != c.code {
				t.Errorf("audit %v", d)
			}
		})
	}
}

func TestDHCPStaticLeases(t *testing.T) {
	te := newDNSEnv(t)
	te.ph.SetDHCP(dhcpOn)
	te.ph.SetStaticLeases([]string{"aa:bb:cc:00:00:01,192.168.1.10,nas", "aa:bb:cc:00:00:02,192.168.1.11,tv,12h", "garbage line"})
	path := te.path("/dhcp/static-leases")
	count := func() int { return len(te.ph.StaticLeases()) }

	t.Run("add", func(t *testing.T) {
		restarts := te.ph.Restarts()
		res := te.admin.do(http.MethodPost, path, gen.DHCPStaticLeaseInput{Mac: " AA-BB-CC-00-00-03 ", Ip: "192.168.1.12", Hostname: strp("Printer")})
		mustStatus(t, res, http.StatusOK)
		if !slices.Contains(te.ph.StaticLeases(), "aa:bb:cc:00:00:03,192.168.1.12,printer") || te.ph.Restarts() != restarts+1 {
			t.Errorf("leases %v, restarts %d", te.ph.StaticLeases(), te.ph.Restarts()-restarts)
		}
		row, d := te.lastAudit()
		if row.Action != audit.ActionDHCPStaticAdd || d["mac"] != "aa:bb:cc:00:00:03" || d["hostname"] != "printer" {
			t.Errorf("audit %s %v", row.Action, d)
		}
	})

	t.Run("change", func(t *testing.T) {
		restarts := te.ph.Restarts()
		res := te.admin.do(http.MethodPatch, path, gen.DHCPStaticLeaseUpdate{
			From: gen.DHCPStaticLeaseRef{Mac: strp("AA:BB:CC:00:00:03"), Ip: strp("192.168.1.12")},
			To:   gen.DHCPStaticLeaseInput{Mac: "aa:bb:cc:00:00:03", Ip: "192.168.1.13", Hostname: strp("printer")},
		})
		mustStatus(t, res, http.StatusOK)
		l := te.ph.StaticLeases()
		if !slices.Contains(l, "aa:bb:cc:00:00:03,192.168.1.13,printer") || slices.Contains(l, "aa:bb:cc:00:00:03,192.168.1.12,printer") {
			t.Errorf("leases %v", l)
		}
		if te.ph.Restarts() != restarts+1 {
			t.Errorf("restarts %d, want one", te.ph.Restarts()-restarts)
		}
		row, d := te.lastAudit()
		if row.Action != audit.ActionDHCPStaticUpdate || d["key_before"] != "aa:bb:cc:00:00:03|192.168.1.12" {
			t.Errorf("audit %s %v", row.Action, d)
		}
		// Nothing to change sends and audits nothing.
		n, audits := len(te.piholeWrites()), te.auditCount()
		res = te.admin.do(http.MethodPatch, path, gen.DHCPStaticLeaseUpdate{
			From: gen.DHCPStaticLeaseRef{Value: strp("aa:bb:cc:00:00:03,192.168.1.13,printer")},
			To:   gen.DHCPStaticLeaseInput{Mac: "aa:bb:cc:00:00:03", Ip: "192.168.1.13", Hostname: strp("printer")},
		})
		mustStatus(t, res, http.StatusOK)
		if len(te.piholeWrites()) != n || te.auditCount() != audits || len(results(t, res)) != 1 {
			t.Errorf("an unchanged change was sent or audited")
		}
	})

	t.Run("change an entry the app can't write", func(t *testing.T) {
		// It is read and can be replaced by a plain one: the old string goes, whatever it held.
		mustStatus(t, te.admin.do(http.MethodPatch, path, gen.DHCPStaticLeaseUpdate{
			From: gen.DHCPStaticLeaseRef{Value: strp("aa:bb:cc:00:00:02,192.168.1.11,tv,12h")},
			To:   gen.DHCPStaticLeaseInput{Mac: "aa:bb:cc:00:00:02", Ip: "192.168.1.11", Hostname: strp("tv")},
		}), http.StatusOK)
		l := te.ph.StaticLeases()
		if !slices.Contains(l, "aa:bb:cc:00:00:02,192.168.1.11,tv") || slices.Contains(l, "aa:bb:cc:00:00:02,192.168.1.11,tv,12h") {
			t.Errorf("leases %v", l)
		}
	})

	t.Run("delete", func(t *testing.T) {
		before := count()
		mustStatus(t, te.admin.do(http.MethodDelete, path, gen.DHCPStaticLeaseDelete{Lease: gen.DHCPStaticLeaseRef{Mac: strp("aa:bb:cc:00:00:03"), Ip: strp("192.168.1.13")}}), http.StatusOK)
		if count() != before-1 {
			t.Errorf("leases %v", te.ph.StaticLeases())
		}
		row, d := te.lastAudit()
		if row.Action != audit.ActionDHCPStaticDelete || d["key"] != "aa:bb:cc:00:00:03|192.168.1.13" {
			t.Errorf("audit %s %v", row.Action, d)
		}
		// An entry that doesn't parse is deleted by its value.
		mustStatus(t, te.admin.do(http.MethodDelete, path, gen.DHCPStaticLeaseDelete{Lease: gen.DHCPStaticLeaseRef{Value: strp("garbage line")}}), http.StatusOK)
		if slices.Contains(te.ph.StaticLeases(), "garbage line") {
			t.Errorf("leases %v", te.ph.StaticLeases())
		}
	})

	refused := []struct {
		name, method string
		body         any
		code, field  string
	}{
		{"a MAC already used", http.MethodPost, gen.DHCPStaticLeaseInput{Mac: "AA:BB:CC:00:00:01", Ip: "192.168.1.30"}, "conflict", "mac"},
		{"an address already used", http.MethodPost, gen.DHCPStaticLeaseInput{Mac: "aa:bb:cc:00:00:30", Ip: "192.168.1.10"}, "conflict", "ip"},
		{"a bad MAC", http.MethodPost, gen.DHCPStaticLeaseInput{Mac: "aa:bb", Ip: "192.168.1.30"}, "validation_failed", "mac"},
		{"an address outside the subnet", http.MethodPost, gen.DHCPStaticLeaseInput{Mac: "aa:bb:cc:00:00:30", Ip: "10.0.0.5"}, "validation_failed", "ip"},
		{"an IPv6 address", http.MethodPost, gen.DHCPStaticLeaseInput{Mac: "aa:bb:cc:00:00:30", Ip: "fd00::5"}, "validation_failed", "ip"},
		{"a hostname that is an option", http.MethodPost, gen.DHCPStaticLeaseInput{Mac: "aa:bb:cc:00:00:30", Ip: "192.168.1.30", Hostname: strp("ignore")}, "validation_failed", "hostname"},
		{"an injected line", http.MethodPost, gen.DHCPStaticLeaseInput{Mac: "aa:bb:cc:00:00:30", Ip: "192.168.1.30", Hostname: strp("a\ndhcp-option=3,1.2.3.4")}, "validation_failed", "hostname"},
		{"a change to a missing lease", http.MethodPatch, gen.DHCPStaticLeaseUpdate{
			From: gen.DHCPStaticLeaseRef{Mac: strp("aa:bb:cc:00:00:77"), Ip: strp("192.168.1.77")},
			To:   gen.DHCPStaticLeaseInput{Mac: "aa:bb:cc:00:00:77", Ip: "192.168.1.78"}}, "not_found", ""},
		{"a change onto another lease's address", http.MethodPatch, gen.DHCPStaticLeaseUpdate{
			From: gen.DHCPStaticLeaseRef{Mac: strp("aa:bb:cc:00:00:01"), Ip: strp("192.168.1.10")},
			To:   gen.DHCPStaticLeaseInput{Mac: "aa:bb:cc:00:00:01", Ip: "192.168.1.11"}}, "conflict", "to.ip"},
		{"a change with a bad target", http.MethodPatch, gen.DHCPStaticLeaseUpdate{
			From: gen.DHCPStaticLeaseRef{Mac: strp("aa:bb:cc:00:00:01"), Ip: strp("192.168.1.10")},
			To:   gen.DHCPStaticLeaseInput{Mac: "nope", Ip: "192.168.1.14"}}, "validation_failed", "to.mac"},
		{"a ref by value and fields", http.MethodDelete, gen.DHCPStaticLeaseDelete{Lease: gen.DHCPStaticLeaseRef{Value: strp("x"), Mac: strp("aa:bb:cc:00:00:01")}}, "validation_failed", "lease"},
		{"a ref with only a MAC", http.MethodDelete, gen.DHCPStaticLeaseDelete{Lease: gen.DHCPStaticLeaseRef{Mac: strp("aa:bb:cc:00:00:01")}}, "validation_failed", "lease"},
		{"a delete of a missing lease", http.MethodDelete, gen.DHCPStaticLeaseDelete{Lease: gen.DHCPStaticLeaseRef{Value: strp("aa:bb:cc:00:00:55,192.168.1.55")}}, "not_found", ""},
	}
	for _, c := range refused {
		t.Run(c.name, func(t *testing.T) {
			n, audits := len(te.piholeWrites()), te.auditCount()
			res := te.admin.do(c.method, path, c.body)
			if res.errorCode() != c.code {
				t.Fatalf("%d %s, want %s", res.Code, res.Body, c.code)
			}
			if c.field != "" && errorDetails(t, res)["field"] != c.field {
				t.Errorf("field %v, want %s", errorDetails(t, res)["field"], c.field)
			}
			if len(te.piholeWrites()) != n || te.auditCount() != audits {
				t.Errorf("a refused write was sent or audited")
			}
		})
	}

	t.Run("a Pi-hole that won't let the app write", func(t *testing.T) {
		for name, set := range map[string]func(){
			"pihole_app_sudo_off":  func() { te.ph.SetAppSudo(false) },
			"pihole_config_locked": func() { te.ph.SetAppSudo(true); te.ph.LockDHCP("hosts") },
		} {
			set()
			n := len(te.piholeWrites())
			res := te.admin.do(http.MethodPost, path, gen.DHCPStaticLeaseInput{Mac: "aa:bb:cc:00:00:31", Ip: "192.168.1.31"})
			if res.Code != http.StatusConflict || res.errorCode() != name {
				t.Errorf("%s: %d %s", name, res.Code, res.Body)
			}
			if len(te.piholeWrites()) != n {
				t.Errorf("%s: sent %v", name, te.piholeWrites()[n:])
			}
		}
		te.ph.SetAppSudo(true)
		te.ph.LockDHCP()
	})
}

func TestDHCPSettings(t *testing.T) {
	te := newDNSEnv(t)
	te.ph.SetDHCP(dhcpOff)
	path := te.path("/dhcp/settings")
	patch := func(body gen.DHCPSettingsPatch, confirm bool) response {
		p := path
		if confirm {
			p += "?confirm=true"
		}
		return te.admin.do(http.MethodPatch, p, body)
	}

	t.Run("turning DHCP on asks first", func(t *testing.T) {
		n, audits := len(te.piholeWrites()), te.auditCount()
		res := patch(gen.DHCPSettingsPatch{Active: ptr(true)}, false)
		if res.Code != http.StatusConflict || res.errorCode() != "confirmation_required" {
			t.Fatalf("%d %s", res.Code, res.Body)
		}
		if s, _ := errorDetails(t, res)["summary"].([]any); len(s) != 1 || s[0] != "Turn DHCP on" {
			t.Errorf("summary %v", errorDetails(t, res)["summary"])
		}
		if len(te.piholeWrites()) != n || te.auditCount() != audits {
			t.Errorf("an unconfirmed change was sent or audited")
		}
	})

	t.Run("a confirmed change", func(t *testing.T) {
		restarts := te.ph.Restarts()
		res := patch(gen.DHCPSettingsPatch{Active: ptr(true), LeaseTime: strp(" 12H "), Router: strp("192.168.1.1")}, true)
		mustStatus(t, res, http.StatusOK)
		d := te.ph.DHCP()
		if !d.Active || d.LeaseTime != "12h" || te.ph.Restarts() != restarts+1 {
			t.Errorf("settings %+v, restarts %d", d, te.ph.Restarts()-restarts)
		}
		row, detail := te.lastAudit()
		changes, _ := detail["changes"].(map[string]any)
		if row.Action != audit.ActionDHCPSettingsUpdate || len(changes) != 2 || changes["lease_time"] == nil || changes["active"] == nil {
			t.Errorf("audit %s %v", row.Action, detail)
		}
	})

	t.Run("a change that needs no confirmation", func(t *testing.T) {
		mustStatus(t, patch(gen.DHCPSettingsPatch{Ipv6: ptr(true), RapidCommit: ptr(true)}, false), http.StatusOK)
		if d := te.ph.DHCP(); !d.IPv6 || !d.RapidCommit {
			t.Errorf("settings %+v", d)
		}
	})

	t.Run("nothing to change", func(t *testing.T) {
		n, audits := len(te.piholeWrites()), te.auditCount()
		res := patch(gen.DHCPSettingsPatch{Active: ptr(true), LeaseTime: strp("12h"), Start: strp("192.168.1.100")}, false)
		mustStatus(t, res, http.StatusOK)
		if len(te.piholeWrites()) != n || te.auditCount() != audits {
			t.Errorf("an unchanged write was sent or audited")
		}
	})

	t.Run("changing the range asks, and says what changes", func(t *testing.T) {
		res := patch(gen.DHCPSettingsPatch{Start: strp("192.168.1.50")}, false)
		if res.errorCode() != "confirmation_required" {
			t.Fatalf("%d %s", res.Code, res.Body)
		}
		if s, _ := errorDetails(t, res)["summary"].([]any); len(s) != 1 || s[0] != "start: 192.168.1.100 to 192.168.1.50" {
			t.Errorf("summary %v", s)
		}
	})

	refused := []struct {
		name  string
		body  gen.DHCPSettingsPatch
		field string
	}{
		{"a router inside the range", gen.DHCPSettingsPatch{Router: strp("192.168.1.150")}, "router"},
		{"a start after the end", gen.DHCPSettingsPatch{Start: strp("192.168.1.250")}, "start"},
		{"an address outside the subnet", gen.DHCPSettingsPatch{End: strp("10.0.0.5")}, "end"},
		{"an IPv6 address", gen.DHCPSettingsPatch{Start: strp("fd00::1")}, "start"},
		{"a netmask that isn't one", gen.DHCPSettingsPatch{Netmask: strp("255.0.255.0")}, "netmask"},
		{"an infinite lease", gen.DHCPSettingsPatch{LeaseTime: strp("infinite")}, "lease_time"},
		{"a lease of one minute", gen.DHCPSettingsPatch{LeaseTime: strp("1m")}, "lease_time"},
		{"a lease with a line break", gen.DHCPSettingsPatch{LeaseTime: strp("1h\ndhcp-option=1")}, "lease_time"},
	}
	for _, c := range refused {
		t.Run(c.name, func(t *testing.T) {
			n, audits := len(te.piholeWrites()), te.auditCount()
			res := patch(c.body, true)
			if res.errorCode() != "validation_failed" || errorDetails(t, res)["field"] != c.field {
				t.Fatalf("%d %s, want %s", res.Code, res.Body, c.field)
			}
			if len(te.piholeWrites()) != n || te.auditCount() != audits {
				t.Errorf("a refused change was sent or audited")
			}
		})
	}

	t.Run("a setting an environment variable fixes", func(t *testing.T) {
		te.ph.LockDHCP("leaseTime")
		defer te.ph.LockDHCP()
		n := len(te.piholeWrites())
		res := patch(gen.DHCPSettingsPatch{LeaseTime: strp("1h")}, true)
		if res.Code != http.StatusConflict || res.errorCode() != "pihole_config_locked" || len(te.piholeWrites()) != n {
			t.Errorf("%d %s", res.Code, res.Body)
		}
	})
}

// TestDHCPTurnOnNamesOthers checks that turning DHCP on warns about another Pi-hole that already serves it.
func TestDHCPTurnOnNamesOthers(t *testing.T) {
	ge := newGroupEnv(t)
	for _, ph := range ge.ph {
		ph.SetAppSudo(true)
		ph.SetRestartOutage(0)
		ph.SetDHCP(dhcpOff)
	}
	ge.ph["beta"].SetDHCP(dhcpOn)
	res := ge.admin.do(http.MethodPatch, ge.instPath("alpha", "/dhcp/settings"), gen.DHCPSettingsPatch{Active: ptr(true)})
	if res.errorCode() != "confirmation_required" {
		t.Fatalf("%d %s", res.Code, res.Body)
	}
	if o, _ := errorDetails(t, res)["other_active"].([]any); len(o) != 1 || o[0] != "beta" {
		t.Errorf("other_active %v", errorDetails(t, res)["other_active"])
	}
}

// TestDHCPGroups checks that DHCP isn't mirrored: reads merge the members, and writes through the group are refused.
func TestDHCPGroups(t *testing.T) {
	ge := newGroupEnv(t)
	for _, ph := range ge.ph {
		ph.SetAppSudo(true)
		ph.SetRestartOutage(0)
	}
	ge.ph["alpha"].SetDHCP(dhcpOn)
	ge.ph["alpha"].SetLeases([]piholetest.DHCPLease{{Expires: 1, HWAddr: "aa:bb:cc:00:00:01", IP: "192.168.1.101", Name: "a", ClientID: "*"}})
	ge.ph["beta"].SetDHCP(dhcpOn)
	ge.ph["beta"].SetLeases([]piholetest.DHCPLease{{Expires: 1, HWAddr: "aa:bb:cc:00:00:02", IP: "192.168.2.101", Name: "b", ClientID: "*"}})
	ge.ph["gamma"].SetDHCP(dhcpOff)
	ge.ph["gamma"].SetLeases([]piholetest.DHCPLease{{Expires: 1, HWAddr: "aa:bb:cc:00:00:03", IP: "192.168.3.101", Name: "stale", ClientID: "*"}})

	leases := decode[gen.DHCPLeases](t, ge.admin.do(http.MethodGet, ge.path("/dhcp/leases"), nil))
	var got []string
	for _, l := range leases.Leases {
		got = append(got, l.Instance+" "+l.Ip)
	}
	if !slices.Equal(got, []string{"alpha 192.168.1.101", "beta 192.168.2.101"}) {
		t.Errorf("leases %v", got)
	}
	var sources []string
	for _, s := range leases.Instances {
		in := s.Instance + ":off"
		if s.Active {
			in = s.Instance + ":on"
		}
		if !s.Included {
			in += ":left out"
		}
		sources = append(sources, in)
	}
	if !slices.Equal(sources, []string{"alpha:on", "beta:on", "gamma:off:left out"}) || leases.Members == nil || len(*leases.Members) != 3 {
		t.Errorf("sources %v, members %v", sources, leases.Members)
	}

	settings := decode[gen.DHCPSettingsRead](t, ge.admin.do(http.MethodGet, ge.path("/dhcp"), nil))
	if len(settings.Instances) != 3 || settings.Instances[0].Instance != "alpha" {
		t.Errorf("settings %+v", settings.Instances)
	}
	if st := decode[gen.DHCPStaticLeases](t, ge.admin.do(http.MethodGet, ge.path("/dhcp/static-leases"), nil)); len(st.Instances) != 3 {
		t.Errorf("static leases %+v", st)
	}

	// A member that can't be read is named and the rest answer.
	ge.unreachable("beta")
	settings = decode[gen.DHCPSettingsRead](t, ge.admin.do(http.MethodGet, ge.path("/dhcp"), nil))
	if len(settings.Instances) != 2 || settings.Members == nil || len(*settings.Members) != 3 {
		t.Errorf("with beta down: %+v", settings)
	}

	for _, c := range []struct {
		method, path string
		body         any
	}{
		{http.MethodDelete, "/dhcp/leases", gen.DHCPLeaseRef{Ip: "192.168.1.101"}},
		{http.MethodPost, "/dhcp/static-leases", gen.DHCPStaticLeaseInput{Mac: "aa:bb:cc:00:00:30", Ip: "192.168.1.30"}},
		{http.MethodPatch, "/dhcp/static-leases", gen.DHCPStaticLeaseUpdate{From: gen.DHCPStaticLeaseRef{Value: strp("x")}, To: gen.DHCPStaticLeaseInput{Mac: "aa:bb:cc:00:00:30", Ip: "192.168.1.30"}}},
		{http.MethodDelete, "/dhcp/static-leases", gen.DHCPStaticLeaseDelete{Lease: gen.DHCPStaticLeaseRef{Value: strp("x")}}},
		{http.MethodPatch, "/dhcp/settings", gen.DHCPSettingsPatch{Ipv6: ptr(true)}},
	} {
		res := ge.admin.do(c.method, ge.path(c.path), c.body)
		if res.Code != http.StatusBadRequest || res.errorCode() != "validation_failed" || errorDetails(t, res)["field"] != "target" {
			t.Errorf("%s %s through the group: %d %s", c.method, c.path, res.Code, res.Body)
		}
	}
	for _, r := range ge.auditRows() {
		if strings.HasPrefix(r.Action, "dhcp_") {
			t.Errorf("a refused group write was audited: %s", r.Action)
		}
	}
}

func TestDHCPPermissions(t *testing.T) {
	te := newDNSEnv(t)
	te.ph.SetDHCP(dhcpOn)
	te.ph.SetLeases([]piholetest.DHCPLease{{Expires: 1, HWAddr: "aa:bb:cc:00:00:01", IP: "192.168.1.101", Name: "a", ClientID: "*"}})
	te.addGrantUser("viewer", "viewer-password-1", grant(rbac.DHCPView, "instance", te.id))
	te.addGrantUser("editor", "editor-password-1", grant(rbac.DHCPEdit, "instance", te.id))
	te.addGrantUser("configurer", "configurer-password-1", grant(rbac.DHCPConfig, "instance", te.id))
	te.addGrantUser("dns", "dns-password-1", grant(rbac.LocalDNSEdit, "instance", te.id), grant(rbac.LocalDNSView, "instance", te.id))
	viewer, editor := te.loggedIn("viewer", "viewer-password-1"), te.loggedIn("editor", "editor-password-1")
	configurer, dns := te.loggedIn("configurer", "configurer-password-1"), te.loggedIn("dns", "dns-password-1")

	for _, p := range []string{"/dhcp", "/dhcp/leases", "/dhcp/static-leases"} {
		mustStatus(t, viewer.do(http.MethodGet, te.path(p), nil), http.StatusOK)
	}
	for _, c := range []struct {
		who          *client
		method, path string
		body         any
		perm         rbac.Permission
	}{
		{editor, http.MethodGet, "/dhcp", nil, rbac.DHCPView},
		{dns, http.MethodGet, "/dhcp/leases", nil, rbac.DHCPView},
		{configurer, http.MethodGet, "/dhcp/static-leases", nil, rbac.DHCPView},
		{viewer, http.MethodDelete, "/dhcp/leases", gen.DHCPLeaseRef{Ip: "192.168.1.101"}, rbac.DHCPEdit},
		{configurer, http.MethodPost, "/dhcp/static-leases", gen.DHCPStaticLeaseInput{Mac: "aa:bb:cc:00:00:30", Ip: "192.168.1.30"}, rbac.DHCPEdit},
		{dns, http.MethodDelete, "/dhcp/static-leases", gen.DHCPStaticLeaseDelete{Lease: gen.DHCPStaticLeaseRef{Value: strp("x")}}, rbac.DHCPEdit},
		{editor, http.MethodPatch, "/dhcp/settings", gen.DHCPSettingsPatch{Ipv6: ptr(true)}, rbac.DHCPConfig},
		{viewer, http.MethodPatch, "/dhcp/settings", gen.DHCPSettingsPatch{Ipv6: ptr(true)}, rbac.DHCPConfig},
	} {
		res := c.who.do(c.method, te.path(c.path), c.body)
		if res.Code != http.StatusForbidden {
			t.Errorf("%s %s: %d %s", c.method, c.path, res.Code, res.Body)
		}
	}
	if w := te.piholeWrites(); len(w) != 0 {
		t.Errorf("writes %v", w)
	}
	mustStatus(t, editor.do(http.MethodDelete, te.path("/dhcp/leases"), gen.DHCPLeaseRef{Ip: "192.168.1.101"}), http.StatusOK)
	mustStatus(t, configurer.do(http.MethodPatch, te.path("/dhcp/settings"), gen.DHCPSettingsPatch{Ipv6: ptr(true)}), http.StatusOK)
}
