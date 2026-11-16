// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package piholeapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// DHCP is read and changed in two ways, both of them FTL's:
//
//   - Leases are dnsmasq's lease file, read by GET /api/dhcp/leases whether or not DHCP is on, and deleted one at a
//     time by DELETE /api/dhcp/leases/{ip}, which asks the resolver to do it and needs DHCP on.
//   - Settings are the dhcp items of Pi-hole's config. Every one of them restarts FTL (FLAG_RESTART_FTL), and FTL
//     checks them as a whole, with dnsmasq, when it writes the new config: a refusal is a 400 and nothing is applied.
//     So all the settings that change go in one PATCH /api/config. The static leases, dhcp.hosts, are an array
//     changed one element at a time, as the local DNS arrays are, and written into dnsmasq's config verbatim.
//
// An app-password session can only change config while the Pi-hole's webserver.api.app_sudo is on (see ErrAppSudoOff).

// ErrDHCPOff is Pi-hole refusing to delete a lease because DHCP is off.
var ErrDHCPOff = errors.New("pihole's DHCP server is off")

// ErrBusy is Pi-hole's resolver being too busy to answer in time. The request may work if it is repeated.
var ErrBusy = errors.New("pihole's resolver was too busy to answer")

// API error codes for the two failures above.
const (
	CodeDHCPOff = "pihole_dhcp_off"
	CodeBusy    = "pihole_busy"
)

// Lease is a DHCP lease as Pi-hole reads it from the lease file. Expires is Unix seconds, 0 for none. Name and
// ClientID are empty where the file has "*". For an IPv6 lease, dnsmasq's lease file has an IAID in the place of
// the hardware address, and HWAddr is that (to check against a real Pi-hole).
type Lease struct {
	Expires  int64  `json:"expires"`
	HWAddr   string `json:"hwaddr"`
	IP       string `json:"ip"`
	Name     string `json:"name"`
	ClientID string `json:"clientid"`
}

// IsIPv6 says whether the lease is for an IPv6 address.
func (l Lease) IsIPv6() bool {
	a, err := netip.ParseAddr(l.IP)
	return err == nil && a.Is6()
}

// GetLeases reads the leases. Reading doesn't need DHCP to be on, or app_sudo.
func (c *Client) GetLeases(ctx context.Context) ([]Lease, error) {
	var out struct {
		Leases []Lease `json:"leases"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/dhcp/leases", nil, &out); err != nil {
		return nil, err
	}
	for i := range out.Leases {
		l := &out.Leases[i]
		if l.Name == "*" {
			l.Name = ""
		}
		if l.ClientID == "*" {
			l.ClientID = ""
		}
	}
	if out.Leases == nil {
		return []Lease{}, nil
	}
	return out.Leases, nil
}

// DeleteLease deletes the lease for ip. A lease Pi-hole doesn't have is a 404 StatusError, DHCP being off is
// ErrDHCPOff, and a resolver too busy to answer in time is ErrBusy. It isn't a config write, so it doesn't restart
// FTL.
func (c *Client) DeleteLease(ctx context.Context, ip string) error {
	a, err := netip.ParseAddr(ip)
	if err != nil || a.Zone() != "" || a.String() != ip {
		return fmt.Errorf("%w: lease address %q", ErrInvalidArgument, ip)
	}
	err = c.do(ctx, http.MethodDelete, "/api/dhcp/leases/"+url.PathEscape(ip), nil, nil)
	var re *RejectedError
	var se *StatusError
	switch {
	case errors.As(err, &re) && strings.Contains(re.Message, "not enabled"):
		return &configError{kind: ErrDHCPOff, err: err}
	case errors.As(err, &se) && se.Code == http.StatusServiceUnavailable:
		return &configError{kind: ErrBusy, err: err}
	}
	return err
}

// DHCP is a Pi-hole's DHCP config as read, with what decides whether the app can change it. Addresses are strings,
// empty when unset, as Pi-hole holds them.
type DHCP struct {
	Active               bool
	Start, End, Router   string
	Netmask              string
	LeaseTime            string
	IPv6                 bool
	RapidCommit          bool
	MultiDNS             bool
	IgnoreUnknownClients bool
	// Hosts are the static leases, exactly as Pi-hole holds them.
	Hosts []string
	// Locked is the config items, by their key under dhcp ("start", "hosts"), set by an environment variable, which
	// FTL won't let its API change.
	Locked map[string]bool
	// AppSudo is webserver.api.app_sudo: whether an app-password session may change config.
	AppSudo bool
	// ReadOnly is misc.readOnly: the whole config is read-only.
	ReadOnly bool
}

// SettingKeys are the dhcp config items the app changes through DHCPPatch, as FTL names them.
var SettingKeys = []string{"active", "start", "end", "router", "netmask", "leaseTime", "ipv6", "rapidCommit", "multiDNS", "ignoreUnknownClients"}

// GetDHCP reads the DHCP config, and the settings that decide whether the app may change it: three reads, all
// allowed without app_sudo.
func (c *Client) GetDHCP(ctx context.Context) (*DHCP, error) {
	var out struct {
		Config struct {
			DHCP struct {
				Active               *configLeaf[bool]     `json:"active"`
				Start                *configLeaf[string]   `json:"start"`
				End                  *configLeaf[string]   `json:"end"`
				Router               *configLeaf[string]   `json:"router"`
				Netmask              *configLeaf[string]   `json:"netmask"`
				LeaseTime            *configLeaf[string]   `json:"leaseTime"`
				IPv6                 *configLeaf[bool]     `json:"ipv6"`
				RapidCommit          *configLeaf[bool]     `json:"rapidCommit"`
				MultiDNS             *configLeaf[bool]     `json:"multiDNS"`
				IgnoreUnknownClients *configLeaf[bool]     `json:"ignoreUnknownClients"`
				Hosts                *configLeaf[[]string] `json:"hosts"`
			} `json:"dhcp"`
		} `json:"config"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/config/dhcp?detailed=true", nil, &out); err != nil {
		return nil, err
	}
	d := out.Config.DHCP
	if d.Active == nil || d.Start == nil || d.End == nil || d.Router == nil || d.Netmask == nil || d.LeaseTime == nil ||
		d.IPv6 == nil || d.RapidCommit == nil || d.MultiDNS == nil || d.IgnoreUnknownClients == nil || d.Hosts == nil {
		return nil, &badResponseError{what: "config read", err: errors.New("a dhcp item is missing")}
	}
	appSudo, err := c.AppSudo(ctx)
	if err != nil {
		return nil, err
	}
	readOnly, err := c.configReadOnly(ctx)
	if err != nil {
		return nil, err
	}
	locked := map[string]bool{}
	for key, env := range map[string]bool{
		"active": d.Active.Flags.EnvVar, "start": d.Start.Flags.EnvVar, "end": d.End.Flags.EnvVar,
		"router": d.Router.Flags.EnvVar, "netmask": d.Netmask.Flags.EnvVar, "leaseTime": d.LeaseTime.Flags.EnvVar,
		"ipv6": d.IPv6.Flags.EnvVar, "rapidCommit": d.RapidCommit.Flags.EnvVar, "multiDNS": d.MultiDNS.Flags.EnvVar,
		"ignoreUnknownClients": d.IgnoreUnknownClients.Flags.EnvVar, "hosts": d.Hosts.Flags.EnvVar,
	} {
		if env {
			locked[key] = true
		}
	}
	return &DHCP{
		Active: d.Active.Value, Start: d.Start.Value, End: d.End.Value, Router: d.Router.Value, Netmask: d.Netmask.Value,
		LeaseTime: d.LeaseTime.Value, IPv6: d.IPv6.Value, RapidCommit: d.RapidCommit.Value, MultiDNS: d.MultiDNS.Value,
		IgnoreUnknownClients: d.IgnoreUnknownClients.Value, Hosts: nonNilStrings(d.Hosts.Value), Locked: locked,
		AppSudo: appSudo, ReadOnly: readOnly,
	}, nil
}

// DHCPPatch is a change to the DHCP settings: only the fields that are set are sent.
type DHCPPatch struct {
	Active               *bool
	Start, End, Router   *string
	Netmask              *string
	LeaseTime            *string
	IPv6                 *bool
	RapidCommit          *bool
	MultiDNS             *bool
	IgnoreUnknownClients *bool
}

// body is the PATCH body, built from the fields that are set and nothing else. An address or lease time is checked
// as a value that can go into config: no control characters.
func (p DHCPPatch) body() (map[string]any, error) {
	dhcp := map[string]any{}
	for _, s := range []struct {
		key string
		v   *string
	}{{"start", p.Start}, {"end", p.End}, {"router", p.Router}, {"netmask", p.Netmask}, {"leaseTime", p.LeaseTime}} {
		if s.v == nil {
			continue
		}
		if strings.ContainsFunc(*s.v, func(r rune) bool { return r < ' ' || r == 0x7f }) || len(*s.v) > 64 {
			return nil, fmt.Errorf("%w: dhcp.%s %q", ErrInvalidArgument, s.key, *s.v)
		}
		dhcp[s.key] = *s.v
	}
	for _, b := range []struct {
		key string
		v   *bool
	}{{"active", p.Active}, {"ipv6", p.IPv6}, {"rapidCommit", p.RapidCommit}, {"multiDNS", p.MultiDNS},
		{"ignoreUnknownClients", p.IgnoreUnknownClients}} {
		if b.v != nil {
			dhcp[b.key] = *b.v
		}
	}
	if len(dhcp) == 0 {
		return nil, fmt.Errorf("%w: nothing to change", ErrInvalidArgument)
	}
	return map[string]any{"config": map[string]any{"dhcp": dhcp}}, nil
}

// PatchDHCP changes the DHCP settings in one PATCH /api/config. With restart, FTL restarts once it has answered and
// DHCP and DNS aren't served until it is back (see WaitRestarted); without it, the change is saved but only served
// after the next restart. FTL checks the settings as a whole, and a refusal is a *RejectedError, with nothing
// applied.
func (c *Client) PatchDHCP(ctx context.Context, p DHCPPatch, restart bool) error {
	body, err := p.body()
	if err != nil {
		return err
	}
	path := "/api/config"
	if !restart {
		path += "?restart=false"
	}
	return configFailure(c.do(ctx, http.MethodPatch, path, body, nil))
}

// AddStaticLease adds value to dhcp.hosts. With restart, FTL restarts once it has answered; see PatchDHCP.
func (c *Client) AddStaticLease(ctx context.Context, value string, restart bool) error {
	return c.configWriteAt(ctx, http.MethodPut, "dhcp", "hosts", value, restart)
}

// DeleteStaticLease removes value from dhcp.hosts, matching it exactly, restarting FTL as AddStaticLease does. One
// Pi-hole doesn't have is a 404 StatusError.
func (c *Client) DeleteStaticLease(ctx context.Context, value string, restart bool) error {
	return c.configWriteAt(ctx, http.MethodDelete, "dhcp", "hosts", value, restart)
}
