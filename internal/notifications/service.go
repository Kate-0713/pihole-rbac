// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package notifications manages notification channels: their settings, secrets and events, the guards on changing
// them, and the routes the notifier sends by. Sending itself is in internal/notify.
//
// Every change runs in one transaction that checks notifications.manage, applies it and writes its audit row. After
// it commits, the notifier's routes are rebuilt, and any guard message is queued to the channel's old destination
// with its old secret: a destination or secret changed, the channel disabled or deleted, or events taken away from
// it. So alerts can't be quietly redirected or switched off.
package notifications

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Kate-0713/pihole-rbac/internal/audit"
	"github.com/Kate-0713/pihole-rbac/internal/notify"
	"github.com/Kate-0713/pihole-rbac/internal/rbac"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// Secrets is what the service needs from the secrets manager.
type Secrets interface {
	Cipher() *secrets.Cipher // nil without a master key
	ChannelSecret(envName string) (secrets.Value, bool)
}

// Service makes every change to notification channels and keeps the notifier's routes in step.
type Service struct {
	Store    *store.Store
	Audit    *audit.Logger
	Secrets  Secrets
	Notifier *notify.Notifier
	Logger   *slog.Logger
	Now      func() time.Time

	mu sync.Mutex // one change at a time, from reading the channel to queueing its guard
}

// Source says where a channel's secret comes from.
type Source string

const (
	SourceEnvironment Source = "environment"
	SourceStored      Source = "stored"
	SourceNone        Source = "none"
)

// Channel is a notification channel as the API shows it: never its secret.
type Channel struct {
	ID              int64
	Kind            notify.Kind
	Name            string
	EnvName         string
	Enabled         bool
	Events          []string // sorted
	WebhookID       string   // Discord: identifies the webhook; not secret
	Matrix          notify.MatrixConfig
	SecretSource    Source
	SecretVariable  string    // the variable that would override the stored secret, when the channel has an env name
	SecretUpdatedAt time.Time // when the stored secret was set, and by whom
	SecretUpdatedBy string
	SecretProblem   string // why the secret can't be used, if it can't
	CreatedAt       time.Time

	sealed secrets.Sealed
}

// Input is a channel's editable settings.
type Input struct {
	Kind    notify.Kind
	Name    string
	EnvName string
	Enabled bool
	Events  []string
	Matrix  notify.MatrixConfig // Matrix only
	// Secret is the channel's secret if the request gives one: a Discord webhook URL or a Matrix access token. It is
	// stored, or, when the channel's variable is set, must match it.
	Secret *secrets.Value
}

// config is the JSON in notification_channels.config: never secret.
type config struct {
	WebhookID  string `json:"webhook_id,omitempty"`
	Homeserver string `json:"homeserver,omitempty"`
	RoomID     string `json:"room_id,omitempty"`
	AllowHTTP  bool   `json:"allow_http,omitempty"`
}

const (
	maxName    = 64
	maxEnvName = 64
	maxEvents  = 200
	maxSecret  = 2048
)

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) log() *slog.Logger {
	if s.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return s.Logger
}

func validation(field, format string, args ...any) *rbac.Error {
	return &rbac.Error{Code: rbac.CodeValidation, Message: fmt.Sprintf(format, args...), Details: map[string]any{"field": field}}
}

func conflict(field, format string, args ...any) *rbac.Error {
	return &rbac.Error{Code: rbac.CodeConflict, Message: fmt.Sprintf(format, args...), Details: map[string]any{"field": field}}
}

func notFound(id int64) *rbac.Error {
	return &rbac.Error{Code: rbac.CodeNotFound, Message: fmt.Sprintf("There is no notification channel with ID %d.", id),
		Details: map[string]any{"channel_id": id}}
}

// fromNotify turns a notify validation error into the API's.
func fromNotify(err error) error {
	var ve *notify.ValidationError
	if errors.As(err, &ve) {
		return validation(ve.Field, "%s", ve.Message)
	}
	return err
}

func target(name string) string { return "channel:" + name }

func channelAAD(id int64) []byte { return secrets.AAD("notification_channels", id) }

// EventInfo is an event a channel can receive.
type EventInfo = audit.ActionInfo

// Events lists every event a channel can receive: the audit actions, with protected_group_add after client_update.
func Events() []EventInfo {
	var out []EventInfo
	for _, a := range audit.Actions() {
		out = append(out, a)
		if a.Name == audit.ActionClientUpdate {
			out = append(out, EventInfo{Name: notify.EventProtectedGroupAdd, Group: audit.GroupPihole,
				Description: "A client added to a protected Pi-hole group"})
		}
	}
	return out
}

var knownEvents = func() map[string]bool {
	m := map[string]bool{}
	for _, e := range Events() {
		m[e.Name] = true
	}
	return m
}()

// normalize checks the settings and returns them in canonical form: trimmed, events sorted without repeats, the
// Matrix settings and a Discord webhook URL canonical.
func (in Input) normalize() (Input, error) {
	if in.Kind != notify.Discord && in.Kind != notify.Matrix {
		return in, validation("kind", "A channel is discord or matrix.")
	}
	in.Name = strings.TrimSpace(in.Name)
	if n := utf8.RuneCountInString(in.Name); n == 0 || n > maxName || strings.IndexFunc(in.Name, unicode.IsControl) >= 0 {
		return in, validation("name", "A channel name is 1-%d characters, with no control characters.", maxName)
	}
	in.EnvName = strings.TrimSpace(in.EnvName)
	if in.EnvName != "" && (!secrets.ValidEnvName(in.EnvName) || len(in.EnvName) > maxEnvName) {
		return in, validation("env_name",
			"The env name is empty, or 1-%d characters of A-Z, 0-9 and _: a secret in %s then overrides the stored one.",
			maxEnvName, secrets.ChannelVar("<env name>"))
	}
	if len(in.Events) > maxEvents {
		return in, validation("events", "At most %d events.", maxEvents)
	}
	events := []string{}
	for _, e := range in.Events {
		if !knownEvents[e] {
			return in, validation("events", "%q isn't an event a channel can receive.", e)
		}
		if !slices.Contains(events, e) {
			events = append(events, e)
		}
	}
	slices.Sort(events)
	in.Events = events
	if in.Kind == notify.Matrix {
		m, err := in.Matrix.Normalize()
		if err != nil {
			return in, fromNotify(err)
		}
		in.Matrix = m
	} else {
		in.Matrix = notify.MatrixConfig{}
	}
	if in.Secret != nil {
		v, _, err := checkSecret(in.Kind, *in.Secret)
		if err != nil {
			return in, err
		}
		in.Secret = &v
	}
	return in, nil
}

// Normalize checks the settings as Create does, without saving anything, and returns them in canonical form, a
// Discord webhook URL included.
func (in Input) Normalize() (Input, error) { return in.normalize() }

// ConfigJSON is what Create stores in notification_channels.config for normalized settings: the Matrix settings, or
// the webhook ID of a Discord channel's secret (none without a secret).
func ConfigJSON(in Input) (string, error) {
	webhookID := ""
	if in.Kind == notify.Discord && in.Secret != nil {
		_, webhookID, _ = checkSecret(in.Kind, *in.Secret)
	}
	return configJSON(in, webhookID)
}

// AuditDetail fills an audit row's detail for a new channel as Create does: its settings, never its secret.
func (in Input) AuditDetail(d map[string]any) {
	webhookID := ""
	if in.Kind == notify.Discord && in.Secret != nil {
		_, webhookID, _ = checkSecret(in.Kind, *in.Secret)
	}
	in.auditDetail(d, webhookID)
}

// checkSecret checks a secret for its kind, and returns it in canonical form with the webhook ID for Discord.
func checkSecret(kind notify.Kind, v secrets.Value) (secrets.Value, string, error) {
	if v.Len() > maxSecret {
		return v, "", validation("secret", "That secret is too long.")
	}
	if kind == notify.Discord {
		canonical, id, err := notify.ParseDiscordWebhook(v.Reveal())
		if err != nil {
			return v, "", fromNotify(err)
		}
		return secrets.NewValue([]byte(canonical)), id, nil
	}
	if err := notify.CheckMatrixToken(v.Reveal()); err != nil {
		return v, "", fromNotify(err)
	}
	return v, "", nil
}

func (s *Service) fromRow(r db.NotificationChannel, events []string) Channel {
	var cfg config
	_ = json.Unmarshal([]byte(r.Config), &cfg) // the column is checked to be valid JSON
	ch := Channel{
		ID: r.ID, Kind: notify.Kind(r.Kind), Name: r.Name, EnvName: r.EnvName.String, Enabled: r.Enabled,
		Events: events, WebhookID: cfg.WebhookID, CreatedAt: store.FromMillis(r.CreatedAt),
	}
	if ch.Events == nil {
		ch.Events = []string{}
	}
	if ch.Kind == notify.Matrix {
		ch.Matrix = notify.MatrixConfig{Homeserver: cfg.Homeserver, RoomID: cfg.RoomID, AllowHTTP: cfg.AllowHTTP}
	}
	if ch.EnvName != "" {
		ch.SecretVariable = secrets.ChannelVar(ch.EnvName)
	}
	if len(r.SecretCiphertext) > 0 {
		ch.sealed = secrets.Sealed{KeyID: r.SecretKeyID.String, Nonce: r.SecretNonce, Ciphertext: r.SecretCiphertext}
		ch.SecretUpdatedAt = store.FromMillis(r.SecretUpdatedAt.Int64)
		ch.SecretUpdatedBy = r.SecretUpdatedBy.String
	}
	_, ch.SecretSource, ch.SecretProblem = s.secretOf(ch)
	if ch.Kind == notify.Discord && ch.SecretSource == SourceEnvironment {
		// The variable can change on a reload, so its webhook ID is worked out from it rather than stored.
		if v, _, _ := s.secretOf(ch); !v.IsZero() {
			if _, id, err := notify.ParseDiscordWebhook(v.Reveal()); err == nil {
				ch.WebhookID = id
			}
		}
	}
	return ch
}

// secretOf returns the secret a channel uses: its variable when set, otherwise the stored one decrypted with the
// current master key. problem says why there is none that works.
func (s *Service) secretOf(ch Channel) (v secrets.Value, src Source, problem string) {
	if ch.EnvName != "" {
		if v, ok := s.Secrets.ChannelSecret(ch.EnvName); ok {
			if _, _, err := checkSecret(ch.Kind, v); err != nil {
				return secrets.Value{}, SourceEnvironment, secrets.ChannelVar(ch.EnvName) + " doesn't hold a valid " + secretWord(ch.Kind) + "."
			}
			canonical, _, _ := checkSecret(ch.Kind, v)
			return canonical, SourceEnvironment, ""
		}
	}
	if ch.sealed.Ciphertext == nil {
		return secrets.Value{}, SourceNone, "No " + secretWord(ch.Kind) + " is set."
	}
	c := s.Secrets.Cipher()
	if c == nil {
		return secrets.Value{}, SourceStored, "The stored secret can't be read until the master key (PIHOLE_RBAC_SECRET_KEY) is set."
	}
	v, err := c.Open(ch.sealed, channelAAD(ch.ID))
	if err != nil {
		return secrets.Value{}, SourceStored, "The stored secret can't be read with the current master key."
	}
	return v, SourceStored, ""
}

func secretWord(k notify.Kind) string {
	if k == notify.Discord {
		return "webhook URL"
	}
	return "access token"
}

// destination is where a channel sends with secret v.
func destination(ch Channel, v secrets.Value) notify.Destination {
	return notify.Destination{ChannelID: ch.ID, Name: ch.Name, Kind: ch.Kind, Secret: v, Matrix: ch.Matrix}
}

func (s *Service) list(ctx context.Context, q *db.Queries) ([]Channel, error) {
	rows, err := q.ListChannels(ctx)
	if err != nil {
		return nil, err
	}
	rules, err := q.ListAllChannelRules(ctx)
	if err != nil {
		return nil, err
	}
	events := map[int64][]string{}
	for _, r := range rules {
		events[r.ChannelID] = append(events[r.ChannelID], r.Event)
	}
	out := make([]Channel, 0, len(rows))
	for _, r := range rows {
		out = append(out, s.fromRow(r, events[r.ID]))
	}
	return out, nil
}

func (s *Service) get(ctx context.Context, q *db.Queries, id int64) (Channel, error) {
	r, err := q.GetChannel(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return Channel{}, notFound(id)
	}
	if err != nil {
		return Channel{}, err
	}
	events, err := q.ListChannelRules(ctx, id)
	if err != nil {
		return Channel{}, err
	}
	return s.fromRow(r, events), nil
}

// List returns every channel, by name.
func (s *Service) List(ctx context.Context) ([]Channel, error) { return s.list(ctx, s.Store.Read()) }

// Get returns one channel.
func (s *Service) Get(ctx context.Context, id int64) (Channel, error) {
	return s.get(ctx, s.Store.Read(), id)
}

// CanStoreSecrets reports whether a master key is set, so secrets can be stored.
func (s *Service) CanStoreSecrets() bool { return s.Secrets.Cipher() != nil }

// Reload rebuilds the notifier's routes from the database and the current secrets: every enabled channel whose
// secret can be used. Call it at startup and after a secrets reload; changes made through the service call it
// themselves.
func (s *Service) Reload(ctx context.Context) error {
	channels, err := s.List(ctx)
	if err != nil {
		return err
	}
	var routes []notify.Route
	for _, ch := range channels {
		if !ch.Enabled || len(ch.Events) == 0 {
			continue
		}
		v, _, problem := s.secretOf(ch)
		if problem != "" {
			s.log().Warn("notification channel can't send", "channel", ch.Name, "problem", problem)
			continue
		}
		events := map[string]bool{}
		for _, e := range ch.Events {
			events[e] = true
		}
		routes = append(routes, notify.Route{Destination: destination(ch, v), Events: events})
	}
	if s.Notifier != nil {
		s.Notifier.SetRoutes(routes)
	}
	return nil
}

func (s *Service) reload(ctx context.Context) {
	if err := s.Reload(context.WithoutCancel(ctx)); err != nil {
		s.log().Error("rebuilding notification routes", "err", err)
	}
}

// txn is one change in progress.
type txn struct {
	ctx   context.Context
	q     *db.Queries
	set   *rbac.Set
	now   time.Time
	entry *audit.Entry
}

// do runs fn in a transaction with its audit row. A refusal for lack of notifications.manage is recorded as
// permission_denied, as other services do.
func (s *Service) do(ctx context.Context, a rbac.Actor, action string, fn func(t *txn) error) error {
	now := s.now()
	entry := audit.Entry{At: now, UserID: a.UserID, Username: a.Username, Action: action, IP: a.IP, Detail: map[string]any{}}
	err := s.Store.WithTx(ctx, func(q *db.Queries) error {
		set, err := rbac.Resolve(ctx, q, a.RoleIDs)
		if err != nil {
			return err
		}
		if !set.CanGlobal(rbac.NotifyManage) {
			return rbac.Forbidden(rbac.NotifyManage)
		}
		if err := fn(&txn{ctx: ctx, q: q, set: set, now: now, entry: &entry}); err != nil {
			return err
		}
		_, err = audit.Insert(ctx, q, entry)
		return err
	})
	switch {
	case rbac.IsCode(err, rbac.CodeForbidden):
		denied := audit.Entry{
			At: now, UserID: a.UserID, Username: a.Username, Action: audit.ActionPermissionDenied,
			Target: entry.Target, Err: err, Detail: map[string]any{"attempted": action, "permission": string(rbac.NotifyManage)},
			IP: a.IP,
		}
		if rerr := s.Audit.Record(ctx, s.Store, denied); rerr != nil {
			return fmt.Errorf("audit refusal: %w", rerr)
		}
		return err
	case err != nil:
		return err
	}
	s.Audit.Log(entry)
	return nil
}

// precheck refuses a caller without notifications.manage before any work, recording it as the change would.
func (s *Service) precheck(ctx context.Context, a rbac.Actor, action string) error {
	set, err := rbac.Resolve(ctx, s.Store.Read(), a.RoleIDs)
	if err != nil {
		return err
	}
	if set.CanGlobal(rbac.NotifyManage) {
		return nil
	}
	return s.do(ctx, a, action, func(*txn) error { return nil }) // refused inside, and recorded
}

func (t *txn) checkUnique(in Input, self int64) error {
	taken, err := t.q.ChannelNameTaken(t.ctx, db.ChannelNameTakenParams{Name: in.Name, ID: self})
	if err != nil {
		return err
	}
	if taken {
		return conflict("name", "Another channel is called %s.", in.Name)
	}
	if in.EnvName == "" {
		return nil
	}
	taken, err = t.q.ChannelEnvNameTaken(t.ctx, db.ChannelEnvNameTakenParams{EnvName: nullString(in.EnvName), ID: self})
	if err != nil {
		return err
	}
	if taken {
		return conflict("env_name", "Another channel already uses the env name %s.", in.EnvName)
	}
	return nil
}

func nullString(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

func (t *txn) setRules(id int64, events []string) error {
	if err := t.q.DeleteChannelRules(t.ctx, id); err != nil {
		return err
	}
	for _, e := range events {
		if err := t.q.AddChannelRule(t.ctx, db.AddChannelRuleParams{ChannelID: id, Event: e}); err != nil {
			return err
		}
	}
	return nil
}

func (t *txn) storeSecret(c *secrets.Cipher, id int64, v secrets.Value, by string) error {
	sealed, err := c.Seal(v, channelAAD(id))
	if err != nil {
		return err
	}
	return t.q.SetChannelSecret(t.ctx, db.SetChannelSecretParams{
		SecretCiphertext: sealed.Ciphertext, SecretNonce: sealed.Nonce,
		SecretKeyID:     sql.NullString{String: sealed.KeyID, Valid: true},
		SecretUpdatedAt: sql.NullInt64{Int64: store.Millis(t.now), Valid: true},
		SecretUpdatedBy: sql.NullString{String: by, Valid: true},
		ID:              id,
	})
}

func configJSON(in Input, webhookID string) (string, error) {
	cfg := config{WebhookID: webhookID}
	if in.Kind == notify.Matrix {
		cfg = config{Homeserver: in.Matrix.Homeserver, RoomID: in.Matrix.RoomID, AllowHTTP: in.Matrix.AllowHTTP}
	}
	b, err := json.Marshal(cfg)
	return string(b), err
}

// secretPlan is what a create or edit does with the channel's secret, worked out before its transaction.
type secretPlan struct {
	store     bool          // seal and store the secret from the request
	value     secrets.Value // the secret the channel will use, or zero for none
	webhookID string        // Discord: the webhook ID of the secret given
	detail    string        // for the audit row: "stored" or "confirmed", or "" when the request gave none
}

// planSecret applies the confirmation rule: a secret only goes where someone who knows it said it may. The request
// must give the channel's secret when
//
//   - a Matrix channel that has a token gets a new homeserver, or plain HTTP is allowed or forbidden, since the token
//     goes to the homeserver with every message; or
//   - the channel starts using a variable that is set: created with an env name whose variable is set, or changed to
//     one.
//
// A secret given for a channel whose variable is set must match it; otherwise it is stored, which needs the master
// key. before is the zero Channel for a create.
func (s *Service) planSecret(before Channel, after Input, given *secrets.Value) (secretPlan, error) {
	var envVal secrets.Value
	envSet := false
	if after.EnvName != "" {
		if v, ok := s.Secrets.ChannelSecret(after.EnvName); ok {
			envSet = true
			envVal, _, _ = checkSecret(after.Kind, v)
		}
	}
	creating := before.ID == 0
	newVariable := envSet && (creating || before.EnvName != after.EnvName)
	hadSecret := !creating && before.SecretSource != SourceNone
	newAddress := !creating && after.Kind == notify.Matrix && hadSecret &&
		(before.Matrix.Homeserver != after.Matrix.Homeserver || before.Matrix.AllowHTTP != after.Matrix.AllowHTTP)

	if given == nil {
		switch {
		case newVariable:
			return secretPlan{}, validation("secret", "%s is set, so enter the %s it holds to confirm that %s may use it.",
				secrets.ChannelVar(after.EnvName), secretWord(after.Kind), after.Name)
		case newAddress:
			return secretPlan{}, validation("secret",
				"Enter the access token again to use the new homeserver settings: a saved token is only sent where it was entered for.")
		}
		return secretPlan{}, nil
	}
	_, id, _ := checkSecret(after.Kind, *given)
	if envSet {
		if !given.Equal(envVal) {
			return secretPlan{}, validation("secret", "That isn't the %s in %s, which this channel uses. Enter that one, or change it there.",
				secretWord(after.Kind), secrets.ChannelVar(after.EnvName))
		}
		return secretPlan{value: envVal, webhookID: id, detail: "confirmed"}, nil
	}
	if s.Secrets.Cipher() == nil {
		return secretPlan{}, validation("secret",
			"Secrets can't be stored until the master key (PIHOLE_RBAC_SECRET_KEY) is set. Give the channel an env name and set its variable instead.")
	}
	return secretPlan{store: true, value: *given, webhookID: id, detail: "stored"}, nil
}

func (in Input) auditDetail(d map[string]any, webhookID string) {
	d["kind"] = string(in.Kind)
	d["name"] = in.Name
	if in.EnvName != "" {
		d["env_name"] = in.EnvName
	}
	d["enabled"] = in.Enabled
	d["events"] = in.Events
	if in.Kind == notify.Matrix {
		d["homeserver"] = in.Matrix.Homeserver
		d["room_id"] = in.Matrix.RoomID
		d["allow_http"] = in.Matrix.AllowHTTP
	} else if webhookID != "" {
		d["webhook_id"] = webhookID
	}
}

// Create adds a channel. Without a secret (and without a set variable) it can't send until one is stored.
func (s *Service) Create(ctx context.Context, a rbac.Actor, in Input) (Channel, error) {
	if err := s.precheck(ctx, a, audit.ActionChannelCreate); err != nil {
		return Channel{}, err
	}
	norm, err := in.normalize()
	if err != nil {
		return Channel{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	plan, err := s.planSecret(Channel{}, norm, norm.Secret)
	if err != nil {
		return Channel{}, err
	}
	var id int64
	err = s.do(ctx, a, audit.ActionChannelCreate, func(t *txn) error {
		t.entry.Target = target(norm.Name)
		if err := t.checkUnique(norm, 0); err != nil {
			return err
		}
		cfg, err := configJSON(norm, plan.webhookID)
		if err != nil {
			return err
		}
		if id, err = t.q.CreateChannel(t.ctx, db.CreateChannelParams{
			Kind: string(norm.Kind), Name: norm.Name, EnvName: nullString(norm.EnvName), Config: cfg,
			Enabled: norm.Enabled, CreatedAt: store.Millis(t.now),
		}); err != nil {
			return err
		}
		if plan.store {
			if err := t.storeSecret(s.Secrets.Cipher(), id, plan.value, a.Username); err != nil {
				return err
			}
		}
		if err := t.setRules(id, norm.Events); err != nil {
			return err
		}
		t.entry.Detail["channel_id"] = id
		norm.auditDetail(t.entry.Detail, plan.webhookID)
		if plan.detail != "" {
			t.entry.Detail["secret"] = plan.detail
		}
		return nil
	})
	if err != nil {
		return Channel{}, err
	}
	s.reload(ctx)
	return s.Get(ctx, id)
}

// guard is a warning for a channel's old destination, queued once the change has committed.
type guard struct {
	dest notify.Destination
	what []string
	by   string
}

func (s *Service) send(g *guard) {
	if g == nil || len(g.what) == 0 || g.dest.Secret.IsZero() || s.Notifier == nil {
		return
	}
	m := &notify.Message{}
	m.Text("⚠️ Notification channel ").Bold(g.dest.Name).Text(" was changed by ").Bold(g.by).Text(": ")
	for i, w := range g.what {
		if i > 0 {
			m.Text("; ")
		}
		m.Text(w)
	}
	m.Text(".")
	s.Notifier.Enqueue(notify.Job{Destination: g.dest, Message: m, Event: "guard", Guard: true, By: g.by})
}

// Update replaces a channel's settings. Its kind can't change. A guard message goes to the old destination when the
// destination or secret changes, the channel is disabled, or events are taken away from an enabled channel.
func (s *Service) Update(ctx context.Context, a rbac.Actor, id int64, in Input) (Channel, error) {
	if err := s.precheck(ctx, a, audit.ActionChannelUpdate); err != nil {
		return Channel{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	before, err := s.Get(ctx, id)
	if err != nil {
		return Channel{}, err
	}
	if in.Kind == "" {
		in.Kind = before.Kind
	}
	if in.Kind != before.Kind {
		return Channel{}, validation("kind", "A channel's kind can't change. Add a new channel instead.")
	}
	norm, err := in.normalize()
	if err != nil {
		return Channel{}, err
	}
	plan, err := s.planSecret(before, norm, norm.Secret)
	if err != nil {
		return Channel{}, err
	}
	oldSecret, _, _ := s.secretOf(before)

	// What the channel will use afterwards: the plan's secret, or the variable or stored secret as it stands.
	afterCh := before
	afterCh.Name, afterCh.EnvName, afterCh.Matrix = norm.Name, norm.EnvName, norm.Matrix
	newSecret := plan.value
	if newSecret.IsZero() {
		newSecret, _, _ = s.secretOf(afterCh)
	}

	var changed []string
	if before.Name != norm.Name {
		changed = append(changed, "name")
	}
	if before.EnvName != norm.EnvName {
		changed = append(changed, "env_name")
	}
	if before.Enabled != norm.Enabled {
		changed = append(changed, "enabled")
	}
	if before.Matrix.Homeserver != norm.Matrix.Homeserver {
		changed = append(changed, "homeserver")
	}
	if before.Matrix.RoomID != norm.Matrix.RoomID {
		changed = append(changed, "room_id")
	}
	if before.Matrix.AllowHTTP != norm.Matrix.AllowHTTP {
		changed = append(changed, "allow_http")
	}
	added, removed := diff(before.Events, norm.Events)
	if len(added)+len(removed) > 0 {
		changed = append(changed, "events")
	}
	if plan.store {
		changed = append(changed, "secret")
	}
	if len(changed) == 0 && plan.detail == "" {
		return before, nil
	}

	g := &guard{dest: destination(before, oldSecret), by: a.Username}
	destChanged := !oldSecret.Equal(newSecret) || before.Matrix != norm.Matrix
	if destChanged {
		g.what = append(g.what, "its destination or secret changed, so messages now go elsewhere")
	}
	if before.Enabled && !norm.Enabled {
		g.what = append(g.what, "it was disabled, so no more messages come here")
	} else if before.Enabled && len(removed) > 0 {
		g.what = append(g.what, "it no longer receives "+strings.Join(removed, ", "))
	}

	webhookID := before.WebhookID
	if plan.webhookID != "" {
		webhookID = plan.webhookID
	}
	err = s.do(ctx, a, audit.ActionChannelUpdate, func(t *txn) error {
		cur, err := s.get(t.ctx, t.q, id)
		if err != nil {
			return err
		}
		t.entry.Target = target(cur.Name)
		if !sameChannel(cur, before) {
			return conflict("", "%s was changed by someone else meanwhile. Load it again.", cur.Name)
		}
		if err := t.checkUnique(norm, id); err != nil {
			return err
		}
		cfg, err := configJSON(norm, webhookID)
		if err != nil {
			return err
		}
		if err := t.q.UpdateChannel(t.ctx, db.UpdateChannelParams{
			Name: norm.Name, EnvName: nullString(norm.EnvName), Config: cfg, Enabled: norm.Enabled, ID: id,
		}); err != nil {
			return err
		}
		if plan.store {
			if err := t.storeSecret(s.Secrets.Cipher(), id, plan.value, a.Username); err != nil {
				return err
			}
		}
		if err := t.setRules(id, norm.Events); err != nil {
			return err
		}
		t.entry.Detail["channel_id"] = id
		t.entry.Detail["changed"] = changed
		if before.Name != norm.Name {
			t.entry.Detail["old_name"] = before.Name
		}
		norm.auditDetail(t.entry.Detail, webhookID)
		if len(added) > 0 {
			t.entry.Detail["events_added"] = added
		}
		if len(removed) > 0 {
			t.entry.Detail["events_removed"] = removed
		}
		if plan.detail != "" {
			t.entry.Detail["secret"] = plan.detail
		}
		if len(g.what) > 0 && !g.dest.Secret.IsZero() {
			t.entry.Detail["old_destination_warned"] = true
		}
		return nil
	})
	if err != nil {
		return Channel{}, err
	}
	s.send(g)
	s.reload(ctx)
	return s.Get(ctx, id)
}

// sameChannel reports whether a channel is as it was when an update started, so a change made meanwhile (from
// another process; this one changes channels one at a time) isn't overwritten unseen.
func sameChannel(a, b Channel) bool {
	return a.Name == b.Name && a.EnvName == b.EnvName && a.Enabled == b.Enabled && a.Matrix == b.Matrix &&
		slices.Equal(a.Events, b.Events) && a.SecretUpdatedAt.Equal(b.SecretUpdatedAt)
}

// diff returns what b has that a hasn't, and the reverse. Both are sorted.
func diff(a, b []string) (added, removed []string) {
	for _, e := range b {
		if !slices.Contains(a, e) {
			added = append(added, e)
		}
	}
	for _, e := range a {
		if !slices.Contains(b, e) {
			removed = append(removed, e)
		}
	}
	return added, removed
}

// SetSecret stores a new secret for a channel, as when a webhook is replaced or a token rotated. It is refused while
// the channel's variable is set, since that overrides a stored secret, and without a master key. The old destination
// is told.
func (s *Service) SetSecret(ctx context.Context, a rbac.Actor, id int64, v secrets.Value) (Channel, error) {
	if err := s.precheck(ctx, a, audit.ActionChannelSecret); err != nil {
		return Channel{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	before, err := s.Get(ctx, id)
	if err != nil {
		return Channel{}, err
	}
	v, webhookID, err := checkSecret(before.Kind, v)
	if err != nil {
		return Channel{}, err
	}
	if before.EnvName != "" {
		if _, ok := s.Secrets.ChannelSecret(before.EnvName); ok {
			return Channel{}, conflict("secret", "The secret of %s comes from %s, which overrides a stored one. Change it there, or clear the channel's env name.",
				before.Name, secrets.ChannelVar(before.EnvName))
		}
	}
	c := s.Secrets.Cipher()
	if c == nil {
		return Channel{}, conflict("secret", "Secrets can't be stored until the master key (PIHOLE_RBAC_SECRET_KEY) is set.")
	}
	oldSecret, _, _ := s.secretOf(before)
	g := &guard{dest: destination(before, oldSecret), by: a.Username}
	if !oldSecret.Equal(v) {
		g.what = []string{"its " + secretWord(before.Kind) + " was replaced, so messages now go elsewhere"}
		if before.Kind == notify.Matrix {
			g.what = []string{"its access token was replaced"}
		}
	}
	err = s.do(ctx, a, audit.ActionChannelSecret, func(t *txn) error {
		cur, err := s.get(t.ctx, t.q, id)
		if err != nil {
			return err
		}
		t.entry.Target = target(cur.Name)
		if !sameChannel(cur, before) {
			return conflict("", "%s was changed by someone else meanwhile. Load it again.", cur.Name)
		}
		if before.Kind == notify.Discord {
			in := Input{Kind: before.Kind, Name: before.Name, EnvName: before.EnvName, Enabled: before.Enabled}
			cfg, err := configJSON(in, webhookID)
			if err != nil {
				return err
			}
			if err := t.q.UpdateChannel(t.ctx, db.UpdateChannelParams{
				Name: cur.Name, EnvName: nullString(cur.EnvName), Config: cfg, Enabled: cur.Enabled, ID: id,
			}); err != nil {
				return err
			}
			t.entry.Detail["webhook_id"] = webhookID
		}
		t.entry.Detail["channel_id"] = id
		t.entry.Detail["secret"] = "stored"
		if len(g.what) > 0 && !g.dest.Secret.IsZero() {
			t.entry.Detail["old_destination_warned"] = true
		}
		return t.storeSecret(c, id, v, a.Username)
	})
	if err != nil {
		return Channel{}, err
	}
	s.send(g)
	s.reload(ctx)
	return s.Get(ctx, id)
}

// Delete removes a channel and its events. An enabled channel is told first (the message is queued with its secret,
// so it still goes once the row is gone).
func (s *Service) Delete(ctx context.Context, a rbac.Actor, id int64) error {
	if err := s.precheck(ctx, a, audit.ActionChannelDelete); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	before, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	secret, _, _ := s.secretOf(before)
	g := &guard{dest: destination(before, secret), by: a.Username}
	if before.Enabled {
		g.what = []string{"it was deleted, so no more messages come here"}
	}
	err = s.do(ctx, a, audit.ActionChannelDelete, func(t *txn) error {
		cur, err := s.get(t.ctx, t.q, id)
		if err != nil {
			return err
		}
		t.entry.Target = target(cur.Name)
		t.entry.Detail["channel_id"] = id
		t.entry.Detail["kind"] = string(cur.Kind)
		if len(g.what) > 0 && !g.dest.Secret.IsZero() {
			t.entry.Detail["old_destination_warned"] = true
		}
		return t.q.DeleteChannel(t.ctx, id)
	})
	if err != nil {
		return err
	}
	s.send(g)
	s.reload(ctx)
	return nil
}

// actionChannelTest only appears as the attempted action of a permission_denied row: a test changes nothing.
const actionChannelTest = "channel_test"

// TestResult is how Send test went. It never holds the destination's answer, only its status and Matrix's errcode.
type TestResult struct {
	OK      bool
	Status  int
	Errcode string
	Message string
}

// Test sends a test message to a channel's saved destination and waits for the answer. It works for a disabled
// channel too, and isn't audited: it changes nothing.
func (s *Service) Test(ctx context.Context, a rbac.Actor, id int64) (TestResult, error) {
	if err := s.precheck(ctx, a, actionChannelTest); err != nil {
		return TestResult{}, err
	}
	ch, err := s.Get(ctx, id)
	if err != nil {
		return TestResult{}, err
	}
	v, _, problem := s.secretOf(ch)
	if problem != "" {
		return TestResult{}, conflict("secret", "%s can't send: %s", ch.Name, problem)
	}
	n := s.Notifier
	if n == nil {
		n = &notify.Notifier{}
	}
	r := n.Send(ctx, destination(ch, v), notify.ForTest(ch.Name, a.Username))
	out := TestResult{OK: r.OK(), Status: r.Status, Errcode: r.Errcode, Message: "Sent."}
	if !r.OK() {
		out.Message = r.Err.Error()
	}
	return out, nil
}

// GuardFailed records a guard message that couldn't be delivered as notification_failed, written by the app with
// who made the change. It is the notifier's Failed hook.
func (s *Service) GuardFailed(j notify.Job, r notify.Result) {
	detail := map[string]any{
		"channel_id": j.Destination.ChannelID, "channel": j.Destination.Name, "kind": string(j.Destination.Kind),
		"changed_by": j.By, "reason": "guard",
	}
	if r.Status != 0 {
		detail["status"] = r.Status
	}
	if r.Errcode != "" {
		detail["errcode"] = r.Errcode
	}
	e := audit.Entry{
		Username: audit.SystemUser, Action: audit.ActionNotificationFailed, Target: target(j.Destination.Name),
		Err: r.Err, Detail: detail,
	}
	if err := s.Audit.Record(context.Background(), s.Store, e); err != nil {
		s.log().Error("recording a failed guard message", "channel", j.Destination.Name, "err", err)
	}
}
