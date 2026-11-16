// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package totp

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"rsc.io/qr"

	"github.com/Kate-0713/pihole-rbac/internal/secrets"
	"github.com/Kate-0713/pihole-rbac/internal/store"
	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

// rfcSecret is the SHA-1 test secret of RFC 6238, appendix B.
var rfcSecret = secrets.NewValue([]byte("12345678901234567890"))

// The SHA-1 rows of RFC 6238's test vectors, which are eight digits long.
func TestRFC6238Vectors(t *testing.T) {
	for _, tc := range []struct {
		unix int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	} {
		at := time.Unix(tc.unix, 0)
		if got := hotp(rfcSecret.RevealBytes(), Step(at), 8); got != tc.want {
			t.Errorf("at %d: %s, want %s", tc.unix, got, tc.want)
		}
		// A six-digit code is the same number modulo 10^6: the last six digits.
		if got := Code(rfcSecret, at); got != tc.want[2:] {
			t.Errorf("at %d: six digits %s, want %s", tc.unix, got, tc.want[2:])
		}
	}
}

func TestVerify(t *testing.T) {
	now := time.Unix(1111111111, 0) // step 37037037
	step := Step(now)
	code := func(offset int64) string { return hotp(rfcSecret.RevealBytes(), step+offset, Digits) }

	for _, tc := range []struct {
		name     string
		input    string
		lastStep int64
		wantStep int64
		ok       bool
	}{
		{"the current step", code(0), 0, step, true},
		{"with the space apps show", code(0)[:3] + " " + code(0)[3:], 0, step, true},
		{"with spaces around it", "  " + code(0) + "\n", 0, step, true},
		{"one step back", code(-1), 0, step - 1, true},
		{"one step ahead", code(1), 0, step + 1, true},
		{"two steps back", code(-2), 0, 0, false},
		{"two steps ahead", code(2), 0, 0, false},
		{"used already", code(0), step, 0, false},
		{"older than the last one used", code(-1), step, 0, false},
		{"the step after the last one used", code(1), step, step + 1, true},
		{"a previous step, after none of the window was used", code(-1), step - 2, step - 1, true},
		{"empty", "", 0, 0, false},
		{"five digits", code(0)[:5], 0, 0, false},
		{"seven digits", code(0) + "0", 0, 0, false},
		{"letters", "abcdef", 0, 0, false},
		{"a sign", "-" + code(0)[1:], 0, 0, false},
		{"other digits", "١٢٣٤٥٦", 0, 0, false},
		{"a wrong code", wrong(code(-1), code(0), code(1)), 0, 0, false},
	} {
		got, ok := Verify(rfcSecret, tc.input, now, tc.lastStep)
		if ok != tc.ok || got != tc.wantStep {
			t.Errorf("%s: step %d, %v, want %d, %v", tc.name, got, ok, tc.wantStep, tc.ok)
		}
	}

	if _, ok := Verify(NewSecret(), code(0), now, 0); ok {
		// One chance in about 330,000 of a false alarm, with three steps accepted.
		t.Error("a code for another secret was accepted")
	}
}

// wrong returns six digits that are none of the codes given.
func wrong(codes ...string) string {
	for i := 0; ; i++ {
		c := fmt.Sprintf("%06d", i)
		if !strings.Contains(strings.Join(codes, " "), c) {
			return c
		}
	}
}

func TestNewSecret(t *testing.T) {
	a, b := NewSecret(), NewSecret()
	if a.Len() != SecretSize || a.Equal(b) {
		t.Fatalf("secrets: %d bytes, equal %v", a.Len(), a.Equal(b))
	}
	enc := Encode(a)
	if !regexp.MustCompile(`^[A-Z2-7]{32}$`).MatchString(enc) {
		t.Errorf("encoded secret = %q", enc)
	}
	if strings.Contains(fmt.Sprint(a), enc) || strings.Contains(fmt.Sprintf("%v %+v %s", a, a, a), string(a.RevealBytes())) {
		t.Error("a secret printed itself")
	}
}

func TestURI(t *testing.T) {
	got := URI("pihole-rbac: lab", "alice:x", rfcSecret)
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" || u.Path != "/pihole-rbac lab:alicex" {
		t.Errorf("uri = %s (path %q)", got, u.Path)
	}
	q := u.Query()
	for k, want := range map[string]string{
		"secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "issuer": "pihole-rbac lab", "algorithm": "SHA1", "digits": "6", "period": "30",
	} {
		if q.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, q.Get(k), want)
		}
	}
	if strings.Contains(got, "+") {
		t.Errorf("a space is written as +, which some authenticator apps show as a plus sign: %s", got)
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, hashes := NewRecoveryCodes()
	if len(codes) != RecoveryCodeCount || len(hashes) != RecoveryCodeCount {
		t.Fatalf("%d codes, %d hashes", len(codes), len(hashes))
	}
	shape := regexp.MustCompile(`^[a-z2-7]{4}(-[a-z2-7]{4}){3}$`)
	seen := map[string]bool{}
	for i, c := range codes {
		if !shape.MatchString(c) || seen[c] {
			t.Errorf("code %d = %q (seen before: %v)", i, c, seen[c])
		}
		seen[c] = true
		for _, typed := range []string{c, strings.ToUpper(c), strings.ReplaceAll(c, "-", ""), " " + strings.ReplaceAll(c, "-", " ") + " "} {
			h, ok := HashRecoveryCode(typed)
			if !ok || !bytes.Equal(h, hashes[i]) {
				t.Errorf("code %d typed as %q doesn't hash to its stored hash", i, typed)
			}
		}
		if bytes.Contains(hashes[i], []byte(c)) || len(hashes[i]) != 32 {
			t.Errorf("hash %d isn't a SHA-256", i)
		}
	}
	for _, bad := range []string{"", "123456", "abcd-efgh-ijkl", "abcd-efgh-ijkl-mnop-qrst", "abcd-efgh-ijkl-mn0p", "abcd_efgh_ijkl_mnop", "abcd-efgh-ijkl-mnö"} {
		if _, ok := HashRecoveryCode(bad); ok {
			t.Errorf("%q was taken for a recovery code", bad)
		}
	}
	if _, ok := NormalizeCode(codes[0]); ok {
		t.Error("a recovery code was taken for a six-digit code")
	}
}

func TestRequired(t *testing.T) {
	for _, tc := range []struct {
		name     string
		user     Policy
		roles    []int64
		required []int64
		want     bool
	}{
		{"nothing set", PolicyRoles, []int64{1, 2}, nil, false},
		{"one of their roles requires it", PolicyRoles, []int64{1, 2}, []int64{2, 9}, true},
		{"another role requires it", PolicyRoles, []int64{1, 2}, []int64{3}, false},
		{"no roles", PolicyRoles, nil, []int64{1}, false},
		{"required themselves, roles don't", PolicyRequired, []int64{1}, nil, true},
		{"required themselves, no roles", PolicyRequired, nil, nil, true},
		{"exempt, though a role requires it", PolicyExempt, []int64{1, 2}, []int64{1, 2}, false},
		{"exempt, roles don't", PolicyExempt, []int64{1}, nil, false},
	} {
		if got := Required(tc.user, tc.roles, tc.required); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
	for p, want := range map[Policy]bool{PolicyRoles: true, PolicyRequired: true, PolicyExempt: true, "optional": false, "Required": false} {
		if p.Valid() != want {
			t.Errorf("%q valid = %v", p, p.Valid())
		}
	}
}

// The SVG is the same grid of modules the encoder made, inside the quiet zone, and nothing else.
func TestQRSVG(t *testing.T) {
	text := URI("pihole-rbac", "alice", rfcSecret)
	svg, err := QRSVG(text)
	if err != nil {
		t.Fatal(err)
	}
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		ViewBox string `xml:"viewBox,attr"`
		Rect    struct {
			Fill string `xml:"fill,attr"`
		} `xml:"rect"`
		Path struct {
			D string `xml:"d,attr"`
		} `xml:"path"`
	}
	if err := xml.Unmarshal([]byte(svg), &doc); err != nil {
		t.Fatalf("not well-formed: %v", err)
	}
	side := code.Size + 2*quietZone
	if doc.ViewBox != fmt.Sprintf("0 0 %d %d", side, side) || doc.Rect.Fill != "#fff" {
		t.Errorf("viewBox %q, background %q", doc.ViewBox, doc.Rect.Fill)
	}
	grid := map[[2]int]bool{}
	for _, m := range regexp.MustCompile(`M(\d+) (\d+)h(\d+)v1h-(\d+)z`).FindAllStringSubmatch(doc.Path.D, -1) {
		var x, y, w, back int
		fmt.Sscan(m[1], &x)
		fmt.Sscan(m[2], &y)
		fmt.Sscan(m[3], &w)
		fmt.Sscan(m[4], &back)
		if w != back {
			t.Fatalf("a run that doesn't close: %s", m[0])
		}
		for i := 0; i < w; i++ {
			grid[[2]int{x + i, y}] = true
		}
	}
	if regexp.MustCompile(`M\d+ \d+h\d+v1h-\d+z`).ReplaceAllString(doc.Path.D, "") != "" {
		t.Errorf("the path holds something other than runs: %q", doc.Path.D)
	}
	black := 0
	for y := -quietZone; y < code.Size+quietZone; y++ {
		for x := -quietZone; x < code.Size+quietZone; x++ {
			if grid[[2]int{x + quietZone, y + quietZone}] != code.Black(x, y) {
				t.Fatalf("module %d,%d differs from the encoder's", x, y)
			}
			if code.Black(x, y) {
				black++
			}
		}
	}
	if black != len(grid) || black == 0 {
		t.Errorf("%d black modules drawn, %d encoded", len(grid), black)
	}
	if strings.Contains(svg, Encode(rfcSecret)) || strings.Contains(svg, "alice") || strings.Contains(svg, "script") {
		t.Error("the SVG holds text from the URI")
	}

	uri, err := QRDataURI(text)
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "data:image/svg+xml;base64,"
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(uri, prefix))
	if !strings.HasPrefix(uri, prefix) || err != nil || string(raw) != svg {
		t.Errorf("data URI doesn't hold the SVG: %v", err)
	}
	if _, err := QRSVG(strings.Repeat("x", 5000)); err == nil {
		t.Error("text too long for a QR code was accepted")
	}
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), store.Options{DataDir: t.TempDir(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func newCipher(t *testing.T, fill byte) *secrets.Cipher {
	t.Helper()
	c, err := secrets.NewCipher(bytes.Repeat([]byte{fill}, secrets.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func tx(t *testing.T, st *store.Store, fn func(q *db.Queries) error) {
	t.Helper()
	if err := st.WithTx(context.Background(), fn); err != nil {
		t.Fatal(err)
	}
}

func addUser(t *testing.T, st *store.Store, name string) int64 {
	t.Helper()
	var id int64
	tx(t, st, func(q *db.Queries) error {
		u, err := q.CreateLocalUser(context.Background(), db.CreateLocalUserParams{
			Username: name, PasswordHash: sql.NullString{String: "x", Valid: true}, CreatedAt: 1,
		})
		id = u.ID
		return err
	})
	return id
}

func setPending(t *testing.T, st *store.Store, c *secrets.Cipher, userID int64, secret secrets.Value) int64 {
	t.Helper()
	var n int64
	tx(t, st, func(q *db.Queries) error {
		s, err := Seal(c, userID, secret)
		if err != nil {
			return err
		}
		n, err = q.SetPendingUserTOTP(context.Background(), db.SetPendingUserTOTPParams{
			UserID: userID, SecretCiphertext: s.Ciphertext, SecretNonce: s.Nonce, SecretKeyID: s.KeyID, CreatedAt: 5,
		})
		return err
	})
	return n
}

// A secret is sealed to its user and key, waits for its first code, then can't be replaced or have a code replayed.
func TestStoredSecret(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	c := newCipher(t, 1)
	alice, bob := addUser(t, st, "alice"), addUser(t, st, "bob")

	if on, err := Enabled(ctx, st.Read(), alice); err != nil || on {
		t.Fatalf("before setup: %v, %v", on, err)
	}
	first, second := NewSecret(), NewSecret()
	if n := setPending(t, st, c, alice, first); n != 1 {
		t.Fatalf("first pending secret: %d rows", n)
	}
	if on, _ := Enabled(ctx, st.Read(), alice); on {
		t.Error("a secret waiting for its first code counts as on")
	}
	// Starting again before confirming replaces the secret.
	if n := setPending(t, st, c, alice, second); n != 1 {
		t.Fatalf("second pending secret: %d rows", n)
	}
	row, err := st.Read().GetUserTOTP(ctx, alice)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Open(c, row); err != nil || !got.Equal(second) {
		t.Fatalf("stored secret: %v", err)
	}
	if bytes.Contains(row.SecretCiphertext, second.RevealBytes()) {
		t.Error("the secret is stored unencrypted")
	}
	moved := row
	moved.UserID = bob
	if _, err := Open(c, moved); err != secrets.ErrDecrypt {
		t.Errorf("a secret moved to another user: %v", err)
	}
	if _, err := Open(newCipher(t, 2), row); err != secrets.ErrWrongKey {
		t.Errorf("another master key: %v", err)
	}

	tx(t, st, func(q *db.Queries) error {
		// Codes are refused until the secret is enabled.
		if n, err := q.AdvanceUserTOTPStep(ctx, db.AdvanceUserTOTPStepParams{Step: 100, UserID: alice}); err != nil || n != 0 {
			t.Errorf("a step before enabling: %d, %v", n, err)
		}
		n, err := q.EnableUserTOTP(ctx, db.EnableUserTOTPParams{EnabledAt: sql.NullInt64{Int64: 9, Valid: true}, LastStep: 100, UserID: alice})
		if err != nil || n != 1 {
			t.Errorf("enable: %d, %v", n, err)
		}
		if n, _ := q.EnableUserTOTP(ctx, db.EnableUserTOTPParams{EnabledAt: sql.NullInt64{Int64: 10, Valid: true}, LastStep: 0, UserID: alice}); n != 0 {
			t.Error("enabled twice")
		}
		return nil
	})
	if on, _ := Enabled(ctx, st.Read(), alice); !on {
		t.Error("not on after enabling")
	}
	// An enabled secret is never replaced by starting setup again.
	if n := setPending(t, st, c, alice, first); n != 0 {
		t.Errorf("an enabled secret was replaced (%d rows)", n)
	}
	row, _ = st.Read().GetUserTOTP(ctx, alice)
	if got, _ := Open(c, row); !got.Equal(second) || row.LastStep != 100 {
		t.Errorf("the enabled secret changed, last step %d", row.LastStep)
	}

	tx(t, st, func(q *db.Queries) error {
		for _, tc := range []struct {
			step int64
			want int64
		}{{100, 0}, {99, 0}, {101, 1}, {101, 0}, {103, 1}, {102, 0}} {
			n, err := q.AdvanceUserTOTPStep(ctx, db.AdvanceUserTOTPStepParams{Step: tc.step, UserID: alice})
			if err != nil || n != tc.want {
				t.Errorf("step %d: %d rows, %v, want %d", tc.step, n, err, tc.want)
			}
		}
		if n, _ := q.AdvanceUserTOTPStep(ctx, db.AdvanceUserTOTPStepParams{Step: 500, UserID: bob}); n != 0 {
			t.Error("a step for a user without TOTP")
		}
		return nil
	})
}

func TestStoredRecoveryCodes(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	c := newCipher(t, 1)
	alice, bob := addUser(t, st, "alice"), addUser(t, st, "bob")
	setPending(t, st, c, alice, NewSecret())
	setPending(t, st, c, bob, NewSecret())
	codes, hashes := NewRecoveryCodes()

	use := func(q *db.Queries, user int64, code string) int64 {
		h, ok := HashRecoveryCode(code)
		if !ok {
			t.Fatalf("%q isn't a recovery code", code)
		}
		n, err := q.UseRecoveryCode(ctx, db.UseRecoveryCodeParams{UsedAt: sql.NullInt64{Int64: 7, Valid: true}, UserID: user, CodeHash: h})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	tx(t, st, func(q *db.Queries) error {
		for _, h := range hashes {
			if err := q.AddRecoveryCode(ctx, db.AddRecoveryCodeParams{UserID: alice, CodeHash: h}); err != nil {
				return err
			}
		}
		if n := use(q, bob, codes[0]); n != 0 {
			t.Error("alice's code worked for bob")
		}
		if n := use(q, alice, strings.ToUpper(codes[0])); n != 1 {
			t.Error("a code didn't work")
		}
		if n := use(q, alice, codes[0]); n != 0 {
			t.Error("a code worked twice")
		}
		other, _ := NewRecoveryCodes()
		if n := use(q, alice, other[0]); n != 0 {
			t.Error("a code from another set worked")
		}
		if left, err := q.CountUnusedRecoveryCodes(ctx, alice); err != nil || left != RecoveryCodeCount-1 {
			t.Errorf("unused codes: %d, %v", left, err)
		}
		return nil
	})

	// A user without a secret can't hold codes, and removing the secret removes them.
	err := st.WithTx(ctx, func(q *db.Queries) error {
		return q.AddRecoveryCode(ctx, db.AddRecoveryCodeParams{UserID: addUserIn(t, q, "carol"), CodeHash: hashes[0]})
	})
	if err == nil {
		t.Error("recovery codes without a secret were accepted")
	}
	tx(t, st, func(q *db.Queries) error {
		if n, err := q.DeleteUserTOTP(ctx, alice); err != nil || n != 1 {
			t.Errorf("remove: %d, %v", n, err)
		}
		if left, _ := q.CountUnusedRecoveryCodes(ctx, alice); left != 0 {
			t.Errorf("%d codes outlived the secret", left)
		}
		if n, _ := q.DeleteUserTOTP(ctx, alice); n != 0 {
			t.Error("removed twice")
		}
		return nil
	})
	// Deleting a user removes everything of theirs.
	tx(t, st, func(q *db.Queries) error {
		if err := q.SetUserTOTPPolicy(ctx, db.SetUserTOTPPolicyParams{UserID: bob, Policy: string(PolicyRequired), SetAt: 1, SetBy: "admin"}); err != nil {
			return err
		}
		return q.DeleteUser(ctx, bob)
	})
	if _, err := st.Read().GetUserTOTP(ctx, bob); err != sql.ErrNoRows {
		t.Errorf("bob's secret after deleting bob: %v", err)
	}
	if _, err := st.Read().GetUserTOTPPolicy(ctx, bob); err != sql.ErrNoRows {
		t.Errorf("bob's setting after deleting bob: %v", err)
	}
}

func addUserIn(t *testing.T, q *db.Queries, name string) int64 {
	t.Helper()
	u, err := q.CreateLocalUser(context.Background(), db.CreateLocalUserParams{
		Username: name, PasswordHash: sql.NullString{String: "x", Valid: true}, CreatedAt: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

// RequiredFor reads a user's own setting, then their roles', from the database.
func TestRequiredFor(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	alice := addUser(t, st, "alice")
	var staff, ops int64
	tx(t, st, func(q *db.Queries) error {
		for name, id := range map[string]*int64{"staff": &staff, "ops": &ops} {
			r, err := q.CreateRole(ctx, db.CreateRoleParams{Name: name, CreatedAt: 1})
			if err != nil {
				return err
			}
			*id = r
		}
		return nil
	})
	check := func(when string, roles []int64, want bool) {
		t.Helper()
		got, err := RequiredFor(ctx, st.Read(), alice, roles)
		if err != nil || got != want {
			t.Errorf("%s: %v, %v, want %v", when, got, err, want)
		}
	}
	check("nothing set", []int64{staff, ops}, false)

	tx(t, st, func(q *db.Queries) error {
		if err := q.SetRoleTOTPRequired(ctx, db.SetRoleTOTPRequiredParams{RoleID: ops, SetAt: 1, SetBy: "admin"}); err != nil {
			return err
		}
		// Setting it twice changes nothing.
		return q.SetRoleTOTPRequired(ctx, db.SetRoleTOTPRequiredParams{RoleID: ops, SetAt: 2, SetBy: "other"})
	})
	check("holding the role that requires it", []int64{staff, ops}, true)
	check("holding only the other role", []int64{staff}, false)
	check("holding no role", nil, false)

	tx(t, st, func(q *db.Queries) error {
		return q.SetUserTOTPPolicy(ctx, db.SetUserTOTPPolicyParams{UserID: alice, Policy: string(PolicyExempt), SetAt: 1, SetBy: "admin"})
	})
	check("exempt, holding the role", []int64{staff, ops}, false)
	tx(t, st, func(q *db.Queries) error {
		return q.SetUserTOTPPolicy(ctx, db.SetUserTOTPPolicyParams{UserID: alice, Policy: string(PolicyRequired), SetAt: 2, SetBy: "admin"})
	})
	check("required, holding only the other role", []int64{staff}, true)
	tx(t, st, func(q *db.Queries) error {
		n, err := q.ClearUserTOTPPolicy(ctx, alice)
		if n != 1 {
			t.Errorf("clear: %d rows", n)
		}
		return err
	})
	check("back to the roles", []int64{staff}, false)

	// The builtin admin role can be listed, which a column on roles couldn't do: its row refuses updates.
	admin, err := st.Read().GetBuiltinRole(ctx)
	if err == sql.ErrNoRows {
		t.Skip("no builtin role before setup")
	}
	if err != nil {
		t.Fatal(err)
	}
	tx(t, st, func(q *db.Queries) error {
		return q.SetRoleTOTPRequired(ctx, db.SetRoleTOTPRequiredParams{RoleID: admin.ID, SetAt: 1, SetBy: "admin"})
	})
	check("holding the builtin admin role", []int64{admin.ID}, true)
}
