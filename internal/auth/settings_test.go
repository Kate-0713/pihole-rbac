// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"slices"
	"testing"

	"github.com/Kate-0713/pihole-rbac/internal/store/db"
)

func TestLoadSettings(t *testing.T) {
	tests := []struct {
		name    string
		stored  string // "" means no row
		want    []Method
		wantErr bool
	}{
		{name: "nothing saved", want: []Method{MethodLocal}},
		{name: "saved order kept", stored: `{"methods":["ldap","local"]}`, want: []Method{MethodLDAP, MethodLocal}},
		{name: "ldap only", stored: `{"methods":["ldap"]}`, want: []Method{MethodLDAP}},
		{name: "empty list", stored: `{"methods":[]}`, wantErr: true},
		{name: "unknown method", stored: `{"methods":["kerberos"]}`, wantErr: true},
		{name: "duplicate", stored: `{"methods":["local","local"]}`, wantErr: true},
		{name: "wrong shape", stored: `{"methods":"local"}`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newSessionEnv(t, SessionOptions{})
			ctx := context.Background()
			if tt.stored != "" {
				if err := e.st.WithTx(ctx, func(q *db.Queries) error {
					return q.UpsertSetting(ctx, db.UpsertSettingParams{Key: SettingsKey, Value: tt.stored})
				}); err != nil {
					t.Fatal(err)
				}
			}
			s, err := LoadSettings(ctx, e.st.Read())
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !slices.Equal(s.Methods, tt.want) {
				t.Fatalf("methods = %v, want %v", s.Methods, tt.want)
			}
		})
	}
}
