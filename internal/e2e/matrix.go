// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// MatrixToken is the access token the fake homeserver accepts.
const MatrixToken = "syt_e2e_matrix_token"

// MatrixFixture tells the browser tests where the fake homeserver is. A channel can reach it over plain HTTP with
// allow_http, since it runs on the loopback address.
type MatrixFixture struct {
	Homeserver string `json:"homeserver"`
	Token      string `json:"token"`
}

// MatrixMessage is one message the fake homeserver received.
type MatrixMessage struct {
	Room string `json:"room"`
	Body string `json:"body"`
}

// Homeserver is a fake Matrix homeserver that accepts m.room.message sends with MatrixToken, in any room, and keeps
// them for the tests to read. Anything else gets Matrix's error shapes.
type Homeserver struct {
	srv      *httptest.Server
	mu       sync.Mutex
	messages []MatrixMessage
}

// StartHomeserver starts the fake on a loopback address.
func StartHomeserver() *Homeserver {
	h := &Homeserver{}
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /_matrix/client/v3/rooms/{room}/send/m.room.message/{txn}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer "+MatrixToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"errcode":"M_UNKNOWN_TOKEN","error":"Unrecognised access token."}`)
			return
		}
		var body struct {
			Body string `json:"body"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"errcode":"M_NOT_JSON","error":"Content not JSON."}`)
			return
		}
		h.mu.Lock()
		h.messages = append(h.messages, MatrixMessage{Room: r.PathValue("room"), Body: body.Body})
		h.mu.Unlock()
		_, _ = io.WriteString(w, `{"event_id":"$e2e"}`)
	})
	h.srv = httptest.NewServer(mux)
	return h
}

// Fixture is the homeserver's part of the fixture.
func (h *Homeserver) Fixture() *MatrixFixture {
	return &MatrixFixture{Homeserver: h.srv.URL, Token: MatrixToken}
}

// Messages returns what has been received, oldest first; with a room, only that room's.
func (h *Homeserver) Messages(room string) []MatrixMessage {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := []MatrixMessage{}
	for _, m := range h.messages {
		if room == "" || strings.EqualFold(m.Room, room) {
			out = append(out, m)
		}
	}
	return out
}

// Close stops the fake.
func (h *Homeserver) Close() { h.srv.Close() }
