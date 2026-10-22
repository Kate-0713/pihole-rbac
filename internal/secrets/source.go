// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package secrets

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// Source says where a secret's current value came from.
type Source string

const (
	SourceUnset     Source = ""
	SourceEnv       Source = "env"       // a plain environment variable; changes need a restart
	SourceFile      Source = "file"      // a *_FILE variable; re-read on reload
	SourceGenerated Source = "generated" // the session key the app generated into the data directory
)

// maxFileSize caps a secret file. Real secrets are tiny; this stops a wrong path (a log, a disk image) being read.
const maxFileSize = 64 << 10

// lookup reads the secret named by envVar from envVar or envVar_FILE. Empty variables count as unset. Setting both is
// an error rather than a guess. Errors name the variable and path, never the value.
func lookup(getenv func(string) string, envVar string) (Value, Source, string, error) {
	plain := getenv(envVar)
	path := strings.TrimSpace(getenv(envVar + "_FILE"))
	switch {
	case plain != "" && path != "":
		return Value{}, SourceUnset, "", fmt.Errorf("%s and %s_FILE are both set; set only one", envVar, envVar)
	case plain != "":
		return NewValue([]byte(plain)), SourceEnv, "", nil
	case path != "":
		v, err := readFile(path)
		if err != nil {
			return Value{}, SourceFile, path, fmt.Errorf("%s_FILE: %w", envVar, err)
		}
		return v, SourceFile, path, nil
	}
	return Value{}, SourceUnset, "", nil
}

// readFile reads a secret file, dropping trailing line endings (editors and `echo` add them; Windows adds \r\n).
func readFile(path string) (Value, error) {
	f, err := os.Open(path)
	if err != nil {
		return Value{}, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return Value{}, err
	}
	if len(b) > maxFileSize {
		return Value{}, fmt.Errorf("%s is larger than %d bytes", path, maxFileSize)
	}
	b = []byte(strings.TrimRight(string(b), "\r\n"))
	if len(b) == 0 {
		return Value{}, errors.New(path + " is empty")
	}
	return Value{b: b}, nil
}
