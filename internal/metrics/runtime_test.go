// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRegisterRuntime(t *testing.T) {
	r := New()
	var errs []error
	r.ErrorFunc = func(err error) { errs = append(errs, err) }
	before := time.Now().Unix()
	RegisterRuntime(r, `v2.11.0-"rc"`)
	got := scrape(t, r)
	if len(errs) != 0 {
		t.Fatalf("collector errors: %v", errs)
	}

	for _, want := range []string{
		"# TYPE pihole_rbac_build_info gauge\n",
		`pihole_rbac_build_info{version="v2.11.0-\"rc\""} 1` + "\n",
		"# TYPE process_start_time_seconds gauge\n",
		"# TYPE go_goroutines gauge\n",
		"# TYPE go_memstats_alloc_bytes gauge\n",
		"# TYPE go_memstats_sys_bytes gauge\n",
		"# TYPE go_gc_cycles_total counter\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}

	value := func(name string) float64 {
		for _, line := range strings.Split(got, "\n") {
			if strings.HasPrefix(line, name+" ") {
				f, err := strconv.ParseFloat(strings.TrimPrefix(line, name+" "), 64)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				return f
			}
		}
		t.Fatalf("no sample for %s in:\n%s", name, got)
		return 0
	}
	if start := value("process_start_time_seconds"); start < float64(before) || start > float64(time.Now().Unix()+1) {
		t.Errorf("process_start_time_seconds = %v, want about now (%d)", start, before)
	}
	if v := value("go_goroutines"); v < 1 {
		t.Errorf("go_goroutines = %v", v)
	}
	if v := value("go_memstats_alloc_bytes"); v <= 0 {
		t.Errorf("go_memstats_alloc_bytes = %v", v)
	}
	if v := value("go_memstats_sys_bytes"); v < value("go_memstats_alloc_bytes") {
		t.Errorf("go_memstats_sys_bytes = %v, less than what is in use", v)
	}
}

func TestRegisterRuntimeOnANilRegistry(t *testing.T) {
	RegisterRuntime(nil, "v1") // must not panic
}
