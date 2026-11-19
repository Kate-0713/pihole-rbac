// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"runtime"
	rtm "runtime/metrics"
	"time"
)

// RegisterRuntime adds the app's build, process and Go runtime basics to r: pihole_rbac_build_info,
// process_start_time_seconds (taken now, so call it when the process starts), go_goroutines,
// go_memstats_alloc_bytes, go_memstats_sys_bytes and go_gc_cycles_total. They are read when scraped, from
// runtime/metrics, which doesn't stop the program the way runtime.ReadMemStats does.
func RegisterRuntime(r *Registry, version string) {
	started := float64(time.Now().UnixMilli()) / 1000
	samples := []rtm.Sample{
		{Name: "/memory/classes/heap/objects:bytes"},
		{Name: "/memory/classes/total:bytes"},
		{Name: "/gc/cycles/total:gc-cycles"},
	}
	r.Collect(func(w *Writer) error {
		if err := w.Gauge("pihole_rbac_build_info", "The version of the running app. Always 1.",
			Sample{Labels: []Label{{"version", version}}, Value: 1}); err != nil {
			return err
		}
		if err := w.Gauge("process_start_time_seconds", "When the process started, in seconds since the Unix epoch.",
			Sample{Value: started}); err != nil {
			return err
		}
		if err := w.Gauge("go_goroutines", "Goroutines that exist now.", Sample{Value: float64(runtime.NumGoroutine())}); err != nil {
			return err
		}
		rtm.Read(samples)
		if err := w.Gauge("go_memstats_alloc_bytes", "Bytes of heap objects in use.", uintSample(samples[0])...); err != nil {
			return err
		}
		if err := w.Gauge("go_memstats_sys_bytes", "Bytes of memory the Go runtime has from the system.", uintSample(samples[1])...); err != nil {
			return err
		}
		return w.Counter("go_gc_cycles_total", "Completed garbage collection cycles.", uintSample(samples[2])...)
	})
}

// uintSample is the value of a runtime/metrics sample as at most one Sample, none if the runtime doesn't have it.
func uintSample(s rtm.Sample) []Sample {
	if s.Value.Kind() != rtm.KindUint64 {
		return nil
	}
	return []Sample{{Value: float64(s.Value.Uint64())}}
}
