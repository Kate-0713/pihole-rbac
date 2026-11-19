// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"bytes"
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func scrape(t *testing.T, r *Registry) string {
	t.Helper()
	var b bytes.Buffer
	n, err := r.WriteTo(&b)
	if err != nil {
		t.Fatal(err)
	}
	if int(n) != b.Len() {
		t.Fatalf("WriteTo reported %d bytes, wrote %d", n, b.Len())
	}
	return b.String()
}

func TestCounterOutput(t *testing.T) {
	r := New()
	c := r.Counter("app_requests_total", "Requests.", "instance", "result")
	c.Inc("lab", "ok")
	c.Inc("lab", "ok")
	c.Add(3, "lab", "down")
	c.Inc("another", "ok")

	want := `# HELP app_requests_total Requests.
# TYPE app_requests_total counter
app_requests_total{instance="another",result="ok"} 1
app_requests_total{instance="lab",result="down"} 3
app_requests_total{instance="lab",result="ok"} 2
`
	if got := scrape(t, r); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestUnlabelledCounterReadsZeroFromTheStart(t *testing.T) {
	r := New()
	r.Counter("app_things_total", "Things.")
	want := "# HELP app_things_total Things.\n# TYPE app_things_total counter\napp_things_total 0\n"
	if got := scrape(t, r); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestLabelledFamilyWithoutSeriesWritesNothing(t *testing.T) {
	r := New()
	r.Counter("app_requests_total", "Requests.", "result")
	if got := scrape(t, r); got != "" {
		t.Errorf("got %q, want nothing", got)
	}
}

func TestEscaping(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"plain", "lab", `lab`},
		{"backslash", `a\b`, `a\\b`},
		{"quote", `a"b`, `a\"b`},
		{"newline", "a\nb", `a\nb`},
		{"all three", "\\\"\n", `\\\"\n`},
		{"invalid utf-8", "a\xffb", "a�b"},
		{"unicode kept", "pi-hole ☃", "pi-hole ☃"},
		{"brace and equals are literal", `a{b="c"}`, `a{b=\"c\"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := New()
			r.Counter("app_total", "x", "instance").Inc(tt.in)
			want := `app_total{instance="` + tt.want + `"} 1` + "\n"
			if got := scrape(t, r); !strings.HasSuffix(got, want) {
				t.Errorf("got %q, want suffix %q", got, want)
			}
		})
	}
}

func TestHelpEscaping(t *testing.T) {
	r := New()
	r.Counter("app_total", "Line one\nline \\ two.")
	if got := scrape(t, r); !strings.HasPrefix(got, "# HELP app_total Line one\\nline \\\\ two.\n") {
		t.Errorf("got %q", got)
	}
}

func TestHistogram(t *testing.T) {
	r := New()
	h := r.Histogram("app_seconds", "Duration.", []float64{0.1, 1, 10}, "instance")
	for _, v := range []float64{0.05, 0.1, 0.5, 1, 7, 100} {
		h.Observe(v, "lab")
	}
	// 0.05 and 0.1 fall in le=0.1 (inclusive), 0.5 and 1 in le=1, 7 in le=10, 100 in +Inf.
	want := `# HELP app_seconds Duration.
# TYPE app_seconds histogram
app_seconds_bucket{instance="lab",le="0.1"} 2
app_seconds_bucket{instance="lab",le="1"} 4
app_seconds_bucket{instance="lab",le="10"} 5
app_seconds_bucket{instance="lab",le="+Inf"} 6
app_seconds_sum{instance="lab"} 108.65
app_seconds_count{instance="lab"} 6
`
	if got := scrape(t, r); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestHistogramWithoutLabels(t *testing.T) {
	r := New()
	h := r.Histogram("app_seconds", "Duration.", []float64{1})
	h.Observe(0.5)
	got := scrape(t, r)
	for _, line := range []string{`app_seconds_bucket{le="1"} 1`, `app_seconds_bucket{le="+Inf"} 1`, "app_seconds_sum 0.5", "app_seconds_count 1"} {
		if !strings.Contains(got, line+"\n") {
			t.Errorf("missing %q in:\n%s", line, got)
		}
	}
}

func TestHistogramIgnoresNaN(t *testing.T) {
	r := New()
	h := r.Histogram("app_seconds", "Duration.", []float64{1}, "x")
	h.Observe(math.NaN(), "a")
	if got := scrape(t, r); got != "" {
		t.Errorf("got %q, want nothing", got)
	}
}

func TestGaugeCollector(t *testing.T) {
	r := New()
	r.Collect(func(w *Writer) error {
		return w.Gauge("app_up", "Up.",
			Sample{Labels: []Label{{"instance", "b"}}, Value: 0},
			Sample{Labels: []Label{{"instance", "a"}}, Value: 1},
		)
	})
	want := "# HELP app_up Up.\n# TYPE app_up gauge\napp_up{instance=\"a\"} 1\napp_up{instance=\"b\"} 0\n"
	if got := scrape(t, r); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGaugeWithoutSamplesIsLeftOut(t *testing.T) {
	r := New()
	r.Collect(func(w *Writer) error { return w.Gauge("app_up", "Up.") })
	if got := scrape(t, r); got != "" {
		t.Errorf("got %q, want nothing", got)
	}
}

func TestGaugeWithoutLabels(t *testing.T) {
	r := New()
	r.Collect(func(w *Writer) error { return w.Gauge("app_sessions", "Sessions.", Sample{Value: 4}) })
	if got := scrape(t, r); !strings.HasSuffix(got, "app_sessions 4\n") {
		t.Errorf("got %q", got)
	}
}

func TestCollectorCounter(t *testing.T) {
	r := New()
	r.Collect(func(w *Writer) error { return w.Counter("app_gc_total", "GCs.", Sample{Value: 7}) })
	if got := scrape(t, r); !strings.Contains(got, "# TYPE app_gc_total counter\napp_gc_total 7\n") {
		t.Errorf("got %q", got)
	}
}

func TestFamiliesAreSortedByName(t *testing.T) {
	r := New()
	r.Counter("zeta_total", "z").Inc()
	r.Collect(func(w *Writer) error { return w.Gauge("beta", "b", Sample{Value: 1}) })
	r.Counter("alpha_total", "a").Inc()
	got := scrape(t, r)
	a, b, z := strings.Index(got, "alpha_total "), strings.Index(got, "beta "), strings.Index(got, "zeta_total ")
	if !(a < b && b < z) {
		t.Errorf("families out of order:\n%s", got)
	}
}

func TestCollectorErrorIsReportedAndTheRestKept(t *testing.T) {
	r := New()
	var reported []error
	r.ErrorFunc = func(err error) { reported = append(reported, err) }
	boom := errors.New("database is down")
	r.Collect(func(w *Writer) error {
		if err := w.Gauge("first", "ok", Sample{Value: 1}); err != nil {
			return err
		}
		return boom
	})
	r.Collect(func(w *Writer) error { return w.Gauge("second", "ok", Sample{Value: 2}) })
	got := scrape(t, r)
	if !strings.Contains(got, "first 1\n") || !strings.Contains(got, "second 2\n") {
		t.Errorf("a failing collector cost the rest of the scrape:\n%s", got)
	}
	if len(reported) != 1 || !errors.Is(reported[0], boom) {
		t.Errorf("reported %v, want [%v]", reported, boom)
	}
}

func TestWriterRefusesBadNamesAndRepeats(t *testing.T) {
	r := New()
	r.Counter("taken_total", "x").Inc()
	var errs []error
	r.ErrorFunc = func(err error) { errs = append(errs, err) }
	r.Collect(func(w *Writer) error { return w.Gauge("taken_total", "x", Sample{Value: 1}) })
	r.Collect(func(w *Writer) error { return w.Gauge("bad name", "x", Sample{Value: 1}) })
	r.Collect(func(w *Writer) error {
		return w.Gauge("fine", "x", Sample{Labels: []Label{{"__reserved", "v"}}, Value: 1})
	})
	r.Collect(func(w *Writer) error { return w.Gauge("twice", "x", Sample{Value: 1}) })
	r.Collect(func(w *Writer) error { return w.Gauge("twice", "x", Sample{Value: 1}) })
	got := scrape(t, r)
	if len(errs) != 4 {
		t.Errorf("got %d errors, want 4: %v", len(errs), errs)
	}
	if strings.Count(got, "# TYPE taken_total") != 1 || strings.Contains(got, "bad name") || strings.Contains(got, "fine") || strings.Count(got, "# TYPE twice") != 1 {
		t.Errorf("unexpected output:\n%s", got)
	}
}

func TestRegistrationMistakesPanic(t *testing.T) {
	tests := []struct {
		name string
		fn   func(*Registry)
	}{
		{"empty name", func(r *Registry) { r.Counter("", "x") }},
		{"name starts with a digit", func(r *Registry) { r.Counter("1abc", "x") }},
		{"name with a dash", func(r *Registry) { r.Counter("a-b", "x") }},
		{"repeated name", func(r *Registry) { r.Counter("a", "x"); r.Counter("a", "x") }},
		{"repeated across kinds", func(r *Registry) { r.Counter("a", "x"); r.Histogram("a", "x", []float64{1}) }},
		{"label with a colon", func(r *Registry) { r.Counter("a", "x", "b:c") }},
		{"reserved label", func(r *Registry) { r.Counter("a", "x", "__name") }},
		{"repeated label", func(r *Registry) { r.Counter("a", "x", "l", "l") }},
		{"le on a histogram", func(r *Registry) { r.Histogram("a", "x", []float64{1}, "le") }},
		{"no buckets", func(r *Registry) { r.Histogram("a", "x", nil) }},
		{"buckets not increasing", func(r *Registry) { r.Histogram("a", "x", []float64{1, 1}) }},
		{"infinite bucket", func(r *Registry) { r.Histogram("a", "x", []float64{1, math.Inf(1)}) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("did not panic")
				}
			}()
			tt.fn(New())
		})
	}
}

func TestMetricNamesMayHaveColons(t *testing.T) {
	r := New()
	r.Counter("job:requests:total", "x").Inc()
}

func TestNilRegistryAndMetricsDoNothing(t *testing.T) {
	var r *Registry
	c := r.Counter("a", "x", "l")
	h := r.Histogram("b", "x", []float64{1})
	r.Collect(func(*Writer) error { return nil })
	c.Inc("v")
	c.Add(2, "v")
	c.DeleteMatching("l", "v")
	h.Observe(1)
	h.DeleteMatching("l", "v")
	var b bytes.Buffer
	if n, err := r.WriteTo(&b); n != 0 || err != nil || b.Len() != 0 {
		t.Errorf("WriteTo on nil: %d, %v, %q", n, err, b.String())
	}
}

func TestWrongNumberOfLabelValuesIsDropped(t *testing.T) {
	r := New()
	c := r.Counter("a_total", "x", "one", "two")
	c.Inc("only one")
	c.Inc("a", "b", "c")
	c.Inc()
	if got := scrape(t, r); got != "" {
		t.Errorf("got %q, want nothing", got)
	}
}

func TestNegativeCounterAddIsDropped(t *testing.T) {
	r := New()
	c := r.Counter("a_total", "x")
	c.Add(-1)
	c.Add(math.NaN())
	c.Add(2)
	if got := scrape(t, r); !strings.HasSuffix(got, "a_total 2\n") {
		t.Errorf("got %q", got)
	}
}

func TestDeleteMatching(t *testing.T) {
	r := New()
	c := r.Counter("a_total", "x", "instance", "result")
	h := r.Histogram("b_seconds", "x", []float64{1}, "instance")
	for _, inst := range []string{"gone", "kept"} {
		c.Inc(inst, "ok")
		c.Inc(inst, "down")
		h.Observe(0.5, inst)
	}
	c.DeleteMatching("instance", "gone")
	h.DeleteMatching("instance", "gone")
	c.DeleteMatching("no such label", "kept") // does nothing
	got := scrape(t, r)
	if strings.Contains(got, `"gone"`) {
		t.Errorf("series of a deleted instance remain:\n%s", got)
	}
	if strings.Count(got, `a_total{instance="kept"`) != 2 || !strings.Contains(got, `b_seconds_count{instance="kept"} 1`) {
		t.Errorf("series of the kept instance changed:\n%s", got)
	}
}

func TestDeletedFamilyDisappearsWhenEmpty(t *testing.T) {
	r := New()
	c := r.Counter("a_total", "x", "instance")
	c.Inc("only")
	c.DeleteMatching("instance", "only")
	if got := scrape(t, r); got != "" {
		t.Errorf("got %q, want nothing", got)
	}
}

func TestSeriesCap(t *testing.T) {
	r := New()
	c := r.Counter("a_total", "x", "id")
	for i := 0; i < MaxSeries+50; i++ {
		c.Inc(strconv.Itoa(i))
	}
	c.Inc("0") // a series that exists still counts once the family is full
	got := scrape(t, r)
	if n := strings.Count(got, "a_total{"); n != MaxSeries {
		t.Errorf("got %d series, want %d", n, MaxSeries)
	}
	if !strings.Contains(got, `a_total{id="0"} 2`+"\n") {
		t.Error("an existing series stopped counting when the family was full")
	}
}

func TestFormatFloat(t *testing.T) {
	tests := []struct {
		in   float64
		want string
	}{
		{0, "0"},
		{1, "1"},
		{-3, "-3"},
		{1000000, "1000000"},
		{123456789012, "123456789012"},
		{0.05, "0.05"},
		{2.5, "2.5"},
		{1e-7, "1e-07"},
		{1e20, "1e+20"},
		{math.Inf(1), "+Inf"},
		{math.Inf(-1), "-Inf"},
		{math.NaN(), "NaN"},
	}
	for _, tt := range tests {
		if got := formatFloat(tt.in); got != tt.want {
			t.Errorf("formatFloat(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// A line of the text format: a comment, or name{labels} value with a quoted, escaped label value.
var lineRE = regexp.MustCompile(`^(# (HELP|TYPE) [a-zA-Z_:][a-zA-Z0-9_:]* .+|[a-zA-Z_:][a-zA-Z0-9_:]*(\{([a-zA-Z_][a-zA-Z0-9_]*="([^"\\\n]|\\[\\"n])*",?)*\})? (-?[0-9][0-9.]*(e[+-][0-9]+)?|\+Inf|-Inf|NaN))$`)

func TestEveryLineIsWellFormed(t *testing.T) {
	r := New()
	c := r.Counter("app_total", "Help with a \\ backslash and\na newline.", "a", "b")
	c.Inc("x\"y", "z\\w")
	c.Inc("line\nbreak", "☃")
	r.Histogram("app_seconds", "h", PiholeBuckets, "instance").Observe(0.3, "i")
	r.Histogram("http_seconds", "h", HTTPBuckets, "route").Observe(0.003, "GET /x")
	r.Collect(func(w *Writer) error {
		return w.Gauge("app_up", "u", Sample{Labels: []Label{{"instance", "q\"r"}}, Value: 1}, Sample{Labels: []Label{{"instance", "n"}}, Value: math.NaN()})
	})
	for _, line := range strings.Split(strings.TrimSuffix(scrape(t, r), "\n"), "\n") {
		if !lineRE.MatchString(line) {
			t.Errorf("malformed line: %q", line)
		}
	}
}

func TestConcurrentUse(t *testing.T) {
	r := New()
	c := r.Counter("a_total", "x", "k")
	h := r.Histogram("b_seconds", "x", []float64{1}, "k")
	r.Collect(func(w *Writer) error { return w.Gauge("g", "x", Sample{Value: 1}) })
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			k := strconv.Itoa(g % 3)
			for i := 0; i < 500; i++ {
				c.Inc(k)
				h.Observe(0.5, k)
				if i%50 == 0 {
					var b bytes.Buffer
					_, _ = r.WriteTo(&b)
					c.DeleteMatching("k", "9")
				}
			}
		}(g)
	}
	wg.Wait()
	got := scrape(t, r)
	total := 0
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "a_total{") {
			n, err := strconv.Atoi(line[strings.LastIndex(line, " ")+1:])
			if err != nil {
				t.Fatal(err)
			}
			total += n
		}
	}
	if total != 8*500 {
		t.Errorf("counted %d, want %d", total, 8*500)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

func TestWriteToReportsAWriteError(t *testing.T) {
	r := New()
	r.Counter("a_total", "x").Inc()
	if _, err := r.WriteTo(failingWriter{}); err == nil {
		t.Error("want an error")
	}
}
