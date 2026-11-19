// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package metrics writes metrics in the Prometheus text exposition format (version 0.0.4). The format is small and
// fixed, so it is written here rather than taking prometheus/client_golang and its modules.
//
// A Registry holds counters and histograms that code increments where an event is decided, and collectors that write
// gauges when the registry is scraped. Every method is safe on a nil *Registry, *Counter or *Histogram and does
// nothing, so code that is handed no registry needs no checks.
//
// Label values are escaped for the format and may be any text, but the callers only ever pass names an admin set or
// values from a fixed list, never request input, so the number of series stays bounded. As a backstop, one counter or
// histogram holds at most MaxSeries series and drops observations for new ones beyond that.
package metrics

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// ContentType is the Content-Type of a scrape response.
const ContentType = "text/plain; version=0.0.4; charset=utf-8"

// MaxSeries is the most series one counter or histogram holds.
const MaxSeries = 2000

// Bucket sets for the histograms the app keeps, in seconds.
var (
	// PiholeBuckets covers a Pi-hole call, from a cached read to a gravity run.
	PiholeBuckets = []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300}
	// HTTPBuckets covers one of the app's own requests.
	HTTPBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60}
)

// Label is one name and value of a sample's label set.
type Label struct{ Name, Value string }

// Sample is one value of a gauge or a collector's counter, with its labels.
type Sample struct {
	Labels []Label
	Value  float64
}

// Collector writes the families it knows at scrape time. A collector that fails returns an error, which goes to
// Registry.ErrorFunc; families written before the error are kept, and the rest of the scrape carries on.
type Collector func(w *Writer) error

// Registry holds the metrics. Create it with New.
type Registry struct {
	// ErrorFunc, when set, is called with each error a collector returns. It must not call back into the registry.
	ErrorFunc func(error)

	mu         sync.Mutex
	names      map[string]bool
	vecs       []*vec
	collectors []Collector
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{names: map[string]bool{}}
}

// Counter registers a counter family with the given label names. It panics on an invalid or repeated name, which is a
// mistake in the program, found when it starts.
func (r *Registry) Counter(name, help string, labels ...string) *Counter {
	if r == nil {
		return nil
	}
	return &Counter{r.register(name, help, "counter", nil, labels)}
}

// Histogram registers a histogram family. buckets are the upper bounds in increasing order, without +Inf, which is
// always added. It panics as Counter does, and on buckets that aren't increasing.
func (r *Registry) Histogram(name, help string, buckets []float64, labels ...string) *Histogram {
	if r == nil {
		return nil
	}
	if len(buckets) == 0 {
		panic("metrics: " + name + ": a histogram needs buckets")
	}
	for i, b := range buckets {
		if math.IsNaN(b) || math.IsInf(b, 0) || (i > 0 && b <= buckets[i-1]) {
			panic("metrics: " + name + ": buckets must be finite and increasing")
		}
	}
	for _, l := range labels {
		if l == "le" {
			panic("metrics: " + name + ": le is reserved for histogram buckets")
		}
	}
	return &Histogram{r.register(name, help, "histogram", append([]float64(nil), buckets...), labels)}
}

// Collect adds a collector, run on every scrape.
func (r *Registry) Collect(c Collector) {
	if r == nil || c == nil {
		return
	}
	r.mu.Lock()
	r.collectors = append(r.collectors, c)
	r.mu.Unlock()
}

func (r *Registry) register(name, help, typ string, buckets []float64, labels []string) *vec {
	if !validName(name, true) {
		panic("metrics: invalid metric name " + strconv.Quote(name))
	}
	for i, l := range labels {
		if !validName(l, false) || strings.HasPrefix(l, "__") {
			panic("metrics: " + name + ": invalid label name " + strconv.Quote(l))
		}
		for _, o := range labels[:i] {
			if o == l {
				panic("metrics: " + name + ": label " + l + " repeated")
			}
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.names[name] {
		panic("metrics: " + name + " registered twice")
	}
	r.names[name] = true
	v := &vec{name: name, help: help, typ: typ, labels: append([]string(nil), labels...), buckets: buckets, series: map[string]*series{}}
	if len(labels) == 0 {
		// Without labels there is exactly one series, which reads 0 from the first scrape.
		v.get(nil)
	}
	r.vecs = append(r.vecs, v)
	return v
}

// validName reports whether s is a valid metric name (colons allowed) or label name.
func validName(s string, metric bool) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		case c >= '0' && c <= '9' && i > 0:
		case c == ':' && metric:
		default:
			return false
		}
	}
	return true
}

// vec is the storage behind a Counter or a Histogram: its series, keyed by label values.
type vec struct {
	name, help, typ string
	labels          []string
	buckets         []float64 // histograms only

	mu     sync.Mutex
	series map[string]*series
}

type series struct {
	values []string
	value  float64  // counter
	counts []uint64 // histogram: per bucket, not cumulative; the last one is +Inf
	sum    float64
	count  uint64
}

// get returns the series for values, creating it. It returns nil when the number of values is wrong or the family is
// full. Callers hold v.mu, except at registration.
func (v *vec) get(values []string) *series {
	if len(values) != len(v.labels) {
		return nil
	}
	key := strings.Join(values, "\xff")
	s := v.series[key]
	if s == nil {
		if len(v.series) >= MaxSeries {
			return nil
		}
		s = &series{values: append([]string(nil), values...)}
		if v.typ == "histogram" {
			s.counts = make([]uint64, len(v.buckets)+1)
		}
		v.series[key] = s
	}
	return s
}

// deleteMatching drops every series whose label is value, so a removed instance or destination leaves no series.
func (v *vec) deleteMatching(label, value string) {
	idx := -1
	for i, l := range v.labels {
		if l == label {
			idx = i
		}
	}
	if idx < 0 {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	for k, s := range v.series {
		if s.values[idx] == value {
			delete(v.series, k)
		}
	}
}

// Counter is a value that only goes up. Series are created by their first use.
type Counter struct{ v *vec }

// Inc adds 1 to the series with the given label values, in the order the labels were registered. A wrong number of
// values, or a full family, drops the increment.
func (c *Counter) Inc(values ...string) { c.Add(1, values...) }

// Add adds n, which must not be negative, to a series.
func (c *Counter) Add(n float64, values ...string) {
	if c == nil || n < 0 || math.IsNaN(n) {
		return
	}
	c.v.mu.Lock()
	defer c.v.mu.Unlock()
	if s := c.v.get(values); s != nil {
		s.value += n
	}
}

// DeleteMatching drops every series whose label has value.
func (c *Counter) DeleteMatching(label, value string) {
	if c != nil {
		c.v.deleteMatching(label, value)
	}
}

// Histogram counts observations in buckets.
type Histogram struct{ v *vec }

// Observe records one value, in the unit of the buckets, in the series with the given label values.
func (h *Histogram) Observe(value float64, values ...string) {
	if h == nil || math.IsNaN(value) {
		return
	}
	h.v.mu.Lock()
	defer h.v.mu.Unlock()
	s := h.v.get(values)
	if s == nil {
		return
	}
	// The first bucket whose bound is at least value: bounds are inclusive, as le says.
	s.counts[sort.SearchFloat64s(h.v.buckets, value)]++
	s.sum += value
	s.count++
}

// DeleteMatching drops every series whose label has value.
func (h *Histogram) DeleteMatching(label, value string) {
	if h != nil {
		h.v.deleteMatching(label, value)
	}
}

// family is one metric family as text, ready to be written in name order.
type family struct{ name, text string }

// Writer is what a Collector writes its families to.
type Writer struct {
	fams *[]family
	seen map[string]bool
}

// Gauge writes a gauge family. With no samples it writes nothing, which is how a collector leaves a series out. The
// error is for an invalid or repeated name or label, or an invalid value; a collector should return it.
func (w *Writer) Gauge(name, help string, samples ...Sample) error {
	return w.family(name, help, "gauge", samples)
}

// Counter writes a counter family whose values the collector keeps, such as the runtime's.
func (w *Writer) Counter(name, help string, samples ...Sample) error {
	return w.family(name, help, "counter", samples)
}

func (w *Writer) family(name, help, typ string, samples []Sample) error {
	if !validName(name, true) {
		return fmt.Errorf("metrics: invalid metric name %q", name)
	}
	if w.seen[name] {
		return fmt.Errorf("metrics: %s written twice in one scrape", name)
	}
	if len(samples) == 0 {
		return nil
	}
	lines := make([]string, 0, len(samples))
	for _, s := range samples {
		var b strings.Builder
		b.WriteString(name)
		for i, l := range s.Labels {
			if !validName(l.Name, false) || strings.HasPrefix(l.Name, "__") {
				return fmt.Errorf("metrics: %s: invalid label name %q", name, l.Name)
			}
			if i == 0 {
				b.WriteByte('{')
			} else {
				b.WriteByte(',')
			}
			b.WriteString(l.Name)
			b.WriteString(`="`)
			b.WriteString(escapeLabelValue(l.Value))
			b.WriteByte('"')
		}
		if len(s.Labels) > 0 {
			b.WriteByte('}')
		}
		b.WriteByte(' ')
		b.WriteString(formatFloat(s.Value))
		lines = append(lines, b.String())
	}
	sort.Strings(lines)
	w.seen[name] = true
	*w.fams = append(*w.fams, family{name, header(name, help, typ) + strings.Join(lines, "\n") + "\n"})
	return nil
}

// WriteTo renders every family, sorted by name, and writes the result in one call, so a failing collector or a slow
// reader never leaves half a family.
func (r *Registry) WriteTo(dst io.Writer) (int64, error) {
	if r == nil {
		return 0, nil
	}
	r.mu.Lock()
	vecs := append([]*vec(nil), r.vecs...)
	cols := append([]Collector(nil), r.collectors...)
	onErr := r.ErrorFunc
	r.mu.Unlock()

	var fams []family
	w := &Writer{fams: &fams, seen: map[string]bool{}}
	for _, v := range vecs {
		if text := v.render(); text != "" {
			fams = append(fams, family{v.name, text})
			w.seen[v.name] = true
		}
	}
	for _, c := range cols {
		if err := c(w); err != nil && onErr != nil {
			onErr(err)
		}
	}
	sort.Slice(fams, func(i, j int) bool { return fams[i].name < fams[j].name })

	var buf bytes.Buffer
	for _, f := range fams {
		buf.WriteString(f.text)
	}
	n, err := dst.Write(buf.Bytes())
	return int64(n), err
}

func header(name, help, typ string) string {
	return "# HELP " + name + " " + escapeHelp(help) + "\n# TYPE " + name + " " + typ + "\n"
}

// render returns the family as text, or "" when it has no series.
func (v *vec) render() string {
	v.mu.Lock()
	keys := make([]string, 0, len(v.series))
	for k := range v.series {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	snap := make([]series, 0, len(keys))
	for _, k := range keys {
		s := *v.series[k]
		s.counts = append([]uint64(nil), s.counts...)
		snap = append(snap, s)
	}
	v.mu.Unlock()
	if len(snap) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString(header(v.name, v.help, v.typ))
	for _, s := range snap {
		if v.typ != "histogram" {
			b.WriteString(v.name)
			writeLabels(&b, v.labels, s.values, "")
			b.WriteByte(' ')
			b.WriteString(formatFloat(s.value))
			b.WriteByte('\n')
			continue
		}
		var cum uint64
		for i, bound := range v.buckets {
			cum += s.counts[i]
			b.WriteString(v.name + "_bucket")
			writeLabels(&b, v.labels, s.values, formatFloat(bound))
			b.WriteString(" " + strconv.FormatUint(cum, 10) + "\n")
		}
		cum += s.counts[len(v.buckets)]
		b.WriteString(v.name + "_bucket")
		writeLabels(&b, v.labels, s.values, "+Inf")
		b.WriteString(" " + strconv.FormatUint(cum, 10) + "\n")
		b.WriteString(v.name + "_sum")
		writeLabels(&b, v.labels, s.values, "")
		b.WriteString(" " + formatFloat(s.sum) + "\n")
		b.WriteString(v.name + "_count")
		writeLabels(&b, v.labels, s.values, "")
		b.WriteString(" " + strconv.FormatUint(s.count, 10) + "\n")
	}
	return b.String()
}

// writeLabels writes {a="1",b="2"} and, when le is set, the bucket's le label last. It writes nothing for no labels.
func writeLabels(b *strings.Builder, names, values []string, le string) {
	if len(names) == 0 && le == "" {
		return
	}
	b.WriteByte('{')
	for i, n := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(n + `="` + escapeLabelValue(values[i]) + `"`)
	}
	if le != "" {
		if len(names) > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`le="` + le + `"`)
	}
	b.WriteByte('}')
}

// escapeLabelValue escapes backslash, double quote and newline, and replaces bytes that aren't valid UTF-8, as the
// format requires.
func escapeLabelValue(s string) string {
	s = strings.ToValidUTF8(s, "�")
	if !strings.ContainsAny(s, "\\\"\n") {
		return s
	}
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

// escapeHelp escapes backslash and newline, as the format requires of HELP text.
func escapeHelp(s string) string {
	s = strings.ToValidUTF8(s, "�")
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}

// formatFloat writes a value the way the format reads it: whole numbers without an exponent, the rest as short as
// they can be, and +Inf, -Inf and NaN spelled out.
func formatFloat(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "+Inf"
	case math.IsInf(f, -1):
		return "-Inf"
	case f == math.Trunc(f) && math.Abs(f) < 1e15:
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}
