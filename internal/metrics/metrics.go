package metrics

import (
	"fmt"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync"
)

type Registry struct {
	mu       sync.Mutex
	counters map[string]float64
	gauges   map[string]float64
}

func New() *Registry {
	return &Registry{counters: make(map[string]float64), gauges: make(map[string]float64)}
}

func NewBuildInfo() *Registry {
	r := New()
	r.Set("knock_proxy_build_info", map[string]string{"goos": runtime.GOOS, "goarch": runtime.GOARCH}, 1)
	return r
}

func (r *Registry) Inc(name string, labels map[string]string) {
	r.Add(name, labels, 1)
}

func (r *Registry) Add(name string, labels map[string]string, value float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counters[key(name, labels)] += value
}

func (r *Registry) Set(name string, labels map[string]string, value float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gauges[key(name, labels)] = value
}

func (r *Registry) AddGauge(name string, labels map[string]string, value float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gauges[key(name, labels)] += value
}

func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(r.Render()))
	})
}

func (r *Registry) Render() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	var names []string
	for k := range r.counters {
		names = append(names, k)
	}
	for k := range r.gauges {
		names = append(names, k)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, k := range names {
		if value, ok := r.counters[k]; ok {
			b.WriteString(k)
			b.WriteByte(' ')
			b.WriteString(fmt.Sprintf("%.0f", value))
			b.WriteByte('\n')
			continue
		}
		if value, ok := r.gauges[k]; ok {
			b.WriteString(k)
			b.WriteByte(' ')
			b.WriteString(fmt.Sprintf("%.0f", value))
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func Reason(reason string) map[string]string {
	return map[string]string{"reason": reason}
}

func key(name string, labels map[string]string) string {
	if len(labels) == 0 {
		return name
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf(`%s="%s"`, k, escape(labels[k])))
	}
	return name + "{" + strings.Join(parts, ",") + "}"
}

func escape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return strings.ReplaceAll(s, `"`, `\"`)
}
