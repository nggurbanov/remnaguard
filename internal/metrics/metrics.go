package metrics

import (
	"fmt"
	"net/http"
	"sync"
)

type Registry struct {
	mu     sync.Mutex
	counts map[string]int64
}

func New() *Registry { return &Registry{counts: map[string]int64{}} }

func (r *Registry) Inc(route, reason, support, statusClass string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counts[route+"|"+reason+"|"+support+"|"+statusClass]++
}

func (r *Registry) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	for key, val := range r.counts {
		_, _ = fmt.Fprintf(w, "remnaguard_requests_total{key=%q} %d\n", key, val)
	}
}
