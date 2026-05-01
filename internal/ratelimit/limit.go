package ratelimit

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Semaphore struct {
	ch chan struct{}
}

func NewSemaphore(n int) *Semaphore {
	if n <= 0 {
		n = 1
	}
	return &Semaphore{ch: make(chan struct{}, n)}
}

func (s *Semaphore) Acquire() bool {
	select {
	case s.ch <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Semaphore) Release() { <-s.ch }

type PerKey struct {
	mu sync.Mutex
	n  int
	m  map[string]*Semaphore
}

func NewPerKey(n int) *PerKey { return &PerKey{n: n, m: map[string]*Semaphore{}} }

func (p *PerKey) Get(key string) *Semaphore {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.m[key] == nil {
		p.m[key] = NewSemaphore(p.n)
	}
	return p.m[key]
}

type FixedWindow struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	buckets map[string]bucket
}

type bucket struct {
	start time.Time
	count int
}

func NewFixedWindow(spec string) (*FixedWindow, error) {
	limit, window, err := ParseRate(spec)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		return nil, nil
	}
	return &FixedWindow{limit: limit, window: window, buckets: map[string]bucket{}}, nil
}

func (f *FixedWindow) Allow(key string) bool {
	if f == nil {
		return true
	}
	now := time.Now()
	f.mu.Lock()
	defer f.mu.Unlock()
	b := f.buckets[key]
	if b.start.IsZero() || now.Sub(b.start) >= f.window {
		f.buckets[key] = bucket{start: now, count: 1}
		return true
	}
	if b.count >= f.limit {
		return false
	}
	b.count++
	f.buckets[key] = b
	return true
}

func ParseRate(spec string) (int, time.Duration, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return 0, 0, nil
	}
	parts := strings.Split(spec, "/")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid rate %q", spec)
	}
	n, err := strconv.Atoi(parts[0])
	if err != nil || n < 0 {
		return 0, 0, fmt.Errorf("invalid rate %q", spec)
	}
	switch parts[1] {
	case "s", "sec", "second":
		return n, time.Second, nil
	case "m", "min", "minute":
		return n, time.Minute, nil
	case "h", "hour":
		return n, time.Hour, nil
	default:
		d, err := time.ParseDuration(parts[1])
		if err != nil {
			return 0, 0, fmt.Errorf("invalid rate window %q", parts[1])
		}
		return n, d, nil
	}
}
