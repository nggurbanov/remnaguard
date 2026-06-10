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
	m  map[string]*perKeyEntry
}

type perKeyEntry struct {
	sem    *Semaphore
	active int
}

func NewPerKey(n int) *PerKey { return &PerKey{n: n, m: map[string]*perKeyEntry{}} }

func (p *PerKey) Get(key string) *Semaphore {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.m[key] == nil {
		p.m[key] = &perKeyEntry{sem: NewSemaphore(p.n)}
	}
	return p.m[key].sem
}

func (p *PerKey) Acquire(key string) (func(), bool) {
	p.mu.Lock()
	entry := p.m[key]
	if entry == nil {
		entry = &perKeyEntry{sem: NewSemaphore(p.n)}
		p.m[key] = entry
	}
	if !entry.sem.Acquire() {
		p.mu.Unlock()
		return nil, false
	}
	entry.active++
	p.mu.Unlock()
	return func() {
		entry.sem.Release()
		p.mu.Lock()
		entry.active--
		if entry.active == 0 && p.m[key] == entry {
			delete(p.m, key)
		}
		p.mu.Unlock()
	}, true
}

func (p *PerKey) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.m)
}

type FixedWindow struct {
	mu        sync.Mutex
	limit     int
	window    time.Duration
	buckets   map[string]bucket
	lastPrune time.Time
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
	return f.allowAt(key, time.Now())
}

func (f *FixedWindow) allowAt(key string, now time.Time) bool {
	if f == nil {
		return true
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lastPrune.IsZero() || now.Sub(f.lastPrune) >= f.window {
		for k, b := range f.buckets {
			if !b.start.IsZero() && now.Sub(b.start) >= f.window {
				delete(f.buckets, k)
			}
		}
		f.lastPrune = now
	}
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
