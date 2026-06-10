package ratelimit

import (
	"testing"
	"time"
)

func TestPerKeyAcquireReleasesAndEvicts(t *testing.T) {
	lim := NewPerKey(1)
	release, ok := lim.Acquire("a")
	if !ok {
		t.Fatal("first acquire should pass")
	}
	if lim.Len() != 1 {
		t.Fatalf("expected one keyed entry, got %d", lim.Len())
	}
	release()
	if lim.Len() != 0 {
		t.Fatalf("expected keyed entry to be evicted, got %d", lim.Len())
	}
}

func TestPerKeyAcquireSaturatesPerKey(t *testing.T) {
	lim := NewPerKey(1)
	release, ok := lim.Acquire("a")
	if !ok {
		t.Fatal("first acquire should pass")
	}
	defer release()
	if _, ok := lim.Acquire("a"); ok {
		t.Fatal("saturated key should not acquire")
	}
	if releaseB, ok := lim.Acquire("b"); !ok {
		t.Fatal("different key should acquire independently")
	} else {
		releaseB()
	}
}

func TestFixedWindow(t *testing.T) {
	lim, err := NewFixedWindow("2/m")
	if err != nil {
		t.Fatal(err)
	}
	if !lim.Allow("a") {
		t.Fatal("first request should pass")
	}
	if !lim.Allow("a") {
		t.Fatal("second request should pass")
	}
	if lim.Allow("a") {
		t.Fatal("third request should be limited")
	}
	if !lim.Allow("b") {
		t.Fatal("different key should have its own bucket")
	}
}

func TestFixedWindowPrunesExpiredBuckets(t *testing.T) {
	lim, err := NewFixedWindow("1/s")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	if !lim.allowAt("a", now) {
		t.Fatal("first request should pass")
	}
	if !lim.allowAt("b", now) {
		t.Fatal("different key should pass")
	}
	if !lim.allowAt("a", now.Add(2*time.Second)) {
		t.Fatal("expired key should pass in a new window")
	}
	if len(lim.buckets) != 1 {
		t.Fatalf("expected expired buckets to be pruned, got %d", len(lim.buckets))
	}
}

func TestParseRate(t *testing.T) {
	if _, _, err := ParseRate("bad"); err == nil {
		t.Fatal("expected invalid rate error")
	}
}
