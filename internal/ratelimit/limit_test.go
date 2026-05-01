package ratelimit

import "testing"

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

func TestParseRate(t *testing.T) {
	if _, _, err := ParseRate("bad"); err == nil {
		t.Fatal("expected invalid rate error")
	}
}
