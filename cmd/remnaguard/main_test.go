package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/nggurbanov/remnaguard/internal/config"
)

func TestWriteTokenFileWithValidationRemovesNewFileOnFailure(t *testing.T) {
	cfgPath, tokenPath := writeTestConfig(t)
	doc := &tokenDoc{Tokens: []config.TokenPolicy{{
		ID:          "tenant-a",
		Scopes:      []string{"not-a-scope"},
		Credentials: []config.Credential{{ID: "cred", HMACSHA256: "digest"}},
	}}}
	if err := writeTokenFileWithValidation(tokenPath, doc, cfgPath); err == nil {
		t.Fatal("expected validation failure")
	}
	if _, err := os.Stat(tokenPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected new invalid token file to be removed, stat error: %v", err)
	}
}

func TestWriteTokenFileWithValidationRestoresExistingFileOnFailure(t *testing.T) {
	cfgPath, tokenPath := writeTestConfig(t)
	original := []byte("tokens: []\n")
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	doc := &tokenDoc{Tokens: []config.TokenPolicy{{
		ID:          "tenant-a",
		Scopes:      []string{"not-a-scope"},
		Credentials: []config.Credential{{ID: "cred", HMACSHA256: "digest"}},
	}}}
	if err := writeTokenFileWithValidation(tokenPath, doc, cfgPath); err == nil {
		t.Fatal("expected validation failure")
	}
	got, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("existing token file was not restored: %q", got)
	}
}

func TestWriteTokenFileWithValidationWrites0600(t *testing.T) {
	cfgPath, tokenPath := writeTestConfig(t)
	doc := &tokenDoc{Tokens: []config.TokenPolicy{{
		ID:          "tenant-a",
		Scopes:      []string{"users:read"},
		Credentials: []config.Credential{{ID: "cred", HMACSHA256: "digest"}},
	}}}
	if err := writeTokenFileWithValidation(tokenPath, doc, cfgPath); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("token file mode got %o want 0600", got)
	}
}

func TestSIGHUPReloadLoopAppliesReload(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signals := make(chan os.Signal, 1)
	applied := make(chan struct{}, 1)
	signals <- syscall.SIGHUP
	runSIGHUPReloadLoop(ctx, signals, func() (*config.Config, error) {
		return config.Defaults(), nil
	}, func(*config.Config) error {
		applied <- struct{}{}
		cancel()
		return nil
	}, func(string, string) {})
	select {
	case <-applied:
	default:
		t.Fatal("expected reload to be applied")
	}
}

func TestSIGHUPReloadLoopRejectsInvalidLoad(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signals := make(chan os.Signal, 1)
	signals <- syscall.SIGHUP
	var reloads int
	var events []string
	runSIGHUPReloadLoop(ctx, signals, func() (*config.Config, error) {
		cancel()
		return nil, errors.New("bad config")
	}, func(*config.Config) error {
		reloads++
		return nil
	}, func(event, reason string) {
		events = append(events, event+":"+reason)
	})
	if reloads != 0 {
		t.Fatalf("reload called %d times", reloads)
	}
	if len(events) != 1 || events[0] != "reload_rejected:invalid_config" {
		t.Fatalf("unexpected events: %#v", events)
	}
}

func writeTestConfig(t *testing.T) (string, string) {
	t.Helper()
	t.Setenv("REMNAGUARD_TOKEN_PEPPER", "pepper-pepper-pepper-pepper-pepper-32")
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "remnaguard.yaml")
	if err := os.WriteFile(cfgPath, []byte(`upstream:
  base_url: "https://example.test"
  bearer: "root"
include:
  - "tokens.d/*.yaml"
`), 0600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, filepath.Join(dir, "tokens.d", "tenant-a.yaml")
}
