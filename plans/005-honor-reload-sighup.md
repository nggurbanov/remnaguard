# Plan 005: Honor the `reload.sighup` setting

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report; do not improvise. When done, update the status row for this plan
> in `plans/README.md` unless a reviewer told you they maintain the index.
>
> **Drift check (run first)**: `git diff --stat 227989b..HEAD -- cmd/remnaguard/main.go configs/remnaguard.example.yaml internal/config/config.go`
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding. On a
> mismatch, treat it as a STOP condition.

## Status

- **Priority**: P2
- **Effort**: S/M
- **Risk**: LOW
- **Depends on**: none
- **Category**: bug
- **Planned at**: commit `227989b`, 2026-06-10

## Why this matters

The config exposes `reload.sighup`, and examples set it to `true`, but the
serve command registers SIGHUP reload unconditionally. Operators who set this
knob to false still get reload behavior. A config knob that is ignored creates
surprise in process managers and makes future reload options less trustworthy.

## Current state

- `internal/config/config.go` defines `ReloadConfig.SIGHUP`.
- `configs/remnaguard.example.yaml` documents `reload.sighup: true`.
- `cmd/remnaguard/main.go` always registers `syscall.SIGHUP`.

Relevant excerpts:

```go
// internal/config/config.go:156
type ReloadConfig struct {
    SIGHUP                       bool `yaml:"sighup"`
    WatchFiles                   bool `yaml:"watch_files"`
    AllowInsecureSecretFilePerms bool `yaml:"allow_insecure_secret_file_permissions"`
}
```

```go
// cmd/remnaguard/main.go:92
ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
defer stop()
sigHUP := make(chan os.Signal, 1)
signal.Notify(sigHUP, syscall.SIGHUP)
go func() {
    for range sigHUP {
        next, err := config.Load(*cfgPath)
        // reload or audit reload_rejected
    }
}()
return rt.Serve(ctx)
```

Repo conventions to match:

- Audit events use `rt.Audit().Emit(...)`.
- CLI logic lives in `cmd/remnaguard/main.go` with unexported helpers.
- If tests are added, use `package main` in `cmd/remnaguard/main_test.go`.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| CLI tests | `go test ./cmd/remnaguard -count=1` | exit 0 |
| Full tests | `go test ./...` | exit 0 |
| Vet | `go vet ./...` | exit 0 |
| Lint | `golangci-lint run` | exit 0 |

## Scope

**In scope**:

- `cmd/remnaguard/main.go`
- `cmd/remnaguard/main_test.go` if it already exists from Plan 004 or create it here
- `configs/remnaguard.example.yaml` only if comments are added
- `docs/deployment.md` only if behavior wording needs clarification

**Out of scope**:

- Do not implement `reload.watch_files`.
- Do not change runtime reload validation or state swap semantics.
- Do not change SIGTERM/SIGINT shutdown behavior.

## Git workflow

- Branch: `codex/005-honor-reload-sighup`
- Commit message style: imperative sentence, for example `Honor reload sighup config`.
- Do not push or open a PR unless the operator instructs it.

## Steps

### Step 1: Extract the SIGHUP reload loop into a testable helper

In `cmd/remnaguard/main.go`, extract the body of the SIGHUP loop into a small helper that accepts:

- A signal channel, preferably `<-chan os.Signal`.
- A load function.
- A reload function.
- An audit emit function.
- A done context or stop channel if needed for tests.

The helper should be testable without sending a real OS signal to the test process. Keep serve behavior unchanged when enabled.

**Verify**: `go test ./cmd/remnaguard -count=1` -> exits 0 or reports no tests.

### Step 2: Gate SIGHUP registration on `cfg.Reload.SIGHUP`

In `serve`, only create the SIGHUP channel, call `signal.Notify`, and start the reload goroutine when `cfg.Reload.SIGHUP` is true.

When enabled, also call `signal.Stop(sigHUP)` on exit or via defer so tests and process shutdown do not retain signal subscriptions.

When disabled, SIGHUP should not trigger config reload through RemnaGuard.

**Verify**: `go test ./cmd/remnaguard -count=1` -> exits 0 or reports no tests.

### Step 3: Add helper tests

Add tests in `cmd/remnaguard/main_test.go`:

- Enabled reload loop receives a synthetic SIGHUP on the injected channel and calls the reload function once.
- Invalid load path emits `reload_rejected` and does not call reload.
- Disabled serve setup does not start the loop. If testing `serve` directly is awkward because it starts servers, test the extracted setup helper instead.

Do not send a real SIGHUP to the process in tests.

**Verify**: `go test ./cmd/remnaguard -run Test.*SIGHUP -count=1` -> exits 0.

### Step 4: Run standard gates

Run the standard suite.

**Verify**:

- `go test ./...` -> exit 0
- `go vet ./...` -> exit 0
- `golangci-lint run` -> exit 0

## Test plan

- Unit tests for the reload loop using injected signal channels and callbacks.
- Existing runtime reload tests in `internal/server` remain green.
- No test should send real process signals.

## Done criteria

- [ ] `reload.sighup: false` prevents SIGHUP registration in `serve`.
- [ ] `reload.sighup: true` preserves existing reload behavior and audit events.
- [ ] Tests cover enabled and disabled behavior without real OS signals.
- [ ] `go test ./...`, `go vet ./...`, and `golangci-lint run` all exit 0.
- [ ] No files outside the in-scope list are modified.
- [ ] `plans/README.md` status row updated.

## STOP conditions

Stop and report back if:

- Testing requires sending real SIGHUP to the running test process.
- Honoring the config requires changing runtime reload semantics.
- You discover `reload.sighup` was intentionally documented but reserved as a no-op.
- Any verification command fails twice after a reasonable fix attempt.

## Maintenance notes

If file watching is implemented later, it should follow this pattern: config knobs must gate actual watchers, and reload loops should be testable through injected channels or callbacks.
