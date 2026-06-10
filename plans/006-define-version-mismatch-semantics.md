# Plan 006: Make `allow_version_mismatch` explicit and safe

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report; do not improvise. When done, update the status row for this plan
> in `plans/README.md` unless a reviewer told you they maintain the index.
>
> **Drift check (run first)**: `git diff --stat 227989b..HEAD -- internal/server/server.go internal/server/server_test.go internal/config/config.go README.md configs/remnaguard.example.yaml`
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding. On a
> mismatch, treat it as a STOP condition.

## Status

- **Priority**: P2
- **Effort**: M
- **Risk**: MED
- **Depends on**: none
- **Category**: bug
- **Planned at**: commit `227989b`, 2026-06-10

## Why this matters

`allow_version_mismatch` is exposed in config but currently cannot open the
guard for any actual mismatch because `isWriteUnsafeMismatch` returns true for
every unequal version. The README also warns that this flag must not be used
to treat writes/actions as policy-enforced for restricted tokens. The fix
needs explicit, tested semantics: the knob should do something useful without
weakening restricted-write safety.

## Current state

- `CompatibilityConfig` exposes `AllowVersionMismatch`.
- `detectVersion` stores only a boolean `versionOK`.
- The helper name suggests write-safety semantics, but it has no route context.

Relevant excerpts:

```go
// internal/config/config.go:63
type CompatibilityConfig struct {
    RemnawaveVersion     string `yaml:"remnawave_version"`
    AssumeVersion        string `yaml:"assume_version"`
    AllowVersionMismatch bool   `yaml:"allow_version_mismatch"`
}
```

```go
// internal/server/server.go:173
func (r *Runtime) detectVersion(ctx context.Context, st *runtimeState) {
    got, err := remnawave.DetectVersion(ctx, st.proxy.Client(), cfg.Upstream.BaseURL, cfg.Upstream.VersionPath)
    if err != nil || got == "" {
        r.audit.Emit("version_detection_failed", "", "", "", "unknown_version", 0)
        return
    }
    ok := got == cfg.Compatibility.RemnawaveVersion || (cfg.Compatibility.AllowVersionMismatch && !isWriteUnsafeMismatch(got, cfg.Compatibility.RemnawaveVersion))
    st.versionOK.Store(ok)
}

// internal/server/server.go:193
func isWriteUnsafeMismatch(got, want string) bool {
    return subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1
}
```

```markdown
README.md:180
`allow_version_mismatch` must not be used to treat writes or actions as
policy-enforced for restricted tokens.
```

Repo conventions to match:

- Runtime readiness is exposed by `/readyz` in `localHandler`.
- Version detection tests already call `rt.Reload` and inspect `versionOK`.
- Denials should use existing `r.deny` reasons; prefer `version_guard` for version-related blocking.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Server tests | `go test ./internal/server -run 'Test.*Version|Test.*Mismatch' -count=1` | exit 0 |
| Full tests | `go test ./...` | exit 0 |
| Race tests | `go test -race ./...` | exit 0 |
| Vet | `go vet ./...` | exit 0 |
| Lint | `golangci-lint run` | exit 0 |

## Scope

**In scope**:

- `internal/server/server.go`
- `internal/server/server_test.go`
- `internal/config/config.go` only if adding a tiny helper or comment improves clarity
- `README.md`
- `configs/remnaguard.example.yaml` only if comments are needed

**Out of scope**:

- Do not update the Remnawave catalog.
- Do not treat restricted writes/actions as policy-enforced when a detected version mismatch is allowed.
- Do not change `assume_version`; it remains an explicit operator override that skips detection.
- Do not add network calls beyond existing version detection.

## Git workflow

- Branch: `codex/006-define-version-mismatch-semantics`
- Commit message style: imperative sentence, for example `Define safe version mismatch behavior`.
- Do not push or open a PR unless the operator instructs it.

## Steps

### Step 1: Implement explicit mismatch state

Add a route-aware state distinction instead of the current `isWriteUnsafeMismatch(got, want)` helper.

Recommended semantics:

- Exact detected version match: `versionOK = true`, no mismatch flag.
- Detection failure: `versionOK = false`.
- Detected mismatch with `allow_version_mismatch: false`: `versionOK = false`.
- Detected mismatch with `allow_version_mismatch: true`: `versionOK = true`, plus a new runtime-state flag such as `versionMismatchAllowed = true`.
- `assume_version` keeps current behavior and should not set the mismatch flag.

This probably means adding an `atomic.Bool` to `runtimeState` next to `versionOK`. Remove or replace `isWriteUnsafeMismatch`; a helper that compares two strings and calls every mismatch unsafe is the current bug.

**Verify**: `go test ./internal/server -run TestReloadRerunsVersionDetection -count=1` -> exits 0.

### Step 2: Block restricted writes/actions during allowed mismatch

In `apiHandler`, after route matching/effective routing and after credential resolution, deny restricted token writes/actions when the new mismatch flag is true.

Target behavior:

- If `st.versionMismatchAllowed.Load()` is true and the request is a restricted write/action (`isRestrictedWrite(route)` and `route.Support == routes.PolicyEnforced`) and the token is not privileged, deny with reason `version_guard`.
- Safe reads may continue.
- Privileged tokens may continue only if this matches the documented intent. If you are unsure, STOP and ask the maintainer; do not silently broaden writes.

Place the check before preflight and body validation so mismatched restricted writes do not reach upstream.

**Verify**: Add a focused test, then run `go test ./internal/server -run TestAllowedVersionMismatchDeniesRestrictedWrites -count=1` -> exits 0.

### Step 3: Add tests for the semantics

In `internal/server/server_test.go`, add tests with a fake upstream metadata response:

- Mismatch with `AllowVersionMismatch=false` leaves readiness closed and API requests get `version_guard`.
- Mismatch with `AllowVersionMismatch=true` opens readiness for safe reads.
- Mismatch with `AllowVersionMismatch=true` denies a restricted write/action before upstream.
- Exact match keeps existing behavior.

Use existing test helpers such as `testConfig`, `httptest.NewServer`, and direct `rt.detectVersion(context.Background(), rt.state.Load())` if that is cleaner than waiting for `Serve`.

**Verify**: `go test ./internal/server -run 'Test.*Version|Test.*Mismatch' -count=1` -> exits 0.

### Step 4: Update docs to say exactly what the flag does

Update the README compatibility paragraph around `allow_version_mismatch`.

The docs should say:

- It allows the process to serve safe reads after successful version detection reports a different version.
- It does not allow restricted writes/actions to be treated as policy-enforced.
- `assume_version` remains the stronger operator override and should be used only when the operator intentionally pins catalog behavior.

**Verify**: `rg -n "allow_version_mismatch" README.md configs` -> output shows updated wording and examples still include the key.

### Step 5: Run standard gates

Run the full verification set.

**Verify**:

- `go test ./...` -> exit 0
- `go test -race ./...` -> exit 0
- `go vet ./...` -> exit 0
- `golangci-lint run` -> exit 0

## Test plan

- New server tests for mismatch denied, mismatch allowed safe-read, mismatch allowed restricted-write denied, and exact match.
- Existing reload/version tests remain green.
- Existing restricted write tests remain green under exact match or assume-version configs.

## Done criteria

- [ ] `allow_version_mismatch: true` has tested behavior for actual detected mismatches.
- [ ] Restricted token writes/actions are denied under allowed mismatch and do not reach upstream.
- [ ] Safe reads continue under allowed mismatch.
- [ ] README describes the exact semantics.
- [ ] `go test ./...`, `go test -race ./...`, `go vet ./...`, and `golangci-lint run` all exit 0.
- [ ] No files outside the in-scope list are modified.
- [ ] `plans/README.md` status row updated.

## STOP conditions

Stop and report back if:

- The maintainer wants different semantics for privileged writes under mismatch.
- Implementing route-aware mismatch requires a broader catalog/version model.
- The code at `detectVersion` no longer stores a simple boolean readiness state.
- Any verification command fails twice after a reasonable fix attempt.

## Maintenance notes

Future Remnawave version support should make this flag less important by adding explicit catalogs per version. Reviewers should be strict: allowed mismatch is an operator escape hatch for reads, not a way to bypass write-policy compatibility.
