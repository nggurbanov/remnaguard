# Plan 009: Split the server hotspot into focused files without behavior changes

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report; do not improvise. When done, update the status row for this plan
> in `plans/README.md` unless a reviewer told you they maintain the index.
>
> **Drift check (run first)**: `git diff --stat 227989b..HEAD -- internal/server/server.go internal/server/server_test.go`
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding. This plan
> intentionally depends on earlier plans that also touch `server.go`; if they
> have landed, use the live post-plan code as the source of truth and keep
> this plan behavior-preserving.

## Status

- **Priority**: P3
- **Effort**: L
- **Risk**: MED
- **Depends on**: plans/001-redact-subscription-paths-in-audit.md, plans/002-validate-allowed-request-fields-keys.md, plans/003-bound-runtime-keyed-state.md, plans/006-define-version-mismatch-semantics.md
- **Category**: tech-debt
- **Planned at**: commit `227989b`, 2026-06-10

## Why this matters

`internal/server/server.go` is the main risk hotspot: it is 2291 lines and
has the highest recent churn in the repository. It combines request routing,
auth facade behavior, audit emission, query validation, body policy, response
filtering, write safety, locks, and local handlers. A behavior-preserving
split into focused files reduces review risk for future security changes
without changing the package API.

## Current state

- `internal/server/server.go` was 2291 lines at planning time.
- `internal/server/server_test.go` was 2385 lines and already covers many behaviors.
- Recent git churn is concentrated in `internal/server/server.go` and `internal/server/server_test.go`.

Relevant excerpts:

```text
wc -l internal/server/server.go internal/server/server_test.go
2291 internal/server/server.go
2385 internal/server/server_test.go
```

```text
git log --since='90 days ago' --name-only --pretty=format: | ... | head
23 internal/server/server.go
21 internal/server/server_test.go
9  internal/config/config.go
```

```go
// internal/server/server.go:197
func (r *Runtime) apiHandler() http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
        st := r.state.Load()
        cfg := st.cfg
        // route match, auth, rate limits, policy decision, write safety,
        // proxying, response policy, post-write verification, audit emission
    })
}
```

```go
// internal/server/server.go:930
func validateRouteQuery(route routes.Route, rawQuery string) error { ... }
func validateRequestQuery(req *http.Request, route routes.Route, rawQuery string) error { ... }

// internal/server/server.go:1737
func filterResponsePolicy(route routes.Route, tok *config.TokenPolicy, res *proxy.Response, req *http.Request, rawQuery string) error { ... }

// internal/server/server.go:2063
func (r *Runtime) preflight(req *http.Request, st *runtimeState, route routes.Route, path string, tok *config.TokenPolicy) error { ... }
```

Repo conventions to match:

- Keep everything in package `server`; do not introduce exported APIs unless already exported.
- Prefer small cohesive files over new abstractions.
- Behavior is guarded by `go test ./internal/server`, `go test -race ./internal/server`, and full suite gates.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Baseline server tests | `go test ./internal/server -count=1` | exit 0 |
| Server race tests | `go test -race ./internal/server` | exit 0 |
| Full tests | `go test ./...` | exit 0 |
| Full race | `go test -race ./...` | exit 0 |
| Vet | `go vet ./...` | exit 0 |
| Lint | `golangci-lint run` | exit 0 |
| Size check | `wc -l internal/server/server.go` | lower than before this plan by at least 400 lines |

## Scope

**In scope**:

- `internal/server/server.go`
- New files under `internal/server/`, for example:
  - `request_context.go`
  - `body_policy.go`
  - `response_policy.go`
  - `write_safety.go`
  - `panel_facade.go` only if extracting an already cohesive block is mechanical
- `internal/server/server_test.go` only for package-level test name updates if needed; prefer no test changes

**Out of scope**:

- Do not change behavior, status codes, denial reasons, response schemas, audit fields, or route support.
- Do not move code to a new package.
- Do not refactor business logic while moving code.
- Do not split tests in this plan unless a compile issue requires a tiny adjustment.
- Do not combine this with feature work such as richer policy dry-runs.

## Git workflow

- Branch: `codex/009-extract-server-hotspot`
- Commit message style: imperative sentence, for example `Split server policy helpers into focused files`.
- Do not push or open a PR unless the operator instructs it.

## Steps

### Step 1: Establish a clean baseline

Run the server and full tests before moving code. If the baseline fails, stop; this plan is not meant to diagnose existing failures.

**Verify**:

- `go test ./internal/server -count=1` -> exit 0
- `go test ./...` -> exit 0

### Step 2: Move request-context and generic response helpers

Create `internal/server/request_context.go` and move only cohesive generic helpers such as:

- `writeJSON`
- `safeRequestContext`
- subscription path redaction helper from Plan 001 if present
- `clientIP`
- body-cache helpers only if they are not more naturally placed with write safety

Do not modify function bodies except for import adjustments. Keep names unchanged.

**Verify**: `go test ./internal/server -count=1` -> exit 0.

### Step 3: Move body-policy validation helpers

Create `internal/server/body_policy.go` and move:

- `validateBodyPolicy`
- `validateTokenRequestFields`
- `validateResourceCreateConstraints`
- `validateResourceWriteConstraints`
- user body constraint validators such as username/email/telegram/squad/subscription page config checks
- small raw-body helpers only if needed by these functions

Do not change behavior. If a helper is used by write safety too, leave it in the file that minimizes import churn; package-level functions can remain unexported across files.

**Verify**: `go test ./internal/server -run 'TestTokenSpecificAllowedRequestFields|TestRestricted' -count=1` -> exit 0.

### Step 4: Move response policy helpers

Create `internal/server/response_policy.go` and move:

- `enforceResponsePolicy`
- `filterResponsePolicy`
- response list filtering helpers
- squad redaction helpers
- subscription page config response helpers
- count metadata redaction helpers

Do not change JSON shapes or filtering predicates.

**Verify**: `go test ./internal/server -run 'Test.*Read|Test.*Filter|Test.*Redact|Test.*SubscriptionPage' -count=1` -> exit 0. If the regexp misses tests, run `go test ./internal/server -count=1`.

### Step 5: Move write-safety helpers

Create `internal/server/write_safety.go` and move:

- `isRestrictedWrite`
- `preflight`
- `preflightUser`
- `postWriteVerify`
- `lockResource` and lock-key helpers, including Plan 003 keyed locker if present
- `bodyString` and body cache helpers if they were not moved earlier

Do not change lock behavior or preflight routes.

**Verify**: `go test ./internal/server -run 'TestRestricted|Test.*Write|Test.*Lock|Test.*HWID' -count=1` -> exit 0. If the regexp misses tests, run `go test ./internal/server -count=1`.

### Step 6: Leave `apiHandler` as orchestration

After extraction, `apiHandler` should still read top-to-bottom as the request pipeline, but helper implementations should live in focused files. Do not split `apiHandler` itself in this plan unless a very small extraction is needed for compile clarity.

Run a line-count check. The goal is to reduce `internal/server/server.go` by at least 400 lines from its line count immediately before this plan. If earlier plans already reduced it substantially, document the before/after in the PR or final note.

**Verify**: `wc -l internal/server/server.go` -> line count is at least 400 lower than before this plan started.

### Step 7: Run full gates

Run all standard gates because this is a broad mechanical move.

**Verify**:

- `go test ./internal/server -count=1` -> exit 0
- `go test -race ./internal/server` -> exit 0
- `go test ./...` -> exit 0
- `go test -race ./...` -> exit 0
- `go vet ./...` -> exit 0
- `golangci-lint run` -> exit 0

## Test plan

- This is behavior-preserving extraction. Prefer relying on existing tests.
- Add tests only if a moved helper becomes easier to test and the test protects an existing behavior.
- The key verification is full server tests plus race tests before and after extraction.

## Done criteria

- [ ] `internal/server/server.go` is at least 400 lines shorter than before this plan started.
- [ ] Extracted files are cohesive and remain in package `server`.
- [ ] No behavior, response shape, denial reason, audit field, route support, or config semantic changed intentionally.
- [ ] `go test ./internal/server`, `go test -race ./internal/server`, `go test ./...`, `go test -race ./...`, `go vet ./...`, and `golangci-lint run` all exit 0.
- [ ] No files outside `internal/server/` are modified unless a tiny test import/name adjustment is required.
- [ ] `plans/README.md` status row updated.

## STOP conditions

Stop and report back if:

- A move requires changing behavior to make tests pass.
- You need to create a new package or exported API.
- The baseline tests fail before extraction.
- A merge conflict or prior plan changes make the listed helper boundaries inaccurate.
- Any verification command fails twice after a reasonable fix attempt.

## Maintenance notes

Reviewers should treat this as a mechanical diff: moved code should be recognizable. After this lands, future feature work should add new policy helpers to the focused files instead of growing `server.go` again.
