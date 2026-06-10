# Plan 003: Bound runtime keyed state for rate limits and write locks

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report; do not improvise. When done, update the status row for this plan
> in `plans/README.md` unless a reviewer told you they maintain the index.
>
> **Drift check (run first)**: `git diff --stat 227989b..HEAD -- internal/ratelimit/limit.go internal/ratelimit/limit_test.go internal/server/server.go internal/server/server_test.go`
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding. On a
> mismatch, treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: none
- **Category**: perf
- **Planned at**: commit `227989b`, 2026-06-10

## Why this matters

Public subscription forwarding keys rate limits and concurrency by client IP.
The current keyed semaphore and fixed-window limiter maps never evict keys, so
a long-running process can accumulate state for every source IP it has ever
seen. Restricted write locks also use a process-lifetime `sync.Map`. Bounding
idle keyed state reduces memory pressure without changing policy decisions.

## Current state

- `internal/ratelimit/limit.go` has a `PerKey` map and a `FixedWindow` map with no deletion path.
- `internal/server/server.go` uses `perSubIP.Get(ip)` and `subRate.Allow(ip)` for public subscriptions.
- `Runtime.locks` is a `sync.Map`; `lockResource` stores one mutex per key and never deletes it.
- Token IDs are bounded by config, but public subscription IPs and write keys are externally variable.

Relevant excerpts:

```go
// internal/ratelimit/limit.go:33
type PerKey struct {
    mu sync.Mutex
    n  int
    m  map[string]*Semaphore
}

func (p *PerKey) Get(key string) *Semaphore {
    if p.m[key] == nil {
        p.m[key] = NewSemaphore(p.n)
    }
    return p.m[key]
}
```

```go
// internal/ratelimit/limit.go:50
type FixedWindow struct {
    mu      sync.Mutex
    limit   int
    window  time.Duration
    buckets map[string]bucket
}
```

```go
// internal/server/server.go:1364
ip := clientIP(req)
sem := st.limits.perSubIP.Get(ip)
if !sem.Acquire() {
    r.deny(...)
    return
}
defer sem.Release()
if !st.limits.subRate.Allow(ip) {
    r.deny(...)
    return
}
```

```go
// internal/server/server.go:2148
func (r *Runtime) lockResource(key string) func() {
    v, _ := r.locks.LoadOrStore(key, &sync.Mutex{})
    mu := v.(*sync.Mutex)
    mu.Lock()
    return mu.Unlock
}
```

Repo conventions to match:

- `internal/ratelimit` is tiny and unit-tested directly.
- Server tests use `httptest` and should not rely on sleeps except where existing reload tests already do.
- Prefer standard library synchronization over adding dependencies.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Rate-limit tests | `go test ./internal/ratelimit -count=1` | exit 0 |
| Server tests | `go test ./internal/server -count=1` | exit 0 |
| Race check | `go test -race ./internal/ratelimit ./internal/server` | exit 0 |
| Full tests | `go test ./...` | exit 0 |
| Lint | `golangci-lint run` | exit 0 |

## Scope

**In scope**:

- `internal/ratelimit/limit.go`
- `internal/ratelimit/limit_test.go`
- `internal/server/server.go`
- `internal/server/server_test.go`

**Out of scope**:

- Do not add new public config knobs unless required by a reviewer.
- Do not change default rate values or concurrency values.
- Do not trust `X-Forwarded-For` for client IPs in this plan.
- Do not change public subscription authorization or header forwarding behavior.

## Git workflow

- Branch: `codex/003-bound-runtime-keyed-state`
- Commit message style: imperative sentence, for example `Evict idle runtime keyed state`.
- Do not push or open a PR unless the operator instructs it.

## Steps

### Step 1: Replace `PerKey.Get` usage with acquire/release ownership

In `internal/ratelimit/limit.go`, add an API on `PerKey` that can delete idle keys safely, for example:

```go
func (p *PerKey) Acquire(key string) (release func(), ok bool)
```

Target behavior:

- It should create a keyed semaphore if missing.
- It should try to acquire the semaphore without blocking.
- If acquire succeeds, increment an active reference count for that key.
- The returned release function must release the semaphore, decrement the active count, and delete the key when the active count reaches zero.
- It must be safe under `go test -race`.
- It must not delete a key while another goroutine is waiting on or using the same keyed semaphore.

The existing `Get` method may remain for compatibility if tests or other code still use it, but server code should move to the new acquire/release API.

**Verify**: `go test ./internal/ratelimit -run TestPerKey -count=1` should fail until Step 2 adds tests, or pass if no matching tests exist. Continue to Step 2.

### Step 2: Add direct `PerKey` eviction tests

In `internal/ratelimit/limit_test.go`, add tests covering:

- Acquire and release for one key succeeds.
- After release, an exported or test-only size method shows the key is gone.
- A saturated key returns `ok == false`.
- Two different keys do not block each other.

It is acceptable to add a small `Len()` method on `PerKey` for tests and diagnostics if it is concurrency-safe.

**Verify**: `go test ./internal/ratelimit -run TestPerKey -count=1` -> exits 0.

### Step 3: Prune expired fixed-window buckets

In `FixedWindow.Allow`, add opportunistic deletion of buckets whose window has expired. Avoid an O(n) scan on every request if possible; a simple counter or last-prune timestamp is fine.

Target behavior:

- A key whose window has expired is removed or overwritten before it can live forever.
- The existing behavior from `TestFixedWindow` remains unchanged.
- Add a test using a very short window spec such as `1/s` only if it can be deterministic. If sleeping would make the test flaky, add a package-private `allowAt(key, now)` helper and test with controlled times.

**Verify**: `go test ./internal/ratelimit -run TestFixedWindow -count=1` -> exits 0.

### Step 4: Use the new keyed semaphore API in server limits

In `internal/server/server.go`, change:

- Per-token concurrency at the current `st.limits.perToken.Get(tok.ID)` call.
- Public subscription per-IP concurrency at the current `st.limits.perSubIP.Get(ip)` call.

Target call shape:

```go
release, ok := st.limits.perSubIP.Acquire(ip)
if !ok {
    r.deny(...)
    return
}
defer release()
```

Preserve status codes and denial reasons exactly.

**Verify**: `go test ./internal/server -run 'Test.*Rate|Test.*Concurrency|TestPublic' -count=1` -> exits 0. If the regexp misses existing tests, run `go test ./internal/server -count=1`.

### Step 5: Replace `Runtime.locks sync.Map` with a ref-counted keyed locker

In `internal/server/server.go` or a new file under `internal/server`, replace `Runtime.locks sync.Map` with a small keyed locker type.

Required behavior:

- `lockResource(key)` still returns an unlock function.
- The same key serializes concurrent restricted writes.
- Different keys can run independently.
- The lock entry is deleted after the last holder releases it.
- Deletion must not allow a third same-key writer to bypass a second writer that was already waiting.

Suggested shape:

```go
type keyedLocker struct {
    mu sync.Mutex
    m  map[string]*lockEntry
}

type lockEntry struct {
    mu   sync.Mutex
    refs int
}
```

Increment `refs` under the map mutex before locking the entry mutex. On unlock, unlock the entry mutex, then decrement refs under the map mutex and delete when zero.

**Verify**: Add server unit tests for same-key serialization and post-release cleanup, then run `go test ./internal/server -run Test.*Lock -count=1` -> exits 0.

### Step 6: Run race and full gates

Run the concurrency-sensitive checks.

**Verify**:

- `go test -race ./internal/ratelimit ./internal/server` -> exit 0
- `go test ./...` -> exit 0
- `go test -race ./...` -> exit 0
- `golangci-lint run` -> exit 0

## Test plan

- New `internal/ratelimit` tests for `PerKey` acquire/release, saturation, and key cleanup.
- New or extended `FixedWindow` tests for expired bucket cleanup.
- New `internal/server` keyed-lock tests proving same-key serialization and cleanup.
- Existing public subscription and restricted write tests remain green.

## Done criteria

- [ ] `PerKey` entries are removed when no request is using the key.
- [ ] Expired `FixedWindow` buckets are pruned or overwritten and cannot live for process lifetime.
- [ ] Restricted write lock entries are removed after the last same-key writer releases.
- [ ] Same-key restricted writes remain serialized under race testing.
- [ ] `go test ./...`, `go test -race ./...`, and `golangci-lint run` all exit 0.
- [ ] No files outside the in-scope list are modified.
- [ ] `plans/README.md` status row updated.

## STOP conditions

Stop and report back if:

- A safe lock cleanup requires changing restricted-write behavior.
- The new keyed semaphore API would block instead of preserving current nonblocking rate/concurrency denial behavior.
- Tests become timing/flakiness dependent.
- Any verification command fails twice after a reasonable fix attempt.

## Maintenance notes

Reviewers should focus on race safety and on preserving existing denial reasons. Future public-edge features that key state by externally supplied values should reuse these bounded primitives instead of adding another process-lifetime map.
