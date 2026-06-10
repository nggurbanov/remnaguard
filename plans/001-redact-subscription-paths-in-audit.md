# Plan 001: Redact subscription paths in audit events

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report; do not improvise. When done, update the status row for this plan
> in `plans/README.md` unless a reviewer told you they maintain the index.
>
> **Drift check (run first)**: `git diff --stat 227989b..HEAD -- internal/server/server.go internal/server/server_test.go internal/alerts/alerts.go README.md`
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding. On a
> mismatch, treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: S
- **Risk**: LOW
- **Depends on**: none
- **Category**: security
- **Planned at**: commit `227989b`, 2026-06-10

## Why this matters

Subscription URLs are bearer-like secrets in this project. Telegram alert
formatting already redacts `/api/sub/{shortUuid}` path segments, but the
JSON audit event path is emitted from the generic deny path before any
redaction. If audit stdout is collected by a log platform, denied public
subscription requests can persist the subscription identifier in logs.

## Current state

- `internal/server/server.go` owns the generic deny path and request context.
- `internal/alerts/alerts.go` already has a path-redaction shape for alert text.
- `internal/server/server_test.go` already has audit decoding helpers near the end of the file.
- `README.md` states subscription URLs should not be logged.

Relevant excerpts:

```go
// internal/server/server.go:2238
func (r *Runtime) deny(w http.ResponseWriter, req *http.Request, route, tokenID, credentialID, reason string, status int) {
    method, path := safeRequestContext(req)
    fields := panelAuditFields(req, "", 0)
    r.audit.EmitRequestFields("request_denied", route, tokenID, credentialID, reason, method, path, status, fields)
    r.alerts.Notify(alerts.Event{
        Method: method,
        Path:   path,
    })
}

// internal/server/server.go:2260
func safeRequestContext(req *http.Request) (string, string) {
    path := req.URL.EscapedPath()
    const maxAlertPath = 256
    if len(path) > maxAlertPath {
        path = path[:maxAlertPath] + "..."
    }
    return method, path
}
```

```go
// internal/alerts/alerts.go:276
emptyDash(redactAlertPath(b.event.Path)),

// internal/alerts/alerts.go:287
func redactAlertPath(path string) string {
    parts := strings.Split(path, "/")
    if len(parts) < 4 || parts[1] != "api" || parts[2] != "sub" || parts[3] == "" {
        return path
    }
    parts[3] = "<redacted>"
    return strings.Join(parts, "/")
}
```

Repo conventions to match:

- Server tests use `httptest.NewServer`, `httptest.NewRecorder`, and helpers such as `decodeAuditEvents` and `assertAuditValue` in `internal/server/server_test.go:2306`.
- Secret-leak assertions should use `assertNoSecretMaterial` where possible.
- Keep redaction small and explicit; do not change audit schema or event names.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Focused tests | `go test ./internal/server ./internal/alerts` | exit 0 |
| Full tests | `go test ./...` | exit 0 |
| Race tests | `go test -race ./...` | exit 0 |
| Vet | `go vet ./...` | exit 0 |
| Lint | `golangci-lint run` | exit 0 |

## Scope

**In scope**:

- `internal/server/server.go`
- `internal/server/server_test.go`
- `internal/alerts/alerts.go` only if you decide to share a redaction helper instead of duplicating the tiny path transform
- `README.md` only if behavior wording needs a small clarification

**Out of scope**:

- Do not change the audit table schema in `internal/audit/audit.go`.
- Do not log request bodies, query strings, headers, token values, credential digests, or raw subscription identifiers.
- Do not change public subscription routing or authorization behavior.
- Do not change alert cooldown or aggregation semantics unless required by a failing test.

## Git workflow

- Branch: `codex/001-redact-subscription-paths-in-audit`
- Commit message style: imperative sentence, for example `Redact subscription paths in audit events`.
- Do not push or open a PR unless the operator instructs it.

## Steps

### Step 1: Add an audit-safe path helper

Add a helper near `safeRequestContext` in `internal/server/server.go`, for example `redactSensitiveAuditPath(path string) string`. It should:

- Return the original path for non-subscription routes.
- Redact only `/api/sub/{segment}` style paths by replacing the segment after `/api/sub/` with `<redacted>`.
- Preserve suffixes such as `/info` or client type path segments.
- Work on escaped paths returned by `req.URL.EscapedPath()`.
- Preserve the existing 256-character truncation behavior from `safeRequestContext`; do not remove that guard.

Prefer using this helper only for audit emission inside `deny`. Keep the original `path` available for response bodies and alert events unless tests show the alert manager benefits from receiving the redacted value too.

**Verify**: `go test ./internal/server -run TestNonExistentAuditPathRedaction` should fail because the test does not exist yet. This confirms you still need Step 2.

### Step 2: Cover denied subscription paths in audit output

Add a server test in `internal/server/server_test.go`. Use the existing `decodeAuditEvents` helper. Shape:

1. Build `cfg := testConfig(upstream.URL, "...")` using the existing test helper. Do not include real secrets in the test.
2. Set `cfg.PublicSubs.Enabled = false`.
3. Create a runtime and set audit output to a `bytes.Buffer`.
4. Send an unauthenticated `GET /api/sub/{test-short-uuid}/info` request.
5. Assert response status is `403`.
6. Assert the last audit event has `event == "request_denied"` and `path == "/api/sub/<redacted>/info"`.
7. Assert the raw test short UUID does not appear in audit output.

Use a clearly fake short UUID such as `audit-redaction-test`; do not use a real subscription identifier.

**Verify**: `go test ./internal/server -run TestDenyAuditRedactsPublicSubscriptionPath -count=1` -> exits 0 and the new test passes.

### Step 3: Keep alert redaction behavior covered

If you duplicated the redaction helper in server code, leave `internal/alerts/alerts.go` alone. If you moved the helper to shared code, update `internal/alerts/alerts_test.go` so the existing alert redaction test still expects `path: /api/sub/<redacted>/info`.

**Verify**: `go test ./internal/alerts -run Test.*Subscription.*Redact -count=1` -> exits 0. If the regexp does not match any tests, run `go test ./internal/alerts -count=1` instead and confirm it exits 0.

### Step 4: Run the standard gates

Run the broader commands after the focused test is green.

**Verify**:

- `go test ./...` -> exit 0
- `go test -race ./...` -> exit 0
- `go vet ./...` -> exit 0
- `golangci-lint run` -> exit 0

## Test plan

- New regression test in `internal/server/server_test.go`: denied public subscription path is redacted in audit JSON.
- Existing alert tests continue to prove Telegram text redacts subscription paths.
- Existing `assertNoSecretMaterial` checks continue to pass.

## Done criteria

- [ ] Audit JSON for denied `/api/sub/{shortUuid}` paths contains `<redacted>` instead of the original segment.
- [ ] Non-subscription audit paths are unchanged.
- [ ] No request bodies, query strings, headers, tokens, or credential digests are added to audit events.
- [ ] `go test ./...`, `go test -race ./...`, `go vet ./...`, and `golangci-lint run` all exit 0.
- [ ] No files outside the in-scope list are modified.
- [ ] `plans/README.md` status row updated.

## STOP conditions

Stop and report back if:

- The deny path no longer calls `EmitRequestFields` with `method, path` near `internal/server/server.go:2238`.
- The fix appears to require changing audit persistence schema.
- You find code that intentionally relies on raw subscription paths in audit output.
- Any verification command fails twice after a reasonable fix attempt.

## Maintenance notes

Future code that emits request paths to any sink should use the same subscription-path redaction rule. Reviewers should check that the redaction applies before stdout or SQLite audit persistence and that no new sink receives the raw public subscription path.
