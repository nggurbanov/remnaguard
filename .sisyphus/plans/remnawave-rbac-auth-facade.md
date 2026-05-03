# Remnawave RBAC Auth Facade

## TL;DR
> **Summary**: Add a `remnawave_panel_facade` mode to RemnaGuard that impersonates enough of Remnawave's backend auth/API contract for an existing Remnawave frontend instance to run as a restricted panel. RemnaGuard owns Telegram-only login, issues its own browser session token, maps Telegram actors to existing RemnaGuard scoped credentials from YAML, and uses the existing catalog/policy pipeline for all normal Remnawave API authorization.
> **Deliverables**:
> - Remnawave-compatible auth facade for Telegram-only restricted panel login using raw contract shapes like `{ "response": { ... } }`
> - Server-side YAML actor-to-credential mapping
> - Distinct browser session token type, never raw `rg_...` or upstream Remnawave root/API token
> - Proxy pipeline integration: session token → mapped credential → existing route catalog/scopes/policies → upstream root bearer
> - Tests-after suite for auth facade, mapping, deny/allow, audit, and compatibility
> - Deployment example for restricted panel `/api/* -> remnaguard` beside original full-admin Remnawave panel
> **Effort**: Large
> **Parallel**: YES - 4 waves
> **Critical Path**: Task 1 → Task 2 → Task 4 → Task 7 → Task 9 → Final Verification

## Context
### Original Request
Add RBAC to the user's own production Remnawave panel using this project (`remnaguard`) without building a separate RBAC system. The final direction is: permissions remain entirely in existing RemnaGuard token scopes; RemnaGuard should pretend to be enough of the Remnawave backend for a restricted panel frontend, including auth.

### Interview Summary
- Remnawave has no useful multi-admin identity model for this: multiple Telegram IDs are login allowlist entries for the same admin, not distinct admin actors.
- Remnawave access tokens include `role`, `username`, and `uuid`, but not `telegram_id`; therefore per-Telegram policy cannot be recovered after native Remnawave login.
- MVP must replace restricted-panel login with RemnaGuard-owned Telegram login/session.
- The existing Remnawave frontend should not be forked initially. It should talk to RemnaGuard as if RemnaGuard were the backend.
- All normal `/api/*` allow/deny decisions must use existing RemnaGuard route catalog/scopes/policies. Do not create a separate RBAC model.
- User selected: Telegram-only MVP, YAML actor mapping, no frontend fork first, tests-after.

### Metis Review (gaps addressed)
- Added explicit MVP mode flag so auth facade cannot break existing API-token gateway behavior.
- Pinned token separation: browser receives a RemnaGuard panel session token, not raw `rg_...` and not upstream root/API token.
- Added compatibility contract tasks for `/api/auth/status`, OAuth2 Telegram authorize/callback, unsupported auth endpoints, and raw HTTP `{ "response": { "accessToken": "..." } }` response shape.
- Added deterministic behavior for unmapped actors, unknown routes, unsupported auth methods, and audit coverage.
- Guarded against scope creep: no RBAC UI/tables, no frontend fork, no second hardcoded route allowlist for normal API calls.

## Work Objectives
### Core Objective
Implement a production-cautious MVP where RemnaGuard can serve as a Remnawave-compatible restricted-panel backend facade: it authenticates Telegram actors, maps them to existing RemnaGuard credentials, and enforces existing RemnaGuard scopes for all cataloged Remnawave API requests.

### Deliverables
- Configurable `remnawave_panel_facade` mode.
- Telegram-only auth facade endpoints compatible with the existing Remnawave frontend bootstrap path.
- YAML actor mapping from Telegram ID to existing RemnaGuard token/credential reference.
- RemnaGuard-issued panel session token with separate issuer/audience/secret/TTL.
- Proxy integration that resolves panel session tokens into existing credential policies before upstreaming.
- Compatibility/deployment docs and example config.
- Tests-after coverage for all auth/security behavior.

### Definition of Done (verifiable conditions with commands)
- `go test ./...` passes.
- `remnaguard validate -c configs/remnaguard.panel-facade.example.yaml` succeeds.
- `remnaguard policy test -c configs/remnaguard.panel-facade.example.yaml --token support-readonly --method GET --path /api/users` returns allow/expected explanation for configured scopes.
- Contract tests prove `/api/auth/status` returns frontend-compatible Telegram-only auth status and no identity/secrets.
- Integration tests prove Telegram login/callback returns raw HTTP `{ "response": { "accessToken": "<panel-session>" } }` and the token does not start with `rg_`.
- Integration tests prove mapped actor allowed route is proxied with upstream root bearer and denied route returns `403` without upstream call.
- Integration tests prove unknown routes fail closed.

### Must Have
- RemnaGuard panel facade mode is opt-in and disabled by default.
- Browser-visible token is a distinct panel session token, never a raw RemnaGuard credential token and never a Remnawave root/API/JWT token.
- YAML mapping references existing RemnaGuard credential IDs/token IDs; it does not define permissions.
- Normal Remnawave API authorization uses existing catalog/scopes/policies only.
- Unsupported auth methods are reported disabled or rejected compatibly.
- Audit events include login success/failure, unmapped actor, token validation failure, policy deny, unknown route deny, and upstream failure.
- Existing API-token gateway behavior remains backward compatible.

### Must NOT Have (guardrails, AI slop patterns, scope boundaries)
- Do not add RBAC tables, roles, permissions UI, admin-management UI, or SQLite-backed authorization model.
- Do not fork or modify Remnawave frontend in MVP.
- Do not expose raw `rg_...`, upstream root bearer, Telegram bot token, or Remnawave API token in browser, responses, logs, metrics, or audit event bodies.
- Do not implement generic blind `/api/*` proxy bypassing route catalog/policy checks.
- Do not introduce a second hardcoded allow/deny list for normal Remnawave API routes.
- Do not accept actor ID, credential ID, scopes, or upstream token from frontend request body/query/header.
- Do not route restricted-panel auth to original Remnawave backend.

## Verification Strategy
> ZERO HUMAN INTERVENTION - all verification is agent-executed.
- Test decision: tests-after using Go unit/integration tests plus command-level validation
- QA policy: Every task has agent-executed scenarios
- Evidence: `.sisyphus/evidence/task-{N}-{slug}.{ext}`

## Execution Strategy
### Parallel Execution Waves
> Target: 5-8 tasks per wave. <3 per wave (except final) = under-splitting.
> Extract shared dependencies as Wave-1 tasks for max parallelism.

Wave 1: Task 1 config/schema, Task 2 auth compatibility contract, Task 3 session-token design
Wave 2: Task 4 Telegram auth facade, Task 5 actor mapping, Task 6 auth endpoint compatibility
Wave 3: Task 7 proxy pipeline integration, Task 8 audit/errors, Task 9 tests-after suite
Wave 4: Task 10 deployment docs/example, Task 11 compatibility smoke/QA hardening

### Dependency Matrix (full, all tasks)
- Task 1 blocks Tasks 3, 5, 7, 10.
- Task 2 blocks Tasks 4, 6, 9, 11.
- Task 3 blocks Tasks 4, 7, 9.
- Task 4 blocks Tasks 6, 7, 8, 9.
- Task 5 blocks Tasks 7, 8, 9.
- Task 6 blocks Tasks 9, 11.
- Task 7 blocks Tasks 8, 9, 10, 11.
- Task 8 blocks Tasks 9, 11.
- Task 9 blocks Task 11.
- Task 10 blocks Task 11.

### Agent Dispatch Summary (wave → task count → categories)
- Wave 1 → 3 tasks → business-logic, deep, business-logic
- Wave 2 → 3 tasks → business-logic, business-logic, business-logic
- Wave 3 → 3 tasks → business-logic, business-logic, deep
- Wave 4 → 2 tasks → writing, deep

## TODOs
> Implementation + Test = ONE task. Never separate.
> EVERY task MUST have: Agent Profile + Parallelization + QA Scenarios.

- [x] 1. Add opt-in panel facade configuration

  **What to do**: Add an opt-in config section for Remnawave panel facade mode. Use a concrete schema under the existing config system, for example:
  ```yaml
  panel_facade:
    enabled: true
    session:
      issuer: "remnaguard-panel"
      audience: "remnawave-restricted-panel"
      token_ttl: "12h"
      secret_env: "REMNAGUARD_PANEL_SESSION_SECRET"
    telegram:
      bot_token_env: "REMNAGUARD_TELEGRAM_BOT_TOKEN"
      auth_max_age: "5m"
    actors:
      telegram:
        "123456789":
          credential_id: "support-readonly"
          display_name: "Support Alice"
  ```
  Validate: facade disabled by default; enabled mode requires session secret env, Telegram bot token env, at least one actor mapping, referenced credential exists, credential is enabled, and no raw `rg_...` value appears in actor mapping. Keep config validation fail-closed.

  **Must NOT do**: Do not add permissions/scopes inside actor mapping. Do not change existing token config semantics. Do not make facade mode default-on.

  **Recommended Agent Profile**:
  - Category: `business-logic` - Reason: config validation and security invariants are core logic
  - Skills: [] - no specialized skill required
  - Omitted: [`frontend-design`] - no frontend/UI work

  **Parallelization**: Can Parallel: YES | Wave 1 | Blocks: Tasks 3, 5, 7, 10 | Blocked By: none

  **References** (executor has NO interview context - be exhaustive):
  - Pattern: `internal/config/config.go` - existing YAML config structs and validation patterns
  - Pattern: `configs/remnaguard.example.yaml` - example config style
  - Pattern: `internal/auth/auth.go` - existing token credential model; do not expose raw token values
  - Pattern: `README.md` - security defaults and config posture

  **Acceptance Criteria** (agent-executable only):
  - [ ] `go test ./internal/config ./internal/auth ./internal/server` passes.
  - [ ] `remnaguard validate -c configs/remnaguard.example.yaml` still succeeds with facade disabled.
  - [ ] A test config with `panel_facade.enabled: true` and missing `REMNAGUARD_PANEL_SESSION_SECRET` fails validation.
  - [ ] A test config with actor mapping containing a raw `rg_` token fails validation.
  - [ ] A test config whose actor references a missing/disabled credential fails validation.

  **QA Scenarios** (MANDATORY - task incomplete without these):
  ```
  Scenario: Disabled mode preserves existing config
    Tool: Bash
    Steps: Run `go test ./internal/config` and `remnaguard validate -c configs/remnaguard.example.yaml`.
    Expected: Both commands exit 0; no facade env vars required.
    Evidence: .sisyphus/evidence/task-1-config-disabled.txt

  Scenario: Unsafe actor mapping rejected
    Tool: Bash
    Steps: Run validation against fixture containing `credential_id: rg_leaked.example` or equivalent raw token value.
    Expected: Validation exits non-zero with message mentioning raw token/actor mapping invalid.
    Evidence: .sisyphus/evidence/task-1-config-rejects-raw-token.txt
  ```

  **Commit**: YES | Message: `feat(config): add panel facade configuration` | Files: [`internal/config/*`, `configs/*`, tests]

- [x] 2. Define Remnawave frontend auth compatibility contract

  **What to do**: Create an internal compatibility contract document/test fixture for the minimum Remnawave auth API surface needed by the existing frontend without fork. Pin these endpoints for MVP:
  - `GET /api/auth/status`: returns auth status JSON with Telegram/OAuth provider enabled enough for frontend login page, password/register/passkey disabled, branding present.
- `POST /api/auth/oauth2/authorize`: accepts `{ "provider": "telegram" }`, returns raw HTTP `{ "response": { "authorizationUrl": "https://restricted.example.com/..." } }`; frontend assigns `authorizationUrl` through its hook layer.
- `POST /api/auth/oauth2/callback`: accepts `{ "provider": "telegram", "code": "...", "state": "..." }`, validates the Telegram/OAuth state/code according to Task 4, and returns raw HTTP `{ "response": { "accessToken": "<panel-session-token>" } }`; frontend hook layer exposes `data.accessToken`.
  - Unsupported `POST /api/auth/login`, `POST /api/auth/register`, passkey endpoints: return deterministic compatible feature-disabled error/status.
  Use exact frontend/backend contract references and add fixtures in testdata. If endpoint names differ after local inspection, prefer the Remnawave contract names from `libs/contract/api/routes.ts` and frontend hooks.

  **Must NOT do**: Do not implement OAuth2/passkey/password/register beyond disabled compatibility. Do not invent a frontend-only custom endpoint unless a no-fork route cannot be mimicked.

  **Recommended Agent Profile**:
  - Category: `deep` - Reason: requires precise external contract mapping and test fixtures
  - Skills: [`context7-mcp`] - contract/library-style lookup if needed
  - Omitted: [`frontend-design`] - no UI generation

  **Parallelization**: Can Parallel: YES | Wave 1 | Blocks: Tasks 4, 6, 9, 11 | Blocked By: none

  **References**:
  - External: `https://github.com/remnawave/frontend/blob/main/src/shared/api/hooks/auth/auth.query.hooks.ts` - frontend `useGetAuthStatus`
  - External: `https://github.com/remnawave/frontend/blob/main/src/shared/api/hooks/auth/auth.hooks.ts` - frontend auth mutations storing `data.accessToken`
  - External: `https://github.com/remnawave/frontend/blob/main/src/features/auth/oauth2-login-button/oauth2-login-button.feature.tsx` - Telegram OAuth2 login button behavior
  - External: `https://github.com/remnawave/backend/blob/main/libs/contract/api/routes.ts` - auth route constants
  - External: `https://github.com/remnawave/backend/blob/main/libs/contract/commands/auth/get-status.command.ts` - status response schema
  - External: `https://github.com/remnawave/backend/blob/main/libs/contract/commands/auth/oauth2/authorize.command.ts` - OAuth2 authorize contract
  - External: `https://github.com/remnawave/backend/blob/main/libs/contract/commands/auth/oauth2/callback.command.ts` - OAuth2 callback contract

  **Acceptance Criteria**:
  - [ ] A checked-in test fixture documents exact MVP response for `GET /api/auth/status`.
  - [ ] A checked-in fixture documents raw HTTP success response `{ "response": { "accessToken": "..." } }`.
  - [ ] Unsupported auth endpoint behavior is documented and testable.
  - [ ] Contract notes explicitly state no Remnawave access token, root token, or `rg_...` token is returned.

  **QA Scenarios**:
  ```
  Scenario: Contract fixtures are present
    Tool: Bash
    Steps: Run `go test ./...` after adding contract fixture tests.
    Expected: Tests assert auth status and callback response JSON shape.
    Evidence: .sisyphus/evidence/task-2-auth-contract-tests.txt

  Scenario: Unsupported auth methods are pinned
    Tool: Bash
    Steps: Run tests for password/register/passkey disabled behavior fixtures.
    Expected: Tests prove unsupported endpoints return deterministic feature-disabled responses.
    Evidence: .sisyphus/evidence/task-2-unsupported-auth-contract.txt
  ```

  **Commit**: YES | Message: `test(auth): define panel facade compatibility contract` | Files: [`internal/server/testdata/*`, compatibility tests/docs]

- [x] 3. Implement distinct panel session token design

  **What to do**: Add a session-token component for panel facade mode. Token must be distinct from RemnaGuard raw credentials: use a different prefix or JWT/PASETO-like opaque signed token, with issuer/audience/expiry claims and Telegram actor ID claim. Validate wrong issuer/audience, expiry, malformed token, and disabled facade. Store only actor identity and session metadata; do not include credential ID, scopes, upstream bearer, or raw `rg_...` value in browser token. Session secret comes only from env specified by config.

  **Must NOT do**: Do not reuse `REMNAGUARD_TOKEN_PEPPER` as session signing key. Do not make browser token accepted by existing `rg_...` credential parser. Do not put actor-selected credential/scopes in token.

  **Recommended Agent Profile**:
  - Category: `business-logic` - Reason: auth/session core logic
  - Skills: []
  - Omitted: [`frontend-design`, `playwright`] - backend-only task

  **Parallelization**: Can Parallel: YES | Wave 1 | Blocks: Tasks 4, 7, 9 | Blocked By: Task 1 for final integration

  **References**:
  - Pattern: `internal/auth/auth.go` - existing credential parsing; keep separation
  - Pattern: `internal/server/server.go` - auth flow location
  - Pattern: `internal/audit` or audit sink package - audit context integration if present

  **Acceptance Criteria**:
  - [ ] Unit tests prove issued panel token does not start with `rg_`.
  - [ ] Unit tests prove panel token is rejected by existing RemnaGuard credential verifier.
  - [ ] Unit tests prove expired/wrong-audience/wrong-issuer/malformed tokens are rejected.
  - [ ] Unit tests prove token payload contains actor identity but not mapped credential/scopes/upstream tokens.

  **QA Scenarios**:
  ```
  Scenario: Panel token cannot be used as rg token
    Tool: Bash
    Steps: Run session-token unit tests that issue a token and pass it through existing credential verifier.
    Expected: Credential verifier rejects token; panel validator accepts it only in facade mode.
    Evidence: .sisyphus/evidence/task-3-token-separation.txt

  Scenario: Expired token denied
    Tool: Bash
    Steps: Run unit test with fixed clock issuing expired panel token.
    Expected: Validation fails with 401-class error reason.
    Evidence: .sisyphus/evidence/task-3-expired-token.txt
  ```

  **Commit**: YES | Message: `feat(auth): add panel session tokens` | Files: [`internal/auth/*`, tests]

- [x] 4. Implement Telegram-only auth facade endpoints

  **What to do**: Add handlers enabled only when `panel_facade.enabled` is true. Implement Telegram-only login/callback compatible with the contract from Task 2. The no-fork MVP must mimic Remnawave's OAuth2 flow: `POST /api/auth/oauth2/authorize` returns `{ "response": { "authorizationUrl": "..." } }`; the returned URL lands on a RemnaGuard-controlled Telegram login/callback page/endpoint that validates Telegram auth and carries state; `POST /api/auth/oauth2/callback` returns `{ "response": { "accessToken": "<panel-session-token>" } }`. Validate Telegram login payload using Telegram bot token hash verification and max age. On success, require actor ID exists in YAML mapping, issue panel session token, and return the wrapped response. On invalid Telegram payload, expired auth date, missing mapping, or disabled actor credential, return deterministic 401/403 and audit. Implement `GET /api/auth/status` to show only Telegram-capable auth and disabled password/register/passkey.

  **Must NOT do**: Do not call Remnawave auth for restricted login. Do not auto-provision actors. Do not accept Telegram ID without hash verification. Do not leak whether a specific Telegram ID is mapped beyond generic denied response body.

  **Recommended Agent Profile**:
  - Category: `business-logic` - Reason: login/auth security
  - Skills: []
  - Omitted: [`frontend-design`] - no UI work

  **Parallelization**: Can Parallel: NO | Wave 2 | Blocks: Tasks 6, 7, 8, 9 | Blocked By: Tasks 1, 2, 3

  **References**:
  - External: Telegram Login Widget verification docs: `https://core.telegram.org/widgets/login#checking-authorization`
  - External: `https://github.com/remnawave/backend/blob/main/libs/contract/commands/auth/get-status.command.ts` - status shape
  - External: `https://github.com/remnawave/frontend/blob/main/src/shared/api/hooks/auth/auth.hooks.ts` - frontend expects `data.accessToken`
  - Pattern: `internal/server/server.go` - handler routing pipeline
  - Pattern: `internal/audit` - record auth events without secrets

  **Acceptance Criteria**:
  - [ ] `GET /api/auth/status` returns valid JSON matching Task 2 fixture.
  - [ ] Valid Telegram/OAuth callback for mapped actor returns `200` and exact raw HTTP `{ "response": { "accessToken": "..." } }`.
  - [ ] Returned token does not start with `rg_` and contains no root/upstream token when decoded/inspected by tests.
  - [ ] Invalid hash returns 401 and audit event.
  - [ ] Expired auth date returns 401 and audit event.
  - [ ] Unmapped Telegram actor returns 403 and audit event.

  **QA Scenarios**:
  ```
  Scenario: Mapped Telegram actor logs in
    Tool: Bash
    Steps: Run integration test or curl fixture against local test server with valid Telegram test payload for actor `123456789`.
    Expected: HTTP 200, body exactly contains `response.accessToken`, token prefix is not `rg_`.
    Evidence: .sisyphus/evidence/task-4-telegram-login-success.json

  Scenario: Unmapped Telegram actor denied
    Tool: Bash
    Steps: Run integration test/curl fixture with valid Telegram payload for actor not present in YAML mapping.
    Expected: HTTP 403, no accessToken, audit records mapping miss.
    Evidence: .sisyphus/evidence/task-4-telegram-unmapped-deny.txt
  ```

  **Commit**: YES | Message: `feat(auth): add Telegram panel facade login` | Files: [`internal/server/*`, `internal/auth/*`, tests]

- [x] 5. Resolve actor mapping to existing credentials

  **What to do**: Add mapping resolver: panel session actor ID → config actor mapping → existing RemnaGuard credential/token policy object. Resolver must run server-side per request or via bounded cache. It must re-check disabled/rotated credentials after config reload. It must never read credential IDs/scopes from frontend. Return typed errors for unmapped actor, missing credential, disabled credential, invalid config, and cache miss.

  **Must NOT do**: Do not duplicate scope parsing in actor mapping. Do not allow raw token lookup by actor. Do not make successful login enough to authorize routes; route policy still must run.

  **Recommended Agent Profile**:
  - Category: `business-logic` - Reason: policy integration logic
  - Skills: []
  - Omitted: [`frontend-design`] - backend-only

  **Parallelization**: Can Parallel: YES | Wave 2 | Blocks: Tasks 7, 8, 9 | Blocked By: Task 1

  **References**:
  - Pattern: `internal/config/config.go` - merged config and token credential structures
  - Pattern: `internal/policy/policy.go` - existing scope/policy evaluation
  - Pattern: `cmd/remnaguard token add/rotate/disable` implementation - credential identity lifecycle

  **Acceptance Criteria**:
  - [ ] Unit tests prove mapped actor resolves to existing credential policy.
  - [ ] Unit tests prove unmapped actor denies.
  - [ ] Unit tests prove disabled/missing credential denies.
  - [ ] Config reload test proves mapping changes take effect without stale authorization beyond documented cache TTL.

  **QA Scenarios**:
  ```
  Scenario: Actor mapping resolves existing credential
    Tool: Bash
    Steps: Run unit tests with fixture actor `123456789 -> support-readonly` and credential `support-readonly` scoped to `users:read`.
    Expected: Resolver returns credential/policy; no scopes read from actor mapping.
    Evidence: .sisyphus/evidence/task-5-mapping-resolve.txt

  Scenario: Disabled credential blocks actor
    Tool: Bash
    Steps: Run unit test where actor maps to disabled credential.
    Expected: Resolver returns deny error; route proxy is not invoked.
    Evidence: .sisyphus/evidence/task-5-disabled-credential-deny.txt
  ```

  **Commit**: YES | Message: `feat(policy): map panel actors to credentials` | Files: [`internal/config/*`, `internal/policy/*`, tests]

- [x] 6. Add compatible unsupported-auth behavior

  **What to do**: Implement deterministic behavior for auth endpoints the no-fork frontend may call but MVP does not support. Based on Task 2, return compatible disabled responses for password login/register/passkey and non-Telegram OAuth providers. Ensure `/api/auth/status` advertises only supported Telegram login and disabled/absent unsupported methods so the frontend should not render unsupported controls. If the frontend still calls unsupported endpoints, return 403 or 404 consistently with JSON error shape used by existing RemnaGuard responses.

  **Must NOT do**: Do not implement password/register/passkey/OIDC beyond disabled response. Do not proxy unsupported auth endpoints to Remnawave backend.

  **Recommended Agent Profile**:
  - Category: `business-logic` - Reason: compatibility behavior
  - Skills: []
  - Omitted: [`frontend-design`] - no UI changes

  **Parallelization**: Can Parallel: YES | Wave 2 | Blocks: Tasks 9, 11 | Blocked By: Tasks 2, 4

  **References**:
  - External: `https://github.com/remnawave/backend/blob/main/libs/contract/api/routes.ts` - auth route list
  - External: `https://github.com/remnawave/frontend/blob/main/src/pages/auth/login/login.page.tsx` - login page renders methods from status
  - Pattern: `internal/server/server.go` - JSON error behavior

  **Acceptance Criteria**:
  - [ ] Tests prove `/api/auth/status` does not advertise password/register/passkey as usable.
  - [ ] Tests prove password login/register/passkey endpoint calls cannot obtain accessToken.
  - [ ] Tests prove unsupported endpoints do not call upstream Remnawave backend.

  **QA Scenarios**:
  ```
  Scenario: Password login disabled
    Tool: Bash
    Steps: Run integration test POST `/api/auth/login` with any username/password.
    Expected: Non-2xx feature-disabled response; no accessToken; no upstream call.
    Evidence: .sisyphus/evidence/task-6-password-disabled.txt

  Scenario: Status hides unsupported auth
    Tool: Bash
    Steps: Run curl/test against `GET /api/auth/status`.
    Expected: Response advertises Telegram path only; passkey/password/register disabled or absent per contract.
    Evidence: .sisyphus/evidence/task-6-status-disabled-methods.json
  ```

  **Commit**: YES | Message: `feat(auth): disable unsupported panel facade auth methods` | Files: [`internal/server/*`, tests]

- [x] 7. Integrate panel sessions with existing proxy/policy pipeline

  **What to do**: Modify request handling so facade mode accepts `Authorization: Bearer <panel-session-token>` for normal Remnawave API routes. Flow must be: validate panel session → resolve actor mapping to existing credential → run existing raw request validation/catalog match/version guard → run existing policy/scope decision as if credential authenticated → strip incoming Authorization/forwarded/protected headers → inject upstream root bearer → proxy. Keep existing `Authorization: Bearer rg_...` API-token behavior intact for non-facade clients according to current config/listener behavior. Unknown/uncataloged routes deny by default.

  **Must NOT do**: Do not let panel session bypass catalog/policy. Do not let frontend select credential/scope. Do not follow redirects or relax existing proxy header stripping. Do not proxy `/api/auth/*` to Remnawave in restricted facade mode.

  **Recommended Agent Profile**:
  - Category: `business-logic` - Reason: core proxy and policy integration
  - Skills: []
  - Omitted: [`frontend-design`] - backend-only

  **Parallelization**: Can Parallel: NO | Wave 3 | Blocks: Tasks 8, 9, 10, 11 | Blocked By: Tasks 1, 3, 4, 5

  **References**:
  - Pattern: `internal/server/server.go:173` - request pipeline from prior exploration
  - Pattern: `internal/proxy/proxy.go:88` - header stripping and upstream bearer injection
  - Pattern: `internal/routes/catalog.go` - static Remnawave 2.7.4 catalog
  - Pattern: `internal/policy/policy.go` - existing scope decision
  - README Security Defaults - unknown routes denied and auth isolation

  **Acceptance Criteria**:
  - [ ] Existing tests for raw `rg_...` bearer clients still pass.
  - [ ] Panel session mapped to credential with allowed scope results in upstream request.
  - [ ] Panel session mapped to credential without required scope returns 403 and does not call upstream.
  - [ ] Unknown route returns deny/fail-closed and does not call upstream.
  - [ ] Upstream request receives root bearer, not panel session token and not raw actor credential.

  **QA Scenarios**:
  ```
  Scenario: Allowed cataloged route proxies
    Tool: Bash
    Steps: Run integration test with panel session for actor mapped to `users:read`, request `GET /api/users`.
    Expected: Upstream test server receives request with root bearer; client receives upstream response.
    Evidence: .sisyphus/evidence/task-7-allowed-route-proxy.txt

  Scenario: Denied route blocks before upstream
    Tool: Bash
    Steps: Run integration test with same actor requesting cataloged route requiring missing scope, e.g. system/settings mutation.
    Expected: HTTP 403; upstream test server records zero calls.
    Evidence: .sisyphus/evidence/task-7-denied-no-upstream.txt
  ```

  **Commit**: YES | Message: `feat(proxy): authorize panel sessions through existing policies` | Files: [`internal/server/*`, `internal/proxy/*`, `internal/policy/*`, tests]

- [x] 8. Extend audit and safe error handling for facade mode

  **What to do**: Add audit event fields for panel facade without logging secrets: actor type (`telegram`), actor ID, display name if configured, mapped credential ID, route/method, policy result, deny reason, upstream status, and auth event type. Add consistent JSON errors for invalid session, expired session, unmapped actor, policy deny, unsupported auth method, unknown route, and upstream failure. Ensure errors do not include raw Telegram payload hash, bot token, panel session token, raw `rg_...`, or upstream bearer.

  **Must NOT do**: Do not log request/response bodies. Do not add unbounded metric labels with actor IDs unless existing metrics policy allows bounded/sanitized labels. Do not include secrets in panic/error strings.

  **Recommended Agent Profile**:
  - Category: `business-logic` - Reason: security audit and error semantics
  - Skills: []
  - Omitted: [`frontend-design`] - no UI work

  **Parallelization**: Can Parallel: YES | Wave 3 | Blocks: Tasks 9, 11 | Blocked By: Tasks 4, 5, 7

  **References**:
  - Pattern: audit sink package (`internal/audit` if present) - existing event style
  - README Security Defaults - no request/response bodies, bounded labels
  - Pattern: `internal/server/server.go` - deny/error responses

  **Acceptance Criteria**:
  - [ ] Tests assert login success/failure audit events contain actor ID but no secrets.
  - [ ] Tests assert policy deny audit event contains actor ID, credential ID, route, method, deny reason.
  - [ ] Tests assert invalid token/unmapped actor/unknown route errors contain no raw token values.
  - [ ] Existing audit tests still pass.

  **QA Scenarios**:
  ```
  Scenario: Policy deny audit contains actor and credential
    Tool: Bash
    Steps: Run integration test for denied route with audit sink enabled.
    Expected: Audit record includes actor `telegram:123456789`, credential `support-readonly`, route, method, deny reason; no token material.
    Evidence: .sisyphus/evidence/task-8-policy-deny-audit.json

  Scenario: Invalid session error redacts token
    Tool: Bash
    Steps: Request cataloged route with malformed bearer `Bearer panel_invalid_secret_value`.
    Expected: 401/403 JSON error does not echo token; audit redacts token.
    Evidence: .sisyphus/evidence/task-8-invalid-token-redacted.txt
  ```

  **Commit**: YES | Message: `feat(audit): record panel facade auth decisions` | Files: [`internal/audit/*`, `internal/server/*`, tests]

- [x] 9. Add tests-after integration and contract suite

  **What to do**: Add comprehensive tests-after suite covering facade config, auth status, Telegram validation, session tokens, actor mapping, allowed/denied proxy, unknown routes, unsupported auth methods, audit, and backward compatibility. Use deterministic test Telegram bot token/hash fixtures. Use a local upstream test server to assert exact upstream headers and whether upstream was called. Capture command outputs into evidence during QA.

  **Must NOT do**: Do not rely on live Telegram or live Remnawave in automated tests. Do not require manual browser interaction. Do not use placeholder assertions like “works”.

  **Recommended Agent Profile**:
  - Category: `deep` - Reason: cross-cutting security integration tests
  - Skills: []
  - Omitted: [`playwright`] - no browser automation required for MVP tests unless Task 11 adds smoke UI

  **Parallelization**: Can Parallel: NO | Wave 3 | Blocks: Task 11 | Blocked By: Tasks 2, 3, 4, 5, 6, 7, 8

  **References**:
  - Existing tests under `internal/**` - follow current test style
  - `docs/deployment.md` - proxy/deployment assumptions
  - `internal/proxy/proxy.go` - upstream header assertions

  **Acceptance Criteria**:
  - [ ] `go test ./...` passes.
  - [ ] Coverage includes successful Telegram authorize/callback and wrapped `response.accessToken` shape.
  - [ ] Coverage includes token separation (`accessToken` not `rg_`, panel token rejected by credential verifier).
  - [ ] Coverage includes allowed route upstream root bearer injection.
  - [ ] Coverage includes denied route no-upstream-call.
  - [ ] Coverage includes unmapped actor, invalid Telegram hash, expired session, unknown route.
  - [ ] Coverage includes raw `rg_...` client backward compatibility.

  **QA Scenarios**:
  ```
  Scenario: Full automated suite
    Tool: Bash
    Steps: Run `go test ./...`.
    Expected: Exit 0; tests cover auth facade and existing gateway behavior.
    Evidence: .sisyphus/evidence/task-9-go-test-all.txt

  Scenario: No live external dependency
    Tool: Bash
    Steps: Run tests with network disabled or inspect test setup to ensure local httptest servers/fixtures only.
    Expected: Tests do not contact live Telegram or live Remnawave.
    Evidence: .sisyphus/evidence/task-9-no-live-network.txt
  ```

  **Commit**: YES | Message: `test(panel): cover auth facade policy flow` | Files: [`internal/**/*_test.go`, testdata]

- [x] 10. Add deployment example and operator docs

  **What to do**: Add docs and example config for running restricted Remnawave frontend beside the original full-admin panel. Document topology:
  ```text
  admin.example.com      -> original Remnawave frontend/backend for full admin only
  restricted.example.com -> Remnawave frontend static app
  restricted.example.com/api/* -> remnaguard panel facade
  remnaguard -> original Remnawave backend with server-held root/API bearer
  ```
  Include YAML actor mapping examples, env vars, secret rotation notes, reverse proxy snippets, and unsupported MVP auth methods. State clearly that frontend fork is not required for enforcement, but UI may show controls that result in 403.

  **Must NOT do**: Do not document putting raw `rg_...` or root token into frontend env. Do not imply upstream Remnawave endorses this. Preserve trademark/non-affiliation language.

  **Recommended Agent Profile**:
  - Category: `writing` - Reason: docs/config examples
  - Skills: []
  - Omitted: [`frontend-design`] - no UI work

  **Parallelization**: Can Parallel: YES | Wave 4 | Blocks: Task 11 | Blocked By: Tasks 1, 7

  **References**:
  - `docs/deployment.md` - current deployment docs
  - `configs/remnaguard.example.yaml` - config style
  - README non-affiliation/security disclaimer
  - Docker/compose files in repo - deployment conventions

  **Acceptance Criteria**:
  - [ ] Example config validates with required env vars supplied in test harness.
  - [ ] Docs include explicit secret placement rules.
  - [ ] Docs include route topology and original panel separation.
  - [ ] Docs mention UI 403 behavior and optional future frontend fork for polish only.

  **QA Scenarios**:
  ```
  Scenario: Example config validates
    Tool: Bash
    Steps: Export fake required env vars and run `remnaguard validate -c configs/remnaguard.panel-facade.example.yaml`.
    Expected: Exit 0.
    Evidence: .sisyphus/evidence/task-10-example-config-validate.txt

  Scenario: Docs contain no frontend secret anti-pattern
    Tool: Bash
    Steps: Search added docs/examples for raw token placement guidance and `rg_` examples in frontend env context.
    Expected: No instruction places raw tokens/root bearer into frontend config.
    Evidence: .sisyphus/evidence/task-10-doc-secret-check.txt
  ```

  **Commit**: YES | Message: `docs(panel): document restricted facade deployment` | Files: [`docs/*`, `configs/*`, compose examples if needed]

- [x] 11. Run compatibility smoke and hardening pass

  **What to do**: Perform final compatibility/hardening pass. Use the existing frontend assumptions from Task 2 and server integration tests from Task 9 to verify auth bootstrap, token storage shape, Authorization handling, allowed/denied API behavior, and safe errors. If possible without implementing frontend changes, run a local static frontend or route-level smoke using curl to auth endpoints and representative API routes. Document any limitation as future optional frontend UX polish, not security blocker.

  **Must NOT do**: Do not weaken backend enforcement to make UI smoother. Do not add frontend fork in this task. Do not mark denied UI controls as a security bug if API enforcement is correct.

  **Recommended Agent Profile**:
  - Category: `deep` - Reason: cross-system final QA/hardening
  - Skills: []
  - Omitted: [`frontend-design`] - no UI design; optional Playwright only if local frontend is already available

  **Parallelization**: Can Parallel: NO | Wave 4 | Blocks: Final Verification | Blocked By: Tasks 2, 6, 7, 8, 9, 10

  **References**:
  - Task 2 compatibility fixtures
  - Task 9 integration tests
  - `internal/routes/catalog.go` - route coverage
  - `README.md` Security Defaults

  **Acceptance Criteria**:
  - [ ] `go test ./...` passes after docs/config additions.
  - [ ] Auth status, Telegram login, allowed API, denied API, unknown API, unsupported auth endpoints are all exercised and evidence captured.
  - [ ] No test/evidence shows raw `rg_...`, upstream root bearer, Telegram bot token, or panel session secret in response body/log/audit.
  - [ ] Backward compatibility for existing API-token remnaguard mode is explicitly verified.

  **QA Scenarios**:
  ```
  Scenario: End-to-end restricted facade flow
    Tool: Bash
    Steps: Start test server/integration harness, call status, perform valid Telegram callback, call allowed route, call denied route.
    Expected: Status 200, login 200 with panel token, allowed route proxied, denied route 403 with audit.
    Evidence: .sisyphus/evidence/task-11-e2e-flow.txt

  Scenario: Secret leak scan in outputs
    Tool: Bash
    Steps: Scan test logs/evidence/audit fixture outputs for configured root bearer, Telegram bot token, raw rg token, session secret.
    Expected: No matches.
    Evidence: .sisyphus/evidence/task-11-secret-leak-scan.txt
  ```

  **Commit**: YES | Message: `chore(panel): harden facade compatibility` | Files: [tests/docs/config as needed]

## Final Verification Wave (MANDATORY — after ALL implementation tasks)
> 4 review agents run in PARALLEL. ALL must APPROVE. Present consolidated results to user and get explicit "okay" before completing.
> **Do NOT auto-proceed after verification. Wait for user's explicit approval before marking work complete.**
> **Never mark F1-F4 as checked before getting user's okay.** Rejection or user feedback -> fix -> re-run -> present again -> wait for okay.
- [x] F1. Plan Compliance Audit — oracle
- [x] F2. Code Quality Review — unspecified-high
- [x] F3. Real Manual QA — unspecified-high
- [x] F4. Scope Fidelity Check — deep

## Commit Strategy
- Commit after each completed implementation task using the specified task commit message.
- Do not combine auth/session/proxy/audit changes into one large commit if tasks can be separated cleanly.
- Do not push unless explicitly requested.
- If tests fail after a task, fix before committing that task.

## Success Criteria
- Restricted panel can authenticate via RemnaGuard-owned Telegram login without Remnawave native login.
- Existing Remnawave frontend can bootstrap against RemnaGuard facade without a fork for MVP.
- Browser receives only RemnaGuard panel session token in Remnawave-compatible `{ "response": { "accessToken": "..." } }` raw HTTP shape.
- RemnaGuard maps Telegram actor to existing credential and uses existing scopes/policies for all cataloged API decisions.
- Denied/unknown requests fail closed with audit and no upstream call.
- Original full-admin Remnawave panel remains separate and unaffected.
- Existing RemnaGuard API-token gateway behavior remains compatible.
