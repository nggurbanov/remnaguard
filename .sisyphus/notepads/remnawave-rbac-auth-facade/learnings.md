
## 2026-05-03 - Telegram Login Widget authorization verification

Official doc inspected: https://core.telegram.org/widgets/login#checking-authorization

Task 4 should verify Telegram Login Widget data locally, without live Telegram calls:

- Required payload source: use the fields received from Telegram Login Widget redirect/callback: `id`, `first_name`, optional `last_name`, optional `username`, optional `photo_url`, `auth_date`, and `hash`. Include any additional received non-`hash` fields in the signature input rather than silently dropping them, because Telegram defines the data-check-string as all received fields except `hash`.
- `data_check_string`: remove only `hash`; format each remaining field exactly as `key=<value>` using the received string value; sort fields alphabetically by key; join with LF (`\n`, byte `0x0A`) and no trailing newline. Example shape: `auth_date=<auth_date>\nfirst_name=<first_name>\nid=<id>\nusername=<username>`.
- Secret derivation: compute `SHA256(bot_token)` and use the raw 32-byte digest as the HMAC key. Do not use the hex text of the SHA256 digest as the HMAC key.
- Hash verification: compute `HMAC-SHA256(data_check_string, secret_key)`, hex-encode it lowercase, decode/validate the received `hash` as hex, and compare with constant-time equality (`hmac.Equal` in Go).
- Freshness: Telegram docs require checking `auth_date` as a Unix timestamp to reject outdated data but do not mandate a max age. The official linked sample rejects payloads older than 86400 seconds; this plan's config uses `panel_facade.telegram.auth_max_age` (example `5m`), so Task 4 should enforce the configured max age and reject future/skewed timestamps if outside the accepted window.
- Deterministic test vector guidance: Telegram docs do not publish a complete known-good payload/hash vector. Use generated fixtures with fake bot tokens. Example fake vector: bot token `000000:TEST_TOKEN_DO_NOT_USE_TEST_TOKEN`; payload fields `auth_date=1700000000`, `first_name=Alice`, `id=123456789`, `last_name=Example`, `photo_url=https://example.com/avatar.jpg`, `username=alice_example`; data-check-string exactly `auth_date=1700000000\nfirst_name=Alice\nid=123456789\nlast_name=Example\nphoto_url=https://example.com/avatar.jpg\nusername=alice_example`; expected hash `b18416b843a8b4d148c835be0bf0ec842859233027024c5ffb25c6b6b1f37b11`. Keep all token values fake.
- Common mistakes that could accept forged Telegram IDs: trusting `id` before hash verification; excluding optional signed fields like `photo_url` or `last_name` when present; allowing client-supplied actor/credential/scope fields; using the bot token directly as the HMAC key instead of `SHA256(bot_token)`; using the hex SHA256 string as the key; including `hash` in the data-check-string; sorting by `key=value` strings instead of keys when duplicate/malformed fields are possible; accepting duplicate query/body keys with ambiguous values; using normal string comparison instead of constant-time comparison; omitting `auth_date` max-age; logging raw payload hashes, bot token, or generated panel session secrets.
- Go implementation pattern: parse into a single-value map after rejecting duplicate keys for signed fields; build sorted keys excluding only `hash`; `secret := sha256.Sum256([]byte(botToken))`; `mac := hmac.New(sha256.New, secret[:])`; write the exact UTF-8 data-check-string bytes; compare decoded expected/received hashes with `hmac.Equal`.

## Wave 1 exploration: config/auth/server/policy paths

- `internal/config/config.go:19-169` defines the current YAML schema: top-level `Config` plus `TokenPolicy`, `Credential`, `Constraints`, and duration fields decoded directly by `yaml.v3`. Add `panel_facade` as another top-level config struct here, disabled by default in `Defaults()` (`internal/config/config.go:197-205`).
- `internal/config/config.go:219-381` is the central fail-closed validation path run by `Load()` (`internal/config/config.go:171-194`) and by CLI validation. Existing env-secret validation patterns include public subscription auth env (`internal/config/config.go:285-293`) and Telegram alerts env (`internal/config/config.go:384-424`).
- `internal/config/config.go:325-327` requires `REMNAGUARD_TOKEN_PEPPER` only when `tokens` are configured. Panel browser session tokens should use a separate env/secret and must not reuse this pepper.
- Existing credential model is logical token -> credentials: `TokenPolicy` and `Credential` at `internal/config/config.go:135-147`. Disabled logical tokens and credentials are skipped by `FindCredential()` at `internal/config/config.go:474-485`; `policy.Decide()` also denies disabled tokens at `internal/policy/policy.go:23-26`. Actor mappings for panel facade should reference existing token/credential IDs and validate against this enabled lookup behavior.
- `internal/auth/auth.go:13-45` only handles raw API credentials with `Bearer rg_<credential_id>.<secret>`, HMAC-SHA256 digesting, and verify. Panel session tokens need a separate parser/verifier and must not start with `rg_`.
- `internal/server/server.go:173-293` is the main API gateway pipeline: raw request validation, static catalog match, version guard, query/body checks, public-sub special case, `auth.ParseBearer`, `cfg.FindCredential`, `auth.Verify` with `REMNAGUARD_TOKEN_PEPPER`, per-token limits, `policy.Decide`, body/response policy, then upstream proxy. Panel sessions should resolve to an existing `TokenPolicy`/`Credential` before this policy/proxy path rather than bypassing catalog decisions.
- `internal/proxy/proxy.go:88-127` strips incoming `Authorization` and sets upstream `Bearer <root>` from config for non-public requests. This is the auth isolation point that should remain unchanged for panel session callers.
- Command validation entrypoints: `cmd/remnaguard/main.go:75-123` loads config for `serve` and `validate`; `cmd/remnaguard/main.go:304-338` implements `policy explain/test`; token file mutation commands validate by reloading config after atomic write at `cmd/remnaguard/main.go:421-469`.
- Route catalog already includes Remnawave auth endpoints but treats them as generated privileged routes by default: `internal/routes/catalog.go:112-132` and `internal/routes/catalog.go:227-231`. `routeGroup()` groups auth/passkey routes at `internal/routes/catalog.go:512-525`. Panel facade should override/intercept these only when opt-in enabled.
- Tests to mimic: config validation style in `internal/config/config_test.go:75-182`; auth parser/digest style in `internal/auth/auth_test.go:9-28`; server httptest gateway style and shared `testConfig()` in `internal/server/server_test.go:18-133` and `internal/server/server_test.go:784-799`; route catalog tests in `internal/routes/catalog_test.go:11-87`; command/contract token setup in `internal/contract/remnaguard_proxy_readonly_test.go:15-62`.

## Pipeline exploration for Tasks 5, 7, and 8 - 2026-05-03

- Current protected API flow is centralized in `internal/server/server.go:173-293`: global concurrency, raw request validation, catalog match, version/query/body checks, public subscription handling, bearer parsing, `config.FindCredential`, HMAC verification, per-token limits, `policy.Decide`, request/body/preflight checks, proxy round trip, response policy/filter/post-write verification, response write, and `proxy_allowed` audit.
- Safest integration point for panel session -> credential -> existing policy path is the bearer resolution block at `internal/server/server.go:221-230`: replace/extract it into an authenticator that preserves raw `rg_...` behavior and, only in facade mode, validates a panel session then resolves its actor mapping to the existing `*config.TokenPolicy` and `*config.Credential` used by lines `231-292`. This avoids a second route allowlist or proxy path.
- Existing raw bearer contract is `internal/auth/auth.go:20-34`: only `Authorization: Bearer rg_<credential_id>.<secret>` parses. Credential lookup ignores disabled tokens/credentials in `internal/config/config.go:474-485`, and scopes remain token-owned in `internal/config/config.go:136-147` / known scopes `internal/config/config.go:497-504`.
- Catalog fail-closed behavior lives in `internal/routes/catalog.go:37-42`, default privileged route construction `internal/routes/catalog.go:44-60`, policy-enforced overrides beginning `internal/routes/catalog.go:61-80`, and matching/no-match in `internal/routes/catalog.go:308-318`. Unknown routes deny before auth/proxy at `internal/server/server.go:187-190`.
- Policy decision is already scope-only in `internal/policy/policy.go:23-47`; privileged routes require `remnawave:*`/`privileged:*` via `internal/policy/policy.go:58-60`, while policy-enforced routes allow matching route scopes or privileged scopes. Actor mapping should not duplicate this logic.
- Upstream call isolation lives in `internal/proxy/proxy.go:88-127`: clone headers, `StripHopByHop`, delete inbound `Authorization`, set `Accept-Encoding: identity`, inject upstream root bearer for non-public routes at `internal/proxy/proxy.go:103-107`, and never follow redirects from client setup `internal/proxy/proxy.go:56-59`. Response header stripping is `internal/proxy/proxy.go:143-169`.
- Protected/header stripping helpers are in `internal/httputil/validate.go:51-68` and protected outbound config validation is `internal/config/config.go:522-536`; `Authorization` is intentionally end-to-end for validation helper tests but explicitly removed in proxy before upstream.
- Audit/error behavior is currently simple and non-JSON for denies: `internal/server/server.go:1017-1030` emits `request_denied` through audit and alerts, then `http.Error`. Audit fields/storage are fixed at `internal/audit/audit.go:51-80` (`event`, `route`, `token_id`, `credential_id`, `reason`, `status`, optional `method`/`path`), with no actor fields yet and no audit package tests found.
- Existing tests to extend for upstream-call/no-upstream-call and root bearer injection: `internal/server/server_test.go:68-114` for successful privileged proxy/root bearer; `internal/server/server_test.go:116-133` for denied restricted privileged route with no upstream; `internal/server/server_test.go:453-502` and `internal/server/server_test.go:504-527` for restricted write allow/deny call counts; `internal/server/server_test.go:645-673` for authenticated subscription route root bearer. Add panel-session variants beside these using local `httptest` upstreams.
- Existing tests to extend for protected header stripping: `internal/server/server_test.go:424-451` verifies all `X-Forwarded-*` headers are stripped on authenticated proxy, `internal/server/server_test.go:387-422` verifies public subscription strips unsafe headers, and `internal/httputil/validate_test.go:40-53` verifies helper-level hop-by-hop stripping while preserving `Authorization` until proxy removes it.
- Existing unknown route and catalog tests: `internal/routes/catalog_test.go:11-15` proves no match for unknown method/path; server-level unknown-route no-upstream coverage should be added around `internal/server/server.go:187-190` because current no-upstream assertions mostly cover policy/body denials, not unknown route through `apiHandler`.


## 2026-05-03 - Remnawave auth contract research for Task 2

Remote sources inspected:
- Backend repo `remnawave/backend`, branch `main`, observed HEAD `5daad91eaac4451b2ced5ea1d35461f1581cf273`; auth contract files are under `libs/contract`. The v2.7.4 release commit is `8032a39eae7a83d2a503ee5eab1f6545168178a5`; latest `main` only adds SECURITY after that release.
- Frontend repo `remnawave/frontend`, branch `main`, observed HEAD `180d24607660305b1d44e0861c83698b7904bb08` (`chore: release v2.7.4`).

Backend route constants and command schemas:
- `libs/contract/api/controllers/auth.ts` defines `AUTH_CONTROLLER = "auth"` and auth route segments: `login`, `register`, `status`, `oauth2/tg/callback`, `oauth2/authorize`, `oauth2/callback`, `passkey/authentication/options`, `passkey/authentication/verify`. URL: https://github.com/remnawave/backend/blob/main/libs/contract/api/controllers/auth.ts
- `libs/contract/api/routes.ts` composes REST auth routes under `/api/auth`: `REST_API.AUTH.LOGIN`, `REGISTER`, `GET_STATUS`, `OAUTH2.TELEGRAM_CALLBACK`, `OAUTH2.AUTHORIZE`, `OAUTH2.CALLBACK`, `PASSKEY.GET_AUTHENTICATION_OPTIONS`, `PASSKEY.VERIFY_AUTHENTICATION`. URL: https://github.com/remnawave/backend/blob/main/libs/contract/api/routes.ts
- `GetStatusCommand` uses `GET /api/auth/status` and response wrapper `{ response: { isLoginAllowed: boolean, isRegisterAllowed: boolean, authentication: null | { passkey: { enabled: boolean }, oauth2: { providers: Record<OAUTH2_PROVIDERS, boolean> }, password: { enabled: boolean } }, branding: { title: string | null, logoUrl: string | null } } }`. URL: https://github.com/remnawave/backend/blob/main/libs/contract/commands/auth/get-status.command.ts
- `OAuth2AuthorizeCommand` uses `POST /api/auth/oauth2/authorize`, request `{ provider: OAUTH2_PROVIDERS }`, response `{ response: { authorizationUrl: string | null } }`. URL: https://github.com/remnawave/backend/blob/main/libs/contract/commands/auth/oauth2/authorize.command.ts
- `OAuth2CallbackCommand` uses `POST /api/auth/oauth2/callback`, request `{ provider: OAUTH2_PROVIDERS, code: string, state: string }`, response `{ response: { accessToken: string } }`. URL: https://github.com/remnawave/backend/blob/main/libs/contract/commands/auth/oauth2/callback.command.ts
- `LoginCommand` uses `POST /api/auth/login`, request `{ username: string, password: string }`, response `{ response: { accessToken: string } }`. URL: https://github.com/remnawave/backend/blob/main/libs/contract/commands/auth/login.command.ts
- `RegisterCommand` uses `POST /api/auth/register`, request `{ username: string, password: string }` where password has min length 24 and uppercase/lowercase/number regex, response `{ response: { accessToken: string } }`. URL: https://github.com/remnawave/backend/blob/main/libs/contract/commands/auth/register.command.ts
- Passkey auth uses `GET /api/auth/passkey/authentication/options` with `{ response: unknown }` and `POST /api/auth/passkey/authentication/verify` with request `{ response: unknown }`, response `{ response: { accessToken: string } }`. URLs: https://github.com/remnawave/backend/blob/main/libs/contract/commands/auth/passkey/get-authentication-options.command.ts and https://github.com/remnawave/backend/blob/main/libs/contract/commands/auth/passkey/verify-authentication.command.ts
- `OAUTH2_PROVIDERS` values are `telegram`, `github`, `pocketid`, `yandex`, `keycloak`, `generic`. URL: https://github.com/remnawave/backend/blob/main/libs/contract/constants/oauth2/providers.contants.ts

Backend behavior relevant to disabled/unsupported fixtures:
- `AuthService.getStatus()` returns `authentication: null` when admin count is unavailable, undefined, zero-register state, or invalid multi-admin state; otherwise it advertises booleans from Remnawave settings. For facade fixtures, `isLoginAllowed: true`, `isRegisterAllowed: false`, `authentication.password.enabled: false`, `authentication.passkey.enabled: false`, and only `authentication.oauth2.providers.telegram: true` matches frontend rendering for Telegram-only login.
- `AuthService.login()` fails with `ERRORS.FORBIDDEN` if login is not allowed, authentication is null, or password auth is disabled. `register()` fails with `ERRORS.FORBIDDEN` if `isRegisterAllowed` is false. OAuth2 authorize/callback fail with `ERRORS.FORBIDDEN` when login is not allowed or provider is disabled. Passkey options/verify fail with `ERRORS.FORBIDDEN` when passkeys are disabled or unconfigured.
- `HttpExceptionFilter` renders non-validation forbidden errors as HTTP 403 JSON `{ "timestamp": "...", "path": "<request-url>", "message": "Forbidden", "errorCode": "A068" }`. This is the closest native disabled/unsupported error shape for deterministic fixture behavior. URLs: https://github.com/remnawave/backend/blob/main/src/modules/auth/auth.service.ts and https://github.com/remnawave/backend/blob/main/src/common/exception/http-exception.filter.ts
- There is a route constant for `/api/auth/oauth2/tg/callback`, but no matching command file under `libs/contract/commands/auth/oauth2/`; the no-fork frontend auth hook path uses the generic `/api/auth/oauth2/callback` command with `provider: "telegram"`.

Frontend hook and login behavior:
- `src/shared/api/hooks/auth/auth.query.hooks.ts` calls `GetStatusCommand.TSQ_url` and validates `GetStatusCommand.ResponseSchema`; the query helper unwraps raw HTTP `{ response: ... }` and exposes `data` as the inner `response`. URLs: https://github.com/remnawave/frontend/blob/main/src/shared/api/hooks/auth/auth.query.hooks.ts and https://github.com/remnawave/frontend/blob/main/src/shared/api/tsq-helpers/create-get-query.hook.ts
- `src/shared/api/hooks/auth/auth.hooks.ts` calls `LoginCommand`, `RegisterCommand`, `OAuth2AuthorizeCommand`, `OAuth2CallbackCommand`, and passkey verify. Mutation helper unwraps raw HTTP `{ response: ... }`; success callbacks receive inner data, so login/register/callback store `data.accessToken`, and authorize receives `data.authorizationUrl`. URLs: https://github.com/remnawave/frontend/blob/main/src/shared/api/hooks/auth/auth.hooks.ts and https://github.com/remnawave/frontend/blob/main/src/shared/api/tsq-helpers/create-mutation-hook.ts
- `src/pages/auth/login/login.page.tsx` renders password login only when `authStatus.authentication.password.enabled`; passkey only when `authStatus.authentication.passkey.enabled`; OAuth2 buttons when any provider boolean under `authentication.oauth2.providers` is true. It renders register form when `!isLoginAllowed && isRegisterAllowed`. URL: https://github.com/remnawave/frontend/blob/main/src/pages/auth/login/login.page.tsx
- `src/features/auth/oauth2-login-button/oauth2-login-button.feature.tsx` renders Telegram when `authentication.oauth2.providers.telegram` is true and posts `{ provider: "telegram" }` through `useOAuth2Authorize`; on success it navigates with `window.location.assign(data.authorizationUrl)` if present. URL: https://github.com/remnawave/frontend/blob/main/src/features/auth/oauth2-login-button/oauth2-login-button.feature.tsx
- `src/features/auth/passkey-login-button/passkey-login-button.feature.tsx` returns `null` when `authentication.passkey.enabled` is false; if enabled it fetches passkey options and verifies via the passkey commands. URL: https://github.com/remnawave/frontend/blob/main/src/features/auth/passkey-login-button/passkey-login-button.feature.tsx
- Axios sends `Content-type: application/json`, `Accept: application/json`, `Remnawave-Client-Type` browser header, and `Authorization: Bearer <stored token>` on requests. URL: https://github.com/remnawave/frontend/blob/main/src/shared/api/axios.ts

Fixture implications:
- Status fixture should keep the native wrapper and exact keys: `{ "response": { "isLoginAllowed": true, "isRegisterAllowed": false, "authentication": { "passkey": { "enabled": false }, "oauth2": { "providers": { "telegram": true, "github": false, "pocketid": false, "yandex": false, "keycloak": false, "generic": false } }, "password": { "enabled": false } }, "branding": { "title": <string|null>, "logoUrl": <string|null> } } } }`.
- OAuth2 authorize fixture should accept `{ "provider": "telegram" }` and return `{ "response": { "authorizationUrl": "https://..." } }`; frontend receives `data.authorizationUrl` after unwrapping.
- OAuth2 callback fixture should accept `{ "provider": "telegram", "code": "...", "state": "..." }` and return `{ "response": { "accessToken": "<panel-session-token>" } }`; frontend receives `data.accessToken` after unwrapping. Do not return a Remnawave JWT/root token or `rg_...` token.
- Password login, register, passkey, and non-Telegram OAuth providers can be suppressed by status. If called anyway, a deterministic 403 JSON modeled after Remnawave forbidden (`message: "Forbidden"`, `errorCode: "A068"`, request `path`) is closer to upstream behavior than inventing a success-shaped disabled response.

## 2026-05-03 - Task 1 panel facade config

- Added top-level `panel_facade` config as an opt-in zero/default-disabled feature; disabled mode does not resolve or require panel session or Telegram env vars.
- Enabled validation is fail-closed: session issuer/audience/positive TTL, session secret env, Telegram bot token env, positive Telegram auth max age, at least one Telegram actor, non-empty actor key, stored credential ID only, and enabled credential lookup via `FindCredential()`.
- Actor `credential_id` values are references to configured credential IDs only; values beginning with `rg_` are rejected before lookup so future panel sessions cannot embed raw API tokens in actor mappings.

## 2026-05-03 - Task 2 auth compatibility fixtures

- Added package-local `internal/server/testdata/auth_compat/` fixtures for Telegram-only `/api/auth/status`, OAuth2 authorize/callback success, and deterministic disabled login/register/passkey/non-Telegram OAuth responses.
- Added `internal/server/auth_compat_contract_test.go` to assert exact fixture keys, native `{ "response": ... }` wrapping, Telegram-only provider booleans, Remnawave-style `Forbidden`/`A068` disabled errors, and that browser `accessToken` is a fake panel session token that is not `rg_` or upstream/root material.
- Captured verification in `.sisyphus/evidence/task-2-auth-contract-tests.txt` and `.sisyphus/evidence/task-2-unsupported-auth-contract.txt`.

## 2026-05-03 - Task 3 panel session tokens

- Added `internal/auth` panel session tokens with `panel_` prefix and HMAC-SHA256 over a base64url JSON payload, separate from raw `rg_` credential parsing. Claims are limited to issuer, audience, expiry, issued-at, and Telegram actor ID.
- Validation is fail-closed for disabled facade/session config, missing configured secret env, wrong issuer/audience, expiry, malformed token, bad signature, and empty actor ID. The signing key is read only from `panel_facade.session.secret_env`; `REMNAGUARD_TOKEN_PEPPER` remains raw credential-only.
- Tests inspect decoded payloads to guard against embedding credential IDs, scopes, upstream/root bearers, raw `rg_` tokens, Telegram bot tokens, or session secret material.

## 2026-05-03 - Task 4 Telegram-only facade endpoints

- `internal/server/server.go` now intercepts enabled `panel_facade` `/api/auth/*` routes before the normal version/auth/proxy path, so status/authorize/callback are served locally and do not call upstream Remnawave.
- Telegram callback verification treats `code` as the signed Login Widget query payload, rejects duplicate or malformed signed fields, builds the sorted non-`hash` data-check-string, uses raw `SHA256(bot_token)` as the HMAC key, constant-time compares the hex HMAC, and enforces configured `auth_max_age`.
- Successful callbacks resolve the verified Telegram actor ID to the configured credential at callback time, require that credential to remain enabled, and return only a freshly issued `panel_` browser session token; unmapped and disabled mappings share a generic `panel_auth_denied` response.

## 2026-05-03 - Task 4 state validation fix

- Panel OAuth2 callback now requires the fixed MVP state issued by the authorize response (`telegram-oauth-state`) before Telegram payload verification can issue a panel session. Missing or wrong state denies generically with no submitted state, actor ID, or token material in the response.

## 2026-05-03 - Task 5 actor credential resolver

- Added a per-request `policy.ResolveTelegramActorCredential` resolver that accepts only trusted server-side config plus verified Telegram actor ID, maps through `panel_facade.actors.telegram`, and returns the existing `*config.TokenPolicy` and `*config.Credential` for the normal policy/proxy path.
- Resolver errors are sentinel typed denials for invalid config, unmapped actors, missing credentials, disabled credentials/tokens, and reserved cache miss; no scopes, raw `rg_` tokens, credential IDs, or actor IDs are read from frontend request material.
- Server callback now uses the shared resolver and keeps end-user denial bodies generic; resolver tests cover config reload/mapping changes by resolving against fresh config objects with no stale global cache.

## 2026-05-03 - Task 6 unsupported auth behavior

- Enabled panel facade now returns local Remnawave-style disabled auth JSON (`path`, `message: Forbidden`, `errorCode: A068`) for password login, register, passkey auth, non-Telegram OAuth, and other unsupported `/api/auth/*` calls instead of generic text denials.
- Server tests assert unsupported auth responses match Task 2 fixtures, contain no `accessToken`, and keep upstream call count at zero while preserving Telegram authorize/callback success.

## 2026-05-03 - Task 7 panel sessions in proxy pipeline

- The server now resolves raw `rg_...` credentials and enabled panel sessions through one request credential helper before per-token limits and `policy.Decide`; the raw path still uses `auth.ParseBearer`, `cfg.FindCredential`, and `auth.Verify` with `REMNAGUARD_TOKEN_PEPPER` unchanged.
- Panel session requests validate only `panel_` bearer tokens with `auth.ValidatePanelSession`, resolve the verified Telegram actor ID through `policy.ResolveTelegramActorCredential`, then reuse the existing route catalog, version/query/body checks, rate limits, policy, proxy, response filtering, post-write verification, and audit path.
- Integration tests cover allowed panel session proxying with upstream root bearer/header stripping, missing-scope denial with zero upstream calls, unknown-route fail-closed with zero upstream calls, and raw `rg_...` compatibility while facade mode is enabled.

## 2026-05-03 - Task 8 facade audit and safe errors

- Panel facade audit now uses explicit optional fields for Telegram actor type/id/display name, mapped credential ID, auth event type, request method/path, and upstream status without logging tokens, request bodies, Telegram hashes, bot/session secrets, or upstream bearer material.
- Panel JSON denials are selected from request-scoped panel context or local auth routes, preserving raw non-panel `rg_...` text-denial behavior while making invalid panel sessions, unmapped actors, policy denies, unknown routes, and upstream failures safe and consistent.
- Server tests capture audit output through the audit logger test output hook and assert both positive actor fields and redaction for malformed `Bearer panel_invalid_secret_value`, unmapped actor sessions, and unknown routes.

## 2026-05-03 - Task 9 integration and contract test suite

- Gap audit confirmed Tasks 1-8 already covered facade config validation, auth contract fixtures, Telegram callback validation, actor mapping, proxy allow/deny behavior, unknown routes, unsupported auth methods, audit redaction, and raw `rg_...` compatibility; Task 9 tightened only non-duplicative assertions.
- Added checks that returned browser `response.accessToken` is an exact wrapped panel-session shape, validates through the panel session verifier, never parses/verifies as raw `rg_...`, and expired panel sessions fail before upstream.
- No-live-network evidence is captured by local `httptest` server/request usage, zero-upstream-call assertions for denials/auth facade routes, deterministic fake Telegram token fixtures, and local `testdata/auth_compat` fixture reads.

## 2026-05-03 - Task 10 deployment example and operator docs

- Added `configs/remnaguard.panel-facade.example.yaml` as a complete, safe example with fake env var names, a sample token/credential, and a Telegram actor mapping referencing the stored credential ID.
- Updated `docs/deployment.md` with a Restricted Panel Facade section covering topology, required environment variables, actor mapping rules, reverse proxy routing, unsupported auth methods, expected UI 403 behavior, and secret placement/rotation notes.
- Validation passes when fake required env vars are supplied: `REMNAWAVE_ROOT_BEARER`, `REMNAGUARD_TOKEN_PEPPER`, `PANEL_FACADE_SESSION_SECRET`, `PANEL_FACADE_TELEGRAM_BOT_TOKEN`.
- Anti-pattern scan confirms docs and example configs never instruct placing raw `rg_...`, upstream root bearer, Telegram bot token, panel session secret, or session signing key into frontend/browser environment.
- Evidence captured in `.sisyphus/evidence/task-10-example-config-validation.txt`, `task-10-secret-anti-pattern-scan.txt`, and `task-10-test-suite-status.txt`.

## 2026-05-03 - Task 11 compatibility smoke and hardening

- Consolidated route-level facade smoke can rely on existing local `httptest` tests: status/authorize no-proxy, Telegram callback issuing `panel_` access token, allowed panel proxy path, denied no-upstream, unknown no-upstream, unsupported auth 403/no-upstream, safe error redaction, and raw `rg_` compatibility.
- Task 11 evidence is captured in `.sisyphus/evidence/task-11-e2e-flow.txt` and `.sisyphus/evidence/task-11-secret-leak-scan.txt`; full `go test ./...` and example config validation are included in the smoke evidence.
- Secret hardening found older validation evidence containing fake env values; those were redacted to placeholders before the final evidence/audit/docs/config scan passed.

## 2026-05-03 - Final-wave OAuth handoff fix

- The panel facade now intercepts `GET /api/auth/oauth2/callback` before normal catalog matching when `panel_facade` is enabled, so the authorize URL no longer lands on an unknown/POST-only API route.
- The GET callback bridge converts Telegram Login Widget signed query fields into the no-fork Remnawave frontend callback route `/oauth2/callback/telegram?code=<signed-payload>&state=telegram-oauth-state`; the existing frontend then posts the raw `{ provider, code, state }` callback command and receives the normal wrapped `panel_` session token.
- Regression coverage starts from `POST /api/auth/oauth2/authorize`, exercises the returned URL with deterministic signed Telegram payload query fields as a browser GET, follows the bridge contract into `POST /api/auth/oauth2/callback`, and verifies a valid panel session for actor `123456789` without live Telegram or Remnawave calls.
