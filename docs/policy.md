# Policy Model

Route support levels:

- `policy-enforced`: scope checks and route-specific safety controls are implemented for the advertised Remnawave version.
- `privileged`: the route is documented and proxied only for broad privileged scopes such as `remnawave:*`.
- `unsupported`: denied.
- `public-subscription`: unauthenticated subscription forwarding, disabled by default and isolated from root upstream auth.

Implemented scopes:

- `remnawave:*`
- `users:read`
- `users:create`
- `users:update`
- `users:action`
- `hwid:read`
- `hwid:write`
- `squads:read`
- `system:read`
- `metadata:read`
- `subscriptions:read`
- `subscription-pages:read`
- `subscription-pages:write`

Legacy singular scopes are accepted for compatibility where already implemented, but new configs should use the plural names above. Future write scopes must not be accepted until the related routes have release-blocking contract tests.

## Request Policy

Every documented Remnawave `2.7.4` operation is present in the static catalog and has an explicit support level. `policy-enforced` routes reject unknown query parameters and duplicate query parameters. Body-policy routes require `application/json`, reject `Content-Encoding`, reject duplicate JSON object keys, require a top-level object, and reject unknown fields.

Configured token constraints are enforced on user bodies and response-side user reads:

- username prefix;
- username suffix, substring, and regex;
- email substring and domain allowlists;
- Telegram ID ranges;
- internal and external squad allowlists;
- subscription page config allowlists;
- traffic limit maximums and unlimited-traffic denial;
- description length.
- per-route request body field allowlists.

Global, bulk, infrastructure, token, config, node, host, and settings routes are privileged unless a route-specific restricted policy exists. User and squad list routes are policy-enforced only with response filtering.

## Preflight And Response Gates

Singleton user reads by UUID, username, and Telegram ID validate the returned user object before returning it to the caller. Per-user HWID routes preflight the owning user before forwarding. Squad reads check configured squad allowlists before forwarding.

`GET /api/users`, `GET /api/internal-squads`, and `GET /api/external-squads` filter returned arrays/envelopes to objects allowed by token constraints. Count-style metadata is rewritten to the visible object count so hidden object totals are not exposed as-is.

## Restricted Writes

Restricted write/action routes are disabled by default and stay privileged unless both flags are set:

```yaml
write_safety:
  enable_restricted_writes: true
  single_writer: true
```

When enabled, RemnaGuard uses per-resource in-memory locks, preflight resource checks, request body/resource validation, upstream proxying, and post-write verification. This mode is intended for one RemnaGuard writer process.

Restricted write support covers:

- `POST /api/users` with pre-upstream username, squad, subscription page config, traffic, description, email, Telegram, and field constraints plus post-write ownership verification;
- `PATCH /api/users` with existing-user ownership preflight, body constraints, and post-write verification;
- selected user actions: disable, enable, reset traffic, revoke;
- HWID create/delete/delete-all with user ownership preflight and `hwid:write`.

Bulk user changes, squad writes, subscription page writes, node/host/infrastructure writes, token management, and admin management stay privileged.
