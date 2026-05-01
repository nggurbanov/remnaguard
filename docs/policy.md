# Policy Model

Route support levels:

- `policy-enforced`: scope checks and route-specific safety controls are implemented for the advertised Remnawave version.
- `privileged`: the route is documented and proxied only for broad privileged scopes such as `remnawave:*`.
- `unsupported`: denied.
- `public-subscription`: unauthenticated subscription forwarding, disabled by default and isolated from root upstream auth.

Implemented scopes:

- `remnawave:*`
- `users:read`
- `hwid:read`
- `squads:read`
- `system:read`
- `metadata:read`
- `subscriptions:read`

Legacy singular scopes are accepted for compatibility where already implemented, but new configs should use the plural names above. Reserved or future write scopes must not be accepted until the related routes have release-blocking contract tests.

## Request Policy

Every documented Remnawave `2.7.4` operation is present in the static catalog and has an explicit support level. `policy-enforced` routes reject unknown query parameters and duplicate query parameters. Body-policy routes require `application/json`, reject `Content-Encoding`, reject duplicate JSON object keys, require a top-level object, and reject unknown fields.

Configured token constraints are enforced on user bodies and response-side user reads:

- username prefix;
- internal and external squad allowlists;
- traffic limit maximums and unlimited-traffic denial;
- description length.

Global/list, bulk, infrastructure, token, config, node, host, and settings routes are privileged unless a route-specific restricted policy exists.

## Preflight And Response Gates

Singleton user reads by UUID, username, and Telegram ID validate the returned user object before returning it to the caller. Per-user HWID routes preflight the owning user before forwarding. Squad reads check configured squad allowlists before forwarding.

## Restricted Writes

Restricted write/action routes are disabled by default and stay privileged unless both flags are set:

```yaml
write_safety:
  enable_restricted_writes: true
  single_writer: true
```

When enabled, RemnaGuard uses per-resource in-memory locks, preflight resource checks, request body/resource validation, upstream proxying, and post-write verification. This mode is intended for one RemnaGuard writer process.
