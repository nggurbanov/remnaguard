# RemnaGuard

> **Public alpha / no security warranty.** This project was fully vibecoded. It has tests, contract checks, and review passes, but it has not had an independent professional security audit. Do not treat it as guaranteed safe for production or high-risk environments. You run it at your own risk.

RemnaGuard is a guarded drop-in replacement for privileged Remnawave API access and a fine-grained policy gateway for restricted API tokens. It is not affiliated with, endorsed by, or sponsored by the Remnawave project or its owners.

RemnaGuard sits between clients and the Remnawave API. Privileged integrations keep documented `/api/...` calls and swap the upstream root token for an `rg_<credential_id>.<secret>` token with `remnawave:*`. Restricted integrations get narrower scopes and route-specific policy enforcement.

## Status

This repository contains the v1 service baseline:

- fail-closed complete static route catalog for Remnawave `2.7.4`;
- raw request-target validation before route matching;
- HMAC-SHA256 credential verification with `REMNAGUARD_TOKEN_PEPPER`;
- token add, rotate, disable, and prune commands with atomic YAML writes, backups, and validation rollback;
- `privileged`, `policy-enforced`, `unsupported`, and `public-subscription` route support levels;
- explicit query allowlists, JSON content enforcement, duplicate-key rejection, body field allowlists, and configured value limits;
- response-side user ownership checks and HWID user preflight checks;
- restricted write/action support behind explicit `write_safety.enable_restricted_writes` plus `single_writer` gates, with per-resource in-memory locks and post-write verification;
- isolated public subscription forwarding, disabled by default, with request/response header allowlists and per-IP limits;
- upstream auth replacement and hop-by-hop/header stripping;
- no redirect following, disabled automatic decompression, HTTPS-by-default upstreams, custom CA, and optional mTLS;
- local `/healthz`, `/readyz`, `/version`, and `/metrics` listener;
- optional pure-Go SQLite audit sink;
- SIGHUP config reload with full validation before swap;
- JSON audit events without request or response bodies.

Write/action routes are privileged by default. Restricted write/action scopes are available only when `write_safety.enable_restricted_writes: true` and `write_safety.single_writer: true` are both configured and should be enabled only after local destructive contracts pass for the target Remnawave version.

## Quick Start

```sh
cp configs/remnaguard.example.yaml remnaguard.yaml
export REMNAWAVE_ROOT_BEARER=...
export REMNAGUARD_TOKEN_PEPPER=change-me-long-random
remnaguard token generate --id restricted-cred --pepper "$REMNAGUARD_TOKEN_PEPPER"
remnaguard validate -c remnaguard.yaml
remnaguard serve -c remnaguard.yaml
```

Store token policies under `tokens.d/*.yaml`. The raw token is printed once by `token generate`; store only the generated HMAC digest in config.

## Compatibility

RemnaGuard advertises compatibility only for explicit static catalogs. The initial catalog is Remnawave `2.7.4`.

By default startup readiness attempts upstream version detection. If detection fails or the version is unsupported, proxied routes fail closed. For isolated environments, set:

```yaml
compatibility:
  remnawave_version: "2.7.4"
  assume_version: "2.7.4"
  allow_version_mismatch: false
```

`allow_version_mismatch` must not be used to treat writes or actions as policy-enforced for restricted tokens.

## Security Defaults

- Unknown, ambiguous, malformed, and unsupported requests are denied.
- Privileged access is not blind proxying: version guard, catalog matching, request structural checks, header stripping, auth isolation, rate limits, and audit still apply.
- Public subscriptions are disabled by default.
- Upstream HTTPS is required unless localhost/private insecure use is explicit.
- Incoming `Authorization`, forwarded, protected auth, and hop-by-hop headers are stripped before upstream proxying.
- Request and response bodies are not logged.
- Metrics use bounded labels only.
- Inbound HTTP/2 is denied by the raw request validator in v1.

Subscription URLs are bearer-like secrets. Do not publish or log them.

## CLI

Implemented:

```text
remnaguard serve -c remnaguard.yaml
remnaguard validate -c remnaguard.yaml
remnaguard routes list
remnaguard routes check-openapi --spec remnawave-openapi.json [--strict]
remnaguard token generate [--id credential-id] [--pepper pepper]
remnaguard token add -c remnaguard.yaml --id token-id --scopes users:read,hwid:read
remnaguard token rotate -c remnaguard.yaml --id token-id
remnaguard token disable -c remnaguard.yaml --id token-id --credential credential-id
remnaguard token prune -c remnaguard.yaml --id token-id
remnaguard policy explain -c remnaguard.yaml --token token-id
remnaguard policy test -c remnaguard.yaml --token token-id --method GET --path /api/users/{uuid}
```

File-editing token commands prefer `tokens.d/<token-id>.yaml`, write files with `0600`, create directories with `0700`, create timestamped backups, and restore the backup if merged config validation fails.

## License

Apache-2.0. See [LICENSE](LICENSE), [NOTICE](NOTICE), and [LEGAL.md](LEGAL.md).

## Release Posture

Release automation is defined in `.goreleaser.yml`. Published container descriptions must repeat the non-affiliation disclaimer and must not use Remnawave logos or visual identity.
