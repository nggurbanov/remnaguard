# Production Contract Smoke Tests

Production targets must be treated as live customer systems. The included external contract smoke is read-only, disabled by default, and intended to validate the privileged drop-in path without mutating customer data.

Required environment:

```sh
export REMNAGUARD_CONTRACT_TESTS=1
export REMNAGUARD_CONTRACT_BASE_URL=https://remnawave.example.com
export REMNAGUARD_CONTRACT_BEARER=...
```

For non-local targets, set this additional guard only after confirming that read-only probes are acceptable:

```sh
export REMNAGUARD_CONTRACT_ALLOW_PROD=1
```

Run:

```sh
go test ./internal/contract -run 'TestReadOnly'
```

Do not commit tokens, `.env` files, captured responses, subscription URLs, user identifiers, or production request bodies.

Current read-only coverage probes representative documented `GET` routes across system metadata/stats, users, nodes, hosts, config profiles, squads, subscription settings/templates/page configs, tokens, and HWID device listing. It accepts any non-5xx upstream status because production policy/data may legitimately return `401`, `403`, or `404` for some read-only endpoints.

Destructive tests are intentionally separate. They require a local staging target and refuse non-local URLs.
