# Releases

RemnaGuard releases should include:

- `go test ./...`
- `go test -race ./...`
- short fuzz smoke runs for raw request-target and JSON policy packages:
  - `go test ./internal/httputil -fuzz=Fuzz -fuzztime=10s`
  - `go test ./internal/jsonpolicy -fuzz=Fuzz -fuzztime=10s`
- read-only external contract smoke tests when an operator explicitly provides a target:
  - `REMNAGUARD_CONTRACT_TESTS=1 REMNAGUARD_CONTRACT_BASE_URL=https://example REMNAGUARD_CONTRACT_BEARER=... go test ./internal/contract -run 'TestReadOnly'`
  - add `REMNAGUARD_CONTRACT_ALLOW_PROD=1` only for an explicitly approved production read-only smoke run
- `go vet ./...`
- `golangci-lint run`
- race tests for packages with concurrency-sensitive changes
- route catalog drift checks
- Docker build
- SBOM
- container scan
- local destructive contract test against Remnawave `2.7.4` staging before advertising restricted writes
- checksums
- signed release artifacts or documented signing status

The Docker and GHCR descriptions must include:

> RemnaGuard is not affiliated with, endorsed by, or sponsored by Remnawave.

Do not advertise compatibility with a new Remnawave version until that version has its own static catalog and release-blocking contract tests.

## Public Compatibility Statement

Use this wording for the first public release:

```text
RemnaGuard is a guarded drop-in replacement for documented privileged
Remnawave API access on Remnawave 2.7.4, and a fine-grained policy gateway for
restricted API tokens.

For privileged tokens with remnawave:*, RemnaGuard knows the full documented
OpenAPI surface for Remnawave 2.7.4 and proxies known non-public routes while
still enforcing route catalog matching, version guard, request structural
safety, upstream auth isolation, header stripping, rate limits, and audit.

For restricted tokens, only policy-enforced routes are available. RemnaGuard
does not claim compatibility with undocumented Remnawave behavior or with
Remnawave versions that do not have a complete static catalog and contract
tests.
```
