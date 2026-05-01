# Contributing

RemnaGuard uses Apache-2.0 and requires clean-room contributions.

- Do not copy Remnawave AGPL backend, panel, subscription-page code, DTOs, OpenAPI schemas, documentation prose, examples, or visual assets.
- Keep route catalogs limited to factual method/path/support metadata.
- Add tests for policy, path/query safety, header handling, and compatibility-sensitive behavior.
- Sign off commits with `Signed-off-by: Name <email>` to certify DCO compliance.

Before opening a pull request:

```sh
go test ./...
go vet ./...
golangci-lint run
```
