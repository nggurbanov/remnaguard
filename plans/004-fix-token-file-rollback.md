# Plan 004: Roll back newly created token files after validation failure

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report; do not improvise. When done, update the status row for this plan
> in `plans/README.md` unless a reviewer told you they maintain the index.
>
> **Drift check (run first)**: `git diff --stat 227989b..HEAD -- cmd/remnaguard/main.go README.md`
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding. On a
> mismatch, treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: S
- **Risk**: LOW
- **Depends on**: none
- **Category**: bug
- **Planned at**: commit `227989b`, 2026-06-10

## Why this matters

The README promises token-edit commands use atomic writes, backups, and
validation rollback. Existing files are restored from a timestamped backup
when merged config validation fails, but newly created token files have no
backup and remain on disk after a failed validation. That leaves operators
with a stale invalid file in `tokens.d/`, and the CLI package currently has no
tests to guard this behavior.

## Current state

- `cmd/remnaguard/main.go` contains token subcommands and token-file writing.
- `README.md` documents the rollback guarantee.
- There is currently no `cmd/remnaguard/*_test.go`; coverage for the command package was 0% during audit.

Relevant excerpts:

```go
// cmd/remnaguard/main.go:421
func writeTokenFileWithValidation(path string, doc *tokenDoc, cfgPath string) error {
    if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
        return err
    }
    var backup string
    if _, err := os.Stat(path); err == nil {
        backup = fmt.Sprintf("%s.%s.bak", path, time.Now().UTC().Format("20060102T150405Z"))
        b, err := os.ReadFile(path)
        if err != nil {
            return err
        }
        if err := os.WriteFile(backup, b, 0600); err != nil {
            return err
        }
    }
    // write temp, rename temp to path
    if _, err := config.Load(cfgPath); err != nil {
        if backup != "" {
            _ = os.Rename(backup, path)
        }
        return fmt.Errorf("validation failed after token edit: %w", err)
    }
    return nil
}
```

```markdown
README.md:215
File-editing token commands prefer `tokens.d/<token-id>.yaml`, write files
with `0600`, create directories with `0700`, create timestamped backups, and
restore the backup if merged config validation fails.
```

Repo conventions to match:

- CLI helpers are currently unexported in package `main`; tests can use `package main`.
- Token files are YAML documents shaped as `tokens: [...]`.
- Config loading includes child YAML files listed under `include`.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| CLI tests | `go test ./cmd/remnaguard -count=1` | exit 0 |
| Full tests | `go test ./...` | exit 0 |
| Vet | `go vet ./...` | exit 0 |
| Lint | `golangci-lint run` | exit 0 |

## Scope

**In scope**:

- `cmd/remnaguard/main.go`
- `cmd/remnaguard/main_test.go` (create)
- `README.md` only if a wording tweak is necessary after the fix

**Out of scope**:

- Do not change token format.
- Do not print raw tokens in tests or docs.
- Do not change credential generation, HMAC calculation, or token verification.
- Do not modify config validation semantics in this plan.

## Git workflow

- Branch: `codex/004-fix-token-file-rollback`
- Commit message style: imperative sentence, for example `Roll back new token files on validation failure`.
- Do not push or open a PR unless the operator instructs it.

## Steps

### Step 1: Track whether the target file existed before writing

In `writeTokenFileWithValidation`, track three states:

- Target existed and backup was created.
- Target did not exist before the edit.
- `os.Stat` failed for a reason other than not-exist.

If `os.Stat(path)` returns an unexpected error, return it before writing.

**Verify**: `go test ./cmd/remnaguard -count=1` -> currently exits 0 or reports no tests. Continue to Step 2.

### Step 2: Remove newly created files when validation fails

After `os.Rename(tmpName, path)`, if `config.Load(cfgPath)` fails:

- If `backup != ""`, preserve the existing behavior and rename the backup back to `path`.
- If the file did not exist before this edit, remove `path`.
- Keep the deferred temp-file cleanup.
- Do not remove parent directories; a newly created `tokens.d/` directory may remain.
- Return the existing `validation failed after token edit: ...` error shape.

Be careful not to remove a pre-existing file if backup restore fails. If restore fails, return an error that includes both validation and restore context.

**Verify**: `go test ./cmd/remnaguard -count=1` -> exits 0 or reports no tests.

### Step 3: Add CLI helper tests

Create `cmd/remnaguard/main_test.go` with `package main`. Add tests for:

1. New invalid token file is removed on validation failure.
2. Existing token file is restored on validation failure.
3. Successful write creates a file with mode `0600`.

Use `t.TempDir()`. Create a minimal `remnaguard.yaml` like:

```yaml
upstream:
  base_url: "https://example.test"
  bearer: "root"
include:
  - "tokens.d/*.yaml"
```

Set `REMNAGUARD_TOKEN_PEPPER` in tests to a long fake value. To force validation failure, write a token doc with an unknown scope or another validation error that does not require real network access. Do not print or store real credentials.

**Verify**: `go test ./cmd/remnaguard -run TestWriteTokenFileWithValidation -count=1` -> exits 0 and includes the new tests.

### Step 4: Run standard gates

Run the standard suite.

**Verify**:

- `go test ./...` -> exit 0
- `go vet ./...` -> exit 0
- `golangci-lint run` -> exit 0

## Test plan

- New `cmd/remnaguard/main_test.go` tests for new-file rollback, existing-file rollback, and mode.
- Existing config tests continue to validate token documents.
- Full test suite remains green.

## Done criteria

- [ ] A failed validation after creating a new token file removes that new file.
- [ ] A failed validation after editing an existing token file restores the original file contents.
- [ ] Successful writes still use `0600` file mode.
- [ ] `go test ./cmd/remnaguard -count=1`, `go test ./...`, `go vet ./...`, and `golangci-lint run` all exit 0.
- [ ] No files outside the in-scope list are modified.
- [ ] `plans/README.md` status row updated.

## STOP conditions

Stop and report back if:

- Rollback cannot be implemented without changing token YAML format.
- Test setup requires storing a real token, bearer, or secret.
- Restore from backup fails and there is no clear way to report both errors.
- Any verification command fails twice after a reasonable fix attempt.

## Maintenance notes

Future token-edit commands should call this helper rather than open-coding file writes. Reviewers should check the failure paths as closely as the success path; operator trust in token rotation depends on rollback being boring and predictable.
