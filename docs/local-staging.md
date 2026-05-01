# Local Remnawave Staging

The destructive contract suite must run against local staging only. It must not use production tokens or production data.

Current local staging convention:

- Remnawave backend `2.7.4`
- app: `http://127.0.0.1:3300`
- metrics: `http://127.0.0.1:3301`
- Postgres: `127.0.0.1:7767`
- files under `.local/remnawave-staging/`

Run the destructive contract once local Remnawave is up and a staging API token exists:

```sh
make contract-local
```

The test creates synthetic `rg-contract-*` users, updates them, exercises selected actions and HWID routes, and deletes its synthetic user during cleanup.

Never point `REMNAGUARD_STAGING_BASE_URL` at production. The test rejects non-local URLs.

The local suite is what gates enabling restricted writes in configuration. Production should still start with restricted writes disabled, then enable them only for carefully scoped tokens after staging passes.
