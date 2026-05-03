# Deployment

RemnaGuard is not affiliated with, endorsed by, or sponsored by Remnawave.

Expose only the API listener publicly. Keep the local listener on `127.0.0.1` unless you explicitly protect it.

## Caddy

Preserve the raw URI and do not rewrite or decode `/api` paths before forwarding.

```caddyfile
api.example.com {
  reverse_proxy 127.0.0.1:8080
}
```

Keep `/healthz`, `/readyz`, `/version`, and `/metrics` on the local listener.

## Telegram Deny Alerts

RemnaGuard can send Telegram notifications for `request_denied` audit events:

```yaml
alerts:
  enabled: true
  telegram:
    enabled: true
    bot_token_env: "REMNAGUARD_ALERTS_TELEGRAM_TOKEN"
    chat_id_env: "REMNAGUARD_ALERTS_TELEGRAM_CHAT_ID"
    cooldown: 5m
    queue_size: 100
    timeout: 5s
```

Store the bot token and chat id in environment variables, not in config files.
Alerts are sent asynchronously and are best-effort; Telegram failures do not
block proxy traffic or affect readiness. Alert messages include only token id,
route, deny reason, status, count, and timestamps.

## Nginx

```nginx
location /api/ {
  proxy_pass http://127.0.0.1:8080$request_uri;
  proxy_set_header Host $host;
  proxy_http_version 1.1;
}
```

Do not add path rewrites, URI decoding, method override headers, or public routes to the local listener.

## Restricted Panel Facade

The panel facade is opt-in and disabled by default. When enabled, it provides a restricted browser login path for the Remnawave panel using Telegram OAuth only. It is not a replacement for the full admin panel. It does not require forking the Remnawave frontend.

### Topology

```
admin.example.com          -> original Remnawave frontend and backend
restricted.example.com     -> Remnawave frontend static app (unchanged)
restricted.example.com/api/* -> RemnaGuard panel facade
RemnaGuard                 -> original Remnawave backend with server-held root/API bearer
```

The facade intercepts `/api/auth/*` locally. All other `/api/*` requests from the restricted panel are proxied through the normal RemnaGuard catalog, policy, and audit path to the upstream Remnawave backend.

### Required Environment Variables

When `panel_facade.enabled` is true, the following environment variables must be set on the RemnaGuard server process. Do not place these values in browser storage, frontend environment variables, or public config.

- `REMNAWAVE_ROOT_BEARER` — the upstream API bearer RemnaGuard uses to call the original Remnawave backend.
- `REMNAGUARD_TOKEN_PEPPER` — the secret used to verify raw `rg_...` API tokens.
- `PANEL_FACADE_SESSION_SECRET` — the signing key for browser session tokens issued by the facade.
- `PANEL_FACADE_TELEGRAM_CLIENT_ID` — Telegram OAuth client ID used for the restricted panel login flow.
- `PANEL_FACADE_TELEGRAM_CLIENT_SECRET` — Telegram OAuth client secret used for the restricted panel login flow.

Use separate secrets for each role. Rotate them independently. The session secret and Telegram OAuth credentials must not be reused as the token pepper or upstream bearer.

### Actor Mapping

Actor mappings connect verified Telegram IDs to existing stored RemnaGuard credentials. The `credential_id` in an actor mapping must reference a credential already defined under `tokens`. Raw `rg_...` values are rejected.

Example:
```yaml
tokens:
  - id: panel-operator
    scopes:
      - users:read
      - subscriptions:read
    credentials:
      - id: panel-operator-credential
        hmac_sha256: "replace-with-remnaguard-token-generate-digest"

panel_facade:
  enabled: true
  session:
    issuer: "remnaguard-panel"
    audience: "remnaguard-panel"
    token_ttl: 24h
    secret_env: "PANEL_FACADE_SESSION_SECRET"
  telegram:
    client_id_env: "PANEL_FACADE_TELEGRAM_CLIENT_ID"
    client_secret_env: "PANEL_FACADE_TELEGRAM_CLIENT_SECRET"
    frontend_domain: "restricted.example.com"
    auth_url: "https://oauth.telegram.org/auth"
    token_url: "https://oauth.telegram.org/token"
    auth_max_age: 5m
  actors:
    telegram:
      "123456789":
        credential_id: "panel-operator-credential"
        display_name: "Example Operator"
```

### Reverse Proxy Routing

Route `/api/*` from the restricted panel domain to the RemnaGuard API listener. Route the admin panel domain directly to the original Remnawave backend. Do not mix the two domains on the same upstream path.

Nginx example for the restricted panel:
```nginx
server {
  listen 443 ssl;
  server_name restricted.example.com;

  location / {
    # Remnawave frontend static app
    root /var/www/remnawave-panel;
    try_files $uri $uri/ /index.html;
  }

  location /api/ {
    proxy_pass http://127.0.0.1:8080$request_uri;
    proxy_set_header Host $host;
    proxy_http_version 1.1;
  }
}
```

### Unsupported Authentication Methods

The panel facade supports only Telegram OAuth in the current release. Password login, registration, passkey authentication, and non-Telegram OAuth providers are disabled. Requests to these endpoints return a Remnawave-style 403 JSON response.

### Expected UI Behavior

Because the facade does not fork the Remnawave frontend, the unchanged UI may still render controls for disabled features. When a user tries to use them, the backend returns 403 and the UI shows an error. This is expected. A future frontend fork could hide disabled controls for a smoother experience, but it is not required for enforcement.

### Secret Placement and Rotation

- Store all secrets in environment variables or a secrets manager, never in YAML files.
- The browser receives only a `panel_` session token after successful Telegram login. It never receives raw `rg_...` tokens, the upstream root bearer, Telegram OAuth credentials, or the session signing secret.
- Rotate the session secret by changing the environment variable and restarting RemnaGuard. Existing browser sessions will expire naturally.
- Rotate the Telegram OAuth client secret, then update the environment variable and restart.

### Example Config

A complete example is available at `configs/remnaguard.panel-facade.example.yaml`.
## systemd

```ini
[Service]
ExecStart=/usr/local/bin/remnaguard serve -c /etc/remnaguard/remnaguard.yaml
Environment=REMNAWAVE_ROOT_BEARER=replace
Environment=REMNAGUARD_TOKEN_PEPPER=replace
Restart=on-failure
User=remnaguard
```

Send `SIGHUP` to reload config. Invalid reloads are rejected and the old config remains active.

## Upstream TLS

HTTPS upstreams are required by default. Local/private HTTP requires `upstream.allow_insecure_http: true`. Custom CAs and mTLS can be configured:

```yaml
upstream:
  custom_ca_file: /etc/remnaguard/ca.pem
  mtls_cert_file: /etc/remnaguard/client.crt
  mtls_key_file: /etc/remnaguard/client.key
```

Automatic redirect following and automatic decompression are disabled.
