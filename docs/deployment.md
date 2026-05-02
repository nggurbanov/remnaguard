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
