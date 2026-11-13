# goraz example: an orders API that keeps every secret in goraz

A small but complete Go service that needs real secrets, and keeps all of them in [goraz](https://github.com/mtnaskari/goraz):

| Secret | Used for | Rotation |
|---|---|---|
| `orders/db/password` | The Postgres password | New connections use the new password, no restart |
| `orders/jwt/current`, `orders/jwt/previous` | Signing 15-minute session tokens | Old sessions keep working until they expire |
| `orders/payments/webhook-secret` (and `-previous`) | Verifying signed payment notifications | Both secrets are accepted while the provider switches |
| `orders/telegram/bot-token` | Notifying operators through a Telegram bot | Picked up on the next reload |
| API keys issued with `goraz token issue` | Clients exchanging a key for a session | Revoke or rotate with overlap |

None of these is in an environment variable, an image or a config file. The service reads one encrypted file that holds only the `orders/` items, and its key arrives as a Docker secret.

## How it fits together

```
operator machine                                container (read-only, no network to anything but Postgres)
───────────────                                 ──────────────────────────────────────────────────────────
.operator/operator.goraz  ── goraz service sync ──▶ /etc/orders/orders.goraz   (encrypted, reloaded every 30 s)
                          ── goraz service create ─▶ /run/secrets/goraz-key    (Docker secret)
```

- `internal/secrets` wraps a `service.Client`, the only place secrets are read. Every read writes an audit event to stdout.
- `internal/store` reads the database password from goraz each time the pool opens a connection.
- `internal/auth` signs session tokens with the current key and also accepts the previous one.
- `internal/webhook` verifies `Payment-Signature: t=…,v1=…` with HMAC-SHA256 and a 5-minute window.
- `internal/notify` sends to Telegram without ever putting the token in a log or an error.

## Run it

You need Go 1.26.11 or later, Docker and `openssl`. Postgres listens on `127.0.0.1:55432` and the API on `127.0.0.1:8088`.

```bash
scripts/bootstrap.sh
```

```bash
docker compose up -d --build
```

```bash
scripts/smoke.sh
```

`bootstrap.sh` creates an operator vault in `.operator/`, generates every secret, writes the service file to `deploy/vault/orders.goraz` and its key to `deploy/secrets/goraz-key`, and issues a client API key into `.operator/api-key`. For this example the operator passphrase is kept in `.operator/passphrase`. A real operator would type it.

`smoke.sh` runs the whole flow against the stack: API key to session, an order, a signed webhook, then every rotation below, and finally checks that no secret reached the logs.

## Use the API

```bash
TOKEN=$(curl -s -X POST -H "Authorization: Bearer $(cat .operator/api-key)" localhost:8088/v1/session | jq -r .token)
curl -s -X POST -H "Authorization: Bearer $TOKEN" -d '{"customer":"Sara","amount_cents":125000}' localhost:8088/v1/orders
curl -s -H "Authorization: Bearer $TOKEN" localhost:8088/v1/orders
```

## Rotate secrets

```bash
scripts/rotate.sh jwt        # then, after 15 minutes: scripts/rotate.sh jwt-done
scripts/rotate.sh webhook    # give the provider the new secret, then: scripts/rotate.sh webhook-done
scripts/rotate.sh db
scripts/rotate.sh key        # after a leak of the service key itself
```

The first three need no restart: the API reloads the service file within 30 seconds. Rotating the service key does, because Docker mounts a secret file by inode, so the container keeps seeing the old file.

## Things this example gets right, and why

- **The service file is mounted as a directory.** A single-file bind mount keeps the old inode after goraz replaces the file atomically, so the container would never see an update.
- **The key file is owned by the service's user.** File-backed Compose secrets keep their host owner and mode, so the container runs with your user and group IDs. goraz refuses a key file others can read.
- **Reads fail closed.** If reloads fail for 15 minutes, or the file passes its 30-day `--valid-for` window, requests get 503 instead of being served with secrets that can't be trusted.
- **The database URL holds no password.** `store.Open` refuses one.
- **Only HS256 is accepted for sessions**, so a token can't pick `none` or another algorithm.

## Tests

```bash
go test ./...
```

Unit tests build a real goraz service file in a temporary folder, rather than mocking goraz. The Postgres test runs against the compose database:

```bash
ORDERS_TEST_DB='postgres://orders@127.0.0.1:55432/orders?sslmode=disable' \
ORDERS_TEST_DB_PASSWORD="$(cat deploy/secrets/db-password)" \
go test -tags integration ./internal/store
```

## Clean up

```bash
docker compose down -v
```

```bash
rm -rf .operator deploy bin .env
```
