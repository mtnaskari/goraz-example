#!/usr/bin/env bash
# Creates the operator vault, generates every secret the service needs, and writes
# the service file and its key into deploy/. Run it once. It refuses to overwrite.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

if [ -e "$GORAZ_VAULT" ]; then
  echo "An operator vault already exists in .operator/. Remove .operator/ to start over." >&2
  exit 1
fi

build_goraz
mkdir -p "$ROOT/.operator" "$ROOT/deploy/secrets"
chmod 0700 "$ROOT/.operator" "$ROOT/deploy/secrets"

umask 077
"$GORAZ" generate --words 7 --separator ' ' > "$PASSFILE"
echo "== Creating the operator vault"
g init --kdf standard | grep -v '^GORAZ-RC-' || true
echo "   (the recovery code was not printed; in a real setup, store it safely)"

echo "== Generating secrets"
"$GORAZ" generate --length 32 | put orders/db/password
"$GORAZ" generate --length 48 | put orders/jwt/current
"$GORAZ" generate --length 40 | put orders/payments/webhook-secret
if [ -n "${TELEGRAM_BOT_TOKEN_FILE:-}" ]; then
  put orders/telegram/bot-token < "$TELEGRAM_BOT_TOKEN_FILE"
fi

echo "== Creating the service file"
g service create orders --prefix orders --valid-for 720h \
  --out "$ROOT/deploy/vault/orders.goraz" --key-out "$ROOT/deploy/secrets/goraz-key"
chmod 0644 "$ROOT/deploy/vault/orders.goraz"
chmod 0400 "$ROOT/deploy/secrets/goraz-key"
write_db_password

echo "== Issuing an API key for a client"
g token issue --service orders --name billing-worker \
  --scope orders --scope orders:read --scope orders:write --ttl 720h > "$ROOT/.operator/api-key"
g service sync orders --out "$ROOT/deploy/vault/orders.goraz" 2>/dev/null
chmod 0644 "$ROOT/deploy/vault/orders.goraz"

printf 'UID=%s\nGID=%s\n' "$(id -u)" "$(id -g)" > "$ROOT/.env"

cat <<EOF

Done.
  deploy/vault/orders.goraz    the encrypted service file (safe to commit)
  deploy/secrets/goraz-key     its key: deliver it as a secret, never commit it
  .operator/api-key            a client API key, shown nowhere else

Next: docker compose up --build
EOF
