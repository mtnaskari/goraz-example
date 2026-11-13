#!/usr/bin/env bash
# Rotates one secret without restarting the service. The running API reloads the
# service file within 30 seconds.
#
#   scripts/rotate.sh jwt       new signing key; tokens signed with the old one keep
#                               working until they expire
#   scripts/rotate.sh webhook   new webhook secret; the old one is still accepted, so
#                               update the provider, then run "webhook-done"
#   scripts/rotate.sh webhook-done
#   scripts/rotate.sh db        new database password; new connections use it
#   scripts/rotate.sh key       new key for the service file itself (after a leak)
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

case "${1:-}" in
  jwt)
    # The old key becomes "previous", so sessions it signed stay valid.
    g read goraz://orders/jwt/current | put orders/jwt/previous
    "$GORAZ" generate --length 48 | put orders/jwt/current
    sync_service
    echo "Rotated. Run 'scripts/rotate.sh jwt-done' after 15 minutes, when old sessions have expired."
    ;;
  jwt-done)
    g rm orders/jwt/previous
    sync_service
    ;;
  webhook)
    g read goraz://orders/payments/webhook-secret | put orders/payments/webhook-secret-previous
    "$GORAZ" generate --length 40 | put orders/payments/webhook-secret
    sync_service
    echo "Rotated. Give the provider the new secret, then run 'scripts/rotate.sh webhook-done'."
    echo "The new secret is not printed: read it with  bin/goraz read goraz://orders/payments/webhook-secret"
    ;;
  webhook-done)
    g rm orders/payments/webhook-secret-previous
    sync_service
    ;;
  db)
    new="$("$GORAZ" generate --length 32)"
    # The new password goes to Postgres on stdin, so it never appears in a process list.
    printf "ALTER ROLE orders PASSWORD '%s';\n" "$new" |
      (cd "$ROOT" && docker compose exec -T db psql -q -v ON_ERROR_STOP=1 -U orders -d orders)
    printf '%s' "$new" | put orders/db/password
    unset new
    sync_service
    write_db_password
    echo "Rotated. Existing connections keep working; new ones use the new password."
    ;;
  key)
    # Writes the new key as a second line, so the service can open the new file
    # while it still holds the old key.
    g service rotate orders --out "$ROOT/deploy/vault/orders.goraz" --key-out "$ROOT/deploy/secrets/goraz-key"
    chmod 0644 "$ROOT/deploy/vault/orders.goraz"
    echo "Rotated. Restart the api container so it reads the new key file:"
    echo "  docker compose up -d --force-recreate api"
    echo "Then remove the first line of deploy/secrets/goraz-key. Issued API keys stop working: issue new ones."
    ;;
  *)
    sed -n '2,13p' "$0"
    exit 2
    ;;
esac
