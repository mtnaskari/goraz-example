#!/usr/bin/env bash
# Exercises the running stack end to end: API key to session, orders, a signed
# webhook, and each rotation without restarting the API.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
API="${API:-http://127.0.0.1:8088}"

fail() { echo "FAIL: $*" >&2; exit 1; }
json() { python3 -I -c "import json,sys; print(json.load(sys.stdin)$1)"; }

session() {
  curl -fsS -X POST -H "Authorization: Bearer $(cat "$ROOT/.operator/api-key")" "$API/v1/session" | json "['token']"
}

webhook() { # order id, secret name
  local body ts sig
  body="{\"order_id\":$1}"
  ts="$(date +%s)"
  sig="$(printf '%s.%s' "$ts" "$body" | openssl dgst -sha256 -hmac "$(g read "goraz://$2")" | awk '{print $NF}')"
  curl -sS -o /dev/null -w '%{http_code}' -X POST -H "Payment-Signature: t=$ts,v1=$sig" -d "$body" "$API/v1/webhooks/payments"
}

wait_reload() { # waits until the API reports a newer secrets generation
  local before="$1" now
  for _ in $(seq 1 40); do
    now="$(curl -fsS "$API/healthz" | json "['secrets_generation']")"
    [ "$now" -gt "$before" ] && return 0
    sleep 1
  done
  fail "the API didn't reload the secrets file"
}

gen() { curl -fsS "$API/healthz" | json "['secrets_generation']"; }

echo "== health";  curl -fsS "$API/healthz"; echo
TOKEN="$(session)" || fail "session"
echo "== create an order"
ID="$(curl -fsS -X POST -H "Authorization: Bearer $TOKEN" -d '{"customer":"Sara","amount_cents":125000}' "$API/v1/orders" | json "['id']")"
echo "   order $ID"
[ "$(webhook "$ID" orders/payments/webhook-secret)" = 200 ] || fail "signed webhook"
[ "$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H 'Payment-Signature: t=1,v1=00' -d '{}' "$API/v1/webhooks/payments")" = 401 ] || fail "unsigned webhook accepted"
STATUS="$(curl -fsS -H "Authorization: Bearer $TOKEN" "$API/v1/orders" | json "['orders'][0]['status']")"
[ "$STATUS" = paid ] || fail "order status $STATUS"
echo "   paid"

echo "== rotate the JWT key"
G="$(gen)"; bash "$ROOT/scripts/rotate.sh" jwt >/dev/null; wait_reload "$G"
curl -fsS -H "Authorization: Bearer $TOKEN" "$API/v1/orders" >/dev/null || fail "an old session stopped working during the overlap"
NEW="$(session)"; curl -fsS -H "Authorization: Bearer $NEW" "$API/v1/orders" >/dev/null || fail "new session"
G="$(gen)"; bash "$ROOT/scripts/rotate.sh" jwt-done >/dev/null; wait_reload "$G"
[ "$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$API/v1/orders")" = 401 ] || fail "an old session works after the overlap"
echo "   old sessions ended after the overlap, new ones work"

echo "== rotate the webhook secret"
ID2="$(curl -fsS -X POST -H "Authorization: Bearer $NEW" -d '{"customer":"Ali","amount_cents":900}' "$API/v1/orders" | json "['id']")"
G="$(gen)"; bash "$ROOT/scripts/rotate.sh" webhook >/dev/null; wait_reload "$G"
[ "$(webhook "$ID2" orders/payments/webhook-secret-previous)" = 200 ] || fail "previous webhook secret during the overlap"
[ "$(webhook "$ID2" orders/payments/webhook-secret)" = 200 ] || fail "new webhook secret"
G="$(gen)"; bash "$ROOT/scripts/rotate.sh" webhook-done >/dev/null; wait_reload "$G"
echo "   both secrets accepted during the overlap"

echo "== rotate the database password"
G="$(gen)"; bash "$ROOT/scripts/rotate.sh" db >/dev/null; wait_reload "$G"
# Restarting the database drops every connection, so the API must reconnect with
# the new password it read from goraz.
(cd "$ROOT" && docker compose restart db >/dev/null)
for _ in $(seq 1 30); do curl -fsS "$API/healthz" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS -H "Authorization: Bearer $NEW" "$API/v1/orders" >/dev/null || fail "no database access after the password rotation"
echo "   reconnected with the new password, no API restart"

echo "== no secret in the logs"
LOGS="$(cd "$ROOT" && docker compose logs api 2>&1)"
for name in orders/db/password orders/jwt/current orders/payments/webhook-secret; do
  v="$(g read "goraz://$name")"
  case "$LOGS" in *"$v"*) fail "the log contains $name" ;; esac
done
case "$LOGS" in *"$(cat "$ROOT/.operator/api-key")"*) fail "the log contains the API key" ;; esac
echo "   clean"
echo "ALL PASSED"
