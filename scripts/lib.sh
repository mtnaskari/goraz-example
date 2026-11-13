# Shared setup for the scripts. The operator vault lives in .operator/, which is
# never committed: in a real team it would be each operator's own vault.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export GORAZ_VAULT="$ROOT/.operator/operator.goraz"
export GORAZ_STATE_DIR="$ROOT/.operator/state"
GORAZ="$ROOT/bin/goraz"
PASSFILE="$ROOT/.operator/passphrase"

# Builds the goraz command at the version go.mod requires.
build_goraz() {
  mkdir -p "$ROOT/bin"
  (cd "$ROOT" && go build -o "$GORAZ" github.com/mtnaskari/goraz/cmd/goraz)
}

# Runs goraz with the operator passphrase on file descriptor 3. Keeping the
# passphrase in a file is for this local example only.
g() {
  "$GORAZ" "$@" --passphrase-fd 3 3<"$PASSFILE"
}

# Puts a value read from standard input.
put() {
  g put "$1"
}

sync_service() {
  g service sync orders --out "$ROOT/deploy/vault/orders.goraz"
  chmod 0644 "$ROOT/deploy/vault/orders.goraz"
}

# Writes the database password where the Postgres container reads it.
write_db_password() {
  umask 077
  g read goraz://orders/db/password > "$ROOT/deploy/secrets/db-password"
}
