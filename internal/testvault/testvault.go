// Package testvault builds a real goraz service file for tests, the same way the
// bootstrap script does with the goraz command.
package testvault

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mtnaskari/goraz/secret"
	"github.com/mtnaskari/goraz/token"
	"github.com/mtnaskari/goraz/vault"

	"github.com/mtnaskari/goraz-example/internal/secrets"
)

// Values are the secrets a test vault holds. They are fake, test-only values that
// protect nothing; never reuse them.
var Values = map[string]string{
	secrets.DBPassword:    "db-password-for-tests",
	secrets.JWTCurrentKey: "jwt-current-key-0123456789abcdef",
	secrets.WebhookSecret: "whsec-current-for-tests",
	secrets.TelegramToken: "123456:telegram-token-for-tests",
}

// Env is an operator vault plus the service file made from it.
type Env struct {
	Main     *vault.Vault
	Dir      string
	File     string // The service file.
	KeyFile  string // Its machine key, mode 0400.
	APIKey   []byte // A client API key with the scopes below.
	Scopes   []string
	t        testing.TB
	keyBytes []byte
}

// New creates the operator vault and the "orders" service file.
func New(t testing.TB) *Env {
	t.Helper()
	dir := t.TempDir()
	main, _, err := vault.Create(filepath.Join(dir, "operator.goraz"), vault.CreateOptions{
		Passphrase: []byte("violet granite ocean drift lantern"), // Fake, test-only.
		Profile:    vault.ProfileInteractive,
		Options:    vault.Options{StateDir: filepath.Join(dir, "state")},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(main.Close)
	e := &Env{Main: main, Dir: dir, File: filepath.Join(dir, "orders.goraz"), KeyFile: filepath.Join(dir, "orders.key"), t: t}
	for name, v := range Values {
		e.Put(name, v)
	}
	key, err := main.CreateService("orders", e.File, vault.ServiceOptions{Prefixes: []string{"orders"}})
	if err != nil {
		t.Fatal(err)
	}
	e.keyBytes = key.Bytes()
	if err := os.WriteFile(e.KeyFile, append(key.Bytes(), '\n'), 0o400); err != nil {
		t.Fatal(err)
	}
	e.Scopes = []string{"orders", "orders:read", "orders:write"}
	m, err := main.ServiceTokens("orders", nil)
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := m.Issue(context.Background(), token.IssueRequest{Name: "billing-worker", Scopes: e.Scopes, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	e.APIKey = tok.Bytes()
	e.Sync()
	return e
}

// Put stores a value in the operator vault. Call Sync to deliver it.
func (e *Env) Put(name, value string) {
	e.t.Helper()
	if err := e.Main.Put(&vault.Item{Name: name, Value: secret.New([]byte(value))}); err != nil {
		e.t.Fatal(err)
	}
}

// Delete removes an item from the operator vault.
func (e *Env) Delete(name string) {
	e.t.Helper()
	if err := e.Main.Delete(name); err != nil {
		e.t.Fatal(err)
	}
}

// Sync writes a fresh service file, as `goraz service sync` does.
func (e *Env) Sync() {
	e.t.Helper()
	if err := e.Main.SyncService("orders", e.File); err != nil {
		e.t.Fatal(err)
	}
}

// Open returns a secrets store reading the service file, with audit events discarded.
func (e *Env) Open(cfg secrets.Config) *secrets.Store {
	e.t.Helper()
	cfg.VaultPath, cfg.KeyPath = e.File, e.KeyFile
	if cfg.Audit == nil {
		cfg.Audit = discard{}
	}
	s, err := secrets.Open(context.Background(), cfg)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(s.Close)
	return s
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
