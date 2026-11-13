// Package secrets is the only place the service reads secrets. It wraps a goraz
// service client, so every secret comes from one encrypted file that holds nothing
// else, and new values take effect without a restart.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/mtnaskari/goraz/audit"
	"github.com/mtnaskari/goraz/secret"
	"github.com/mtnaskari/goraz/service"
	"github.com/mtnaskari/goraz/token"
)

// The names of this service's items in the goraz vault. Each lives below the
// orders/ prefix, which is all the service file contains. They are names, not values.
//
//nolint:gosec // G101 matches the word "password" in a name; no credential is here.
const (
	DBPassword      = "orders/db/password"
	JWTCurrentKey   = "orders/jwt/current"
	JWTPreviousKey  = "orders/jwt/previous"
	WebhookSecret   = "orders/payments/webhook-secret"
	TelegramToken   = "orders/telegram/bot-token"
	reloadInterval  = 30 * time.Second
	maxStaleDefault = 15 * time.Minute
)

// Config says where the service file and its key are. Neither is a secret by
// itself: the file is encrypted, and the key is delivered as a file by the platform.
type Config struct {
	VaultPath string
	KeyPath   string
	// Audit receives one JSON line per secret read. It is usually stdout.
	Audit io.Writer
	// MaxStale is how long failed reloads are tolerated before reads fail closed.
	MaxStale time.Duration
	// OnReloadError reports a refused file. It never receives a secret.
	OnReloadError func(error)
	// Now replaces the clock in tests.
	Now func() time.Time
}

// Store hands out secrets.
type Store struct {
	c        *service.Client
	verifier *service.Verifier
}

// Open reads the service file and keeps it fresh in the background.
func Open(ctx context.Context, cfg Config) (*Store, error) {
	if cfg.VaultPath == "" || cfg.KeyPath == "" {
		return nil, errors.New("secrets: the vault path and the key path are required")
	}
	if cfg.MaxStale == 0 {
		cfg.MaxStale = maxStaleDefault
	}
	sink := audit.NewJSONSink(cfg.Audit)
	c, err := service.Open(ctx, service.Options{
		Path:          cfg.VaultPath,
		Key:           service.KeyFile(cfg.KeyPath),
		Audit:         sink,
		Interval:      reloadInterval,
		MaxStale:      cfg.MaxStale,
		OnReloadError: cfg.OnReloadError,
		Now:           cfg.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("secrets: opening %s: %w", cfg.VaultPath, err)
	}
	v, err := c.Verifier(nil)
	if err != nil {
		c.Close()
		return nil, err
	}
	return &Store{c: c, verifier: v}, nil
}

// Close stops the background reload and clears keys.
func (s *Store) Close() { s.c.Close() }

// Get returns a secret. The caller should Wipe it when done.
func (s *Store) Get(name string) (secret.Secret, error) {
	return s.c.Value(name)
}

// Optional returns a secret, or a zero Secret if the item doesn't exist.
func (s *Store) Optional(name string) (secret.Secret, error) {
	v, err := s.c.Value(name)
	if err != nil && isNotFound(err) {
		return secret.Secret{}, nil
	}
	return v, err
}

// VerifyAPIKey checks a client API key issued with `goraz token issue --service
// orders`, and that it holds scope.
func (s *Store) VerifyAPIKey(ctx context.Context, key []byte, scope string) (token.Record, error) {
	return s.verifier.Verify(ctx, key, scope)
}

// Generation is the service file's generation, useful for health checks.
func (s *Store) Generation() uint64 { return s.c.Generation() }

// Reload checks the file now, instead of waiting for the next interval.
func (s *Store) Reload() error { return s.c.Reload() }
