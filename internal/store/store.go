// Package store keeps orders in Postgres. The database password is read from goraz
// each time the pool opens a connection, so after a password rotation new
// connections use the new password with no restart.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mtnaskari/goraz/secret"

	"github.com/mtnaskari/goraz-example/internal/secrets"
)

// PasswordSource gives the database password.
type PasswordSource interface {
	Get(name string) (secret.Secret, error)
}

// Order is one order.
type Order struct {
	ID          int64     `json:"id"`
	Customer    string    `json:"customer"`
	AmountCents int64     `json:"amount_cents"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

// ErrNotFound means no such order.
var ErrNotFound = errors.New("store: order not found")

// Store is the order repository.
type Store struct{ pool *pgxpool.Pool }

// Open connects with a DSN that holds no password, such as
// "postgres://orders@localhost:55432/orders?sslmode=disable".
func Open(ctx context.Context, dsn string, pw PasswordSource) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: parsing the DSN: %w", err)
	}
	if cfg.ConnConfig.Password != "" {
		return nil, errors.New("store: the DSN must not contain a password; it comes from goraz")
	}
	// Each new connection reads the current password. pgx keeps it as a string for
	// the handshake, which Go can't wipe; the copy here is cleared at least.
	cfg.BeforeConnect = func(_ context.Context, c *pgx.ConnConfig) error {
		p, err := pw.Get(secrets.DBPassword)
		if err != nil {
			return err
		}
		defer p.Wipe()
		c.Password = string(p.Bytes())
		return nil
	}
	cfg.MaxConnLifetime = 30 * time.Minute
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	s := &Store{pool: pool}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the pool.
func (s *Store) Close() { s.pool.Close() }

// Ping checks the database.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// ResetConnections closes idle connections, so the next ones use a new password.
func (s *Store) ResetConnections() { s.pool.Reset() }

func (s *Store) migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS orders (
		id           BIGSERIAL PRIMARY KEY,
		customer     TEXT NOT NULL,
		amount_cents BIGINT NOT NULL CHECK (amount_cents > 0),
		status       TEXT NOT NULL DEFAULT 'pending',
		created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
	)`)
	if err != nil {
		return fmt.Errorf("store: migrating: %w", err)
	}
	return nil
}

// Create adds an order.
func (s *Store) Create(ctx context.Context, customer string, amountCents int64) (Order, error) {
	var o Order
	err := s.pool.QueryRow(ctx,
		`INSERT INTO orders (customer, amount_cents) VALUES ($1, $2)
		 RETURNING id, customer, amount_cents, status, created_at`,
		customer, amountCents).Scan(&o.ID, &o.Customer, &o.AmountCents, &o.Status, &o.CreatedAt)
	return o, err
}

// List returns the newest orders.
func (s *Store) List(ctx context.Context, limit int) ([]Order, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, customer, amount_cents, status, created_at FROM orders ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Order, error) {
		var o Order
		err := r.Scan(&o.ID, &o.Customer, &o.AmountCents, &o.Status, &o.CreatedAt)
		return o, err
	})
}

// MarkPaid sets an order's status to paid. It is idempotent, because a provider
// may deliver the same webhook more than once.
func (s *Store) MarkPaid(ctx context.Context, id int64) (Order, error) {
	var o Order
	err := s.pool.QueryRow(ctx,
		`UPDATE orders SET status = 'paid' WHERE id = $1
		 RETURNING id, customer, amount_cents, status, created_at`, id).
		Scan(&o.ID, &o.Customer, &o.AmountCents, &o.Status, &o.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Order{}, ErrNotFound
	}
	return o, err
}
