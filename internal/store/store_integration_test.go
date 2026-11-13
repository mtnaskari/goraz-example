//go:build integration

package store_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/mtnaskari/goraz/secret"

	"github.com/mtnaskari/goraz-example/internal/secrets"
	"github.com/mtnaskari/goraz-example/internal/store"
)

// passwords serves the database password the way the goraz store does.
type passwords map[string]string

func (p passwords) Get(name string) (secret.Secret, error) {
	v, ok := p[name]
	if !ok {
		return secret.Secret{}, errors.New("missing")
	}
	return secret.New([]byte(v)), nil
}

// Run with the compose database: ORDERS_TEST_DB and ORDERS_TEST_DB_PASSWORD.
func TestStoreAgainstPostgres(t *testing.T) {
	dsn, pw := os.Getenv("ORDERS_TEST_DB"), os.Getenv("ORDERS_TEST_DB_PASSWORD")
	if dsn == "" || pw == "" {
		t.Skip("ORDERS_TEST_DB and ORDERS_TEST_DB_PASSWORD are not set")
	}
	ctx := context.Background()
	if _, err := store.Open(ctx, dsn+"&password=nope", passwords{}); err == nil {
		t.Fatal("a DSN with a password was accepted")
	}
	s, err := store.Open(ctx, dsn, passwords{secrets.DBPassword: pw})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	o, err := s.Create(ctx, "integration", 4200)
	if err != nil {
		t.Fatal(err)
	}
	paid, err := s.MarkPaid(ctx, o.ID)
	if err != nil || paid.Status != "paid" {
		t.Fatalf("%v %v", paid, err)
	}
	if _, err := s.MarkPaid(ctx, -1); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("err = %v", err)
	}
	list, err := s.List(ctx, 10)
	if err != nil || len(list) == 0 {
		t.Fatalf("%v %v", list, err)
	}

	// A wrong password must fail on a fresh connection.
	bad, err := store.Open(ctx, dsn, passwords{secrets.DBPassword: "wrong"})
	if err == nil {
		bad.Close()
		t.Error("a wrong password connected")
	}
}
