package secrets_test

import (
	"bytes"
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mtnaskari/goraz-example/internal/secrets"
	"github.com/mtnaskari/goraz-example/internal/testvault"
)

type buf struct {
	b bytes.Buffer
}

func (w *buf) Write(p []byte) (int, error) { return w.b.Write(p) }

func TestReadsSecretsAndAuditsWithoutValues(t *testing.T) {
	e := testvault.New(t)
	var audit buf
	s := e.Open(secrets.Config{Audit: &audit})
	v, err := s.Get(secrets.DBPassword)
	if err != nil {
		t.Fatal(err)
	}
	if string(v.Bytes()) != testvault.Values[secrets.DBPassword] {
		t.Fatal("wrong value")
	}
	v.Wipe()
	log := audit.b.String()
	if !strings.Contains(log, `"item.read"`) {
		t.Errorf("no audit event: %s", log)
	}
	for _, leak := range []string{"db-password-for-tests", "orders/db"} {
		if strings.Contains(log, leak) {
			t.Errorf("audit stream contains %q", leak)
		}
	}
}

func TestOptionalMissingIsZero(t *testing.T) {
	s := testvault.New(t).Open(secrets.Config{})
	v, err := s.Optional(secrets.JWTPreviousKey)
	if err != nil || !v.IsZero() {
		t.Fatalf("%v %v", v, err)
	}
}

func TestRotationReachesARunningService(t *testing.T) {
	e := testvault.New(t)
	s := e.Open(secrets.Config{})
	e.Put(secrets.WebhookSecret, "whsec-rotated")
	e.Sync()
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	v, err := s.Get(secrets.WebhookSecret)
	if err != nil {
		t.Fatal(err)
	}
	if string(v.Bytes()) != "whsec-rotated" {
		t.Error("the rotated value didn't arrive")
	}
}

// When reloads keep failing, reads fail closed instead of serving old data forever.
func TestStaleSecretsFailClosed(t *testing.T) {
	e := testvault.New(t)
	var now atomic.Int64
	now.Store(time.Now().UnixNano())
	clock := func() time.Time { return time.Unix(0, now.Load()) }
	var refused atomic.Int32
	s := e.Open(secrets.Config{MaxStale: time.Minute, Now: clock, OnReloadError: func(error) { refused.Add(1) }})

	// A damaged file arrives and is refused; the service keeps its current data.
	data := []byte("not a goraz file")
	if err := writeFile(e.File, data); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err == nil {
		t.Fatal("a damaged file was accepted")
	}
	if _, err := s.Get(secrets.DBPassword); err != nil {
		t.Errorf("within the limit: %v", err)
	}
	now.Add(int64(2 * time.Minute))
	_, err := s.Get(secrets.DBPassword)
	if !secrets.Unavailable(err) {
		t.Errorf("past the limit: %v", err)
	}
}

func TestAPIKeys(t *testing.T) {
	e := testvault.New(t)
	s := e.Open(secrets.Config{})
	ctx := context.Background()
	if _, err := s.VerifyAPIKey(ctx, e.APIKey, "orders:read"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyAPIKey(ctx, e.APIKey, "admin"); err == nil {
		t.Error("a missing scope was accepted")
	}
	if _, err := s.VerifyAPIKey(ctx, []byte("goraz_st_nope"), "orders"); err == nil {
		t.Error("a malformed key was accepted")
	}
}
