package auth_test

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/mtnaskari/goraz-example/internal/auth"
	"github.com/mtnaskari/goraz-example/internal/secrets"
	"github.com/mtnaskari/goraz-example/internal/testvault"
)

func TestIssueVerify(t *testing.T) {
	s := testvault.New(t).Open(secrets.Config{})
	a := auth.New(s, nil)
	tok, err := a.Issue("billing-worker", []string{"orders:read"})
	if err != nil {
		t.Fatal(err)
	}
	sess, err := a.Verify(tok)
	if err != nil {
		t.Fatal(err)
	}
	if sess.Subject != "billing-worker" || !sess.HasScope("orders:read") || sess.HasScope("orders:write") {
		t.Errorf("%+v", sess)
	}
}

func TestExpiry(t *testing.T) {
	s := testvault.New(t).Open(secrets.Config{})
	now := time.Now()
	a := auth.New(s, func() time.Time { return now })
	tok, err := a.Issue("x", nil)
	if err != nil {
		t.Fatal(err)
	}
	later := auth.New(s, func() time.Time { return now.Add(auth.SessionTTL + time.Second) })
	if _, err := later.Verify(tok); !errors.Is(err, auth.ErrInvalidSession) {
		t.Errorf("err = %v", err)
	}
}

// A rotation keeps tokens signed with the previous key valid until they expire, and
// ends them once the previous key is removed.
func TestKeyRotation(t *testing.T) {
	e := testvault.New(t)
	s := e.Open(secrets.Config{})
	a := auth.New(s, nil)
	old, err := a.Issue("x", nil)
	if err != nil {
		t.Fatal(err)
	}
	e.Put(secrets.JWTPreviousKey, testvault.Values[secrets.JWTCurrentKey])
	e.Put(secrets.JWTCurrentKey, "jwt-new-key-fedcba9876543210fedcba")
	e.Sync()
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Verify(old); err != nil {
		t.Errorf("an old token during the overlap: %v", err)
	}
	fresh, err := a.Issue("x", nil)
	if err != nil {
		t.Fatal(err)
	}
	e.Delete(secrets.JWTPreviousKey)
	e.Sync()
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Verify(old); !errors.Is(err, auth.ErrInvalidSession) {
		t.Errorf("an old token after the overlap: %v", err)
	}
	if _, err := a.Verify(fresh); err != nil {
		t.Errorf("a new token: %v", err)
	}
}

func TestRejectsOtherAlgorithmsAndForgeries(t *testing.T) {
	s := testvault.New(t).Open(secrets.Config{})
	a := auth.New(s, nil)
	claims := jwt.MapClaims{"sub": "x", "aud": "orders", "iss": "orders", "exp": time.Now().Add(time.Hour).Unix()}
	none, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("guessed key"))
	if err != nil {
		t.Fatal(err)
	}
	for name, tok := range map[string]string{"none": none, "forged": forged, "garbage": "a.b.c"} {
		if _, err := a.Verify(tok); !errors.Is(err, auth.ErrInvalidSession) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
