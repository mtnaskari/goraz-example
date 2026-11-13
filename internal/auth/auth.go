// Package auth issues and checks the short-lived session tokens (JWTs) that clients
// use after presenting an API key. The signing keys come from goraz, and two are
// active during a rotation: tokens signed with the previous key keep working until
// they expire.
package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/mtnaskari/goraz/secret"

	"github.com/mtnaskari/goraz-example/internal/secrets"
)

// SessionTTL is how long a session token lives.
const SessionTTL = 15 * time.Minute

// ErrInvalidSession is returned for any token that doesn't verify.
var ErrInvalidSession = errors.New("auth: invalid session token")

// KeySource gives the current and previous signing keys.
type KeySource interface {
	Get(name string) (secret.Secret, error)
	Optional(name string) (secret.Secret, error)
}

// Sessions signs and verifies session tokens.
type Sessions struct {
	keys KeySource
	now  func() time.Time
}

// New returns Sessions using keys from src.
func New(src KeySource, now func() time.Time) *Sessions {
	if now == nil {
		now = time.Now
	}
	return &Sessions{keys: src, now: now}
}

// keyID names a key without revealing it, so a verifier can pick the right one.
func keyID(key []byte) string {
	sum := sha256.Sum256(append([]byte("orders/jwt/kid\x00"), key...))
	return hex.EncodeToString(sum[:8])
}

// Issue returns a session token for subject with the given scopes.
func (s *Sessions) Issue(subject string, scopes []string) (string, error) {
	key, err := s.keys.Get(secrets.JWTCurrentKey)
	if err != nil {
		return "", err
	}
	defer key.Wipe()
	now := s.now()
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims{
		Scopes: scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			Issuer:    "orders",
			Audience:  jwt.ClaimStrings{"orders"},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(SessionTTL)),
		},
	})
	t.Header["kid"] = keyID(key.Bytes())
	signed, err := t.SignedString(key.Bytes())
	if err != nil {
		return "", fmt.Errorf("auth: signing: %w", err)
	}
	return signed, nil
}

type claims struct {
	Scopes []string `json:"scopes"`
	jwt.RegisteredClaims
}

// Session is a verified token.
type Session struct {
	Subject string
	Scopes  []string
}

// HasScope reports whether the session holds scope.
func (s Session) HasScope(scope string) bool {
	return slices.Contains(s.Scopes, scope)
}

// Verify checks a session token. Only HS256 is accepted, so a token can't choose a
// weaker algorithm or "none".
func (s *Sessions) Verify(raw string) (Session, error) {
	current, err := s.keys.Get(secrets.JWTCurrentKey)
	if err != nil {
		return Session{}, err
	}
	defer current.Wipe()
	previous, err := s.keys.Optional(secrets.JWTPreviousKey)
	if err != nil {
		return Session{}, err
	}
	defer previous.Wipe()

	var c claims
	_, err = jwt.ParseWithClaims(raw, &c, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		switch {
		case kid == keyID(current.Bytes()):
			return current.Bytes(), nil
		case !previous.IsZero() && kid == keyID(previous.Bytes()):
			return previous.Bytes(), nil
		}
		return nil, ErrInvalidSession
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithAudience("orders"),
		jwt.WithIssuer("orders"),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(s.now),
	)
	if err != nil {
		return Session{}, ErrInvalidSession
	}
	return Session{Subject: c.Subject, Scopes: c.Scopes}, nil
}
