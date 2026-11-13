// Package api is the HTTP interface of the orders service.
//
//	POST /v1/session              exchange an API key for a 15-minute session token
//	GET  /v1/orders               list orders           (scope orders:read)
//	POST /v1/orders               create an order       (scope orders:write)
//	POST /v1/webhooks/payments    a signed payment notification
//	GET  /healthz                 database and secrets health
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/mtnaskari/goraz/secret"
	"github.com/mtnaskari/goraz/token"

	"github.com/mtnaskari/goraz-example/internal/auth"
	"github.com/mtnaskari/goraz-example/internal/secrets"
	"github.com/mtnaskari/goraz-example/internal/store"
	"github.com/mtnaskari/goraz-example/internal/webhook"
)

// Secrets is what the API needs from goraz.
type Secrets interface {
	Get(name string) (secret.Secret, error)
	Optional(name string) (secret.Secret, error)
	VerifyAPIKey(ctx context.Context, key []byte, scope string) (token.Record, error)
	Generation() uint64
}

// Orders is the order repository.
type Orders interface {
	Create(ctx context.Context, customer string, amountCents int64) (store.Order, error)
	List(ctx context.Context, limit int) ([]store.Order, error)
	MarkPaid(ctx context.Context, id int64) (store.Order, error)
	Ping(ctx context.Context) error
}

// Notifier tells operators about events.
type Notifier interface {
	Send(ctx context.Context, text string) error
}

// Server holds the handlers' dependencies.
type Server struct {
	Secrets  Secrets
	Sessions *auth.Sessions
	Orders   Orders
	Notify   Notifier
	Log      *slog.Logger
	Now      func() time.Time
}

// Handler returns the routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/session", s.session)
	mux.HandleFunc("GET /v1/orders", s.requireScope("orders:read", s.listOrders))
	mux.HandleFunc("POST /v1/orders", s.requireScope("orders:write", s.createOrder))
	mux.HandleFunc("POST /v1/webhooks/payments", s.paymentWebhook)
	mux.HandleFunc("GET /healthz", s.health)
	return mux
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// fail maps an internal error to a response. Stale or expired secrets answer 503,
// because serving with secrets that can't be trusted is worse than not serving.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	if secrets.Unavailable(err) {
		s.Log.Error("secrets unavailable", "path", r.URL.Path, "err", err)
		writeError(w, http.StatusServiceUnavailable, "temporarily unavailable")
		return
	}
	s.Log.Error("request failed", "path", r.URL.Path, "err", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	t, ok := strings.CutPrefix(h, "Bearer ")
	return t, ok && t != ""
}

// session exchanges a long-lived API key, issued with goraz, for a short session.
func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	key, ok := bearer(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing API key")
		return
	}
	rec, err := s.Secrets.VerifyAPIKey(r.Context(), []byte(key), "orders")
	switch {
	case errors.Is(err, token.ErrInvalidToken), errors.Is(err, token.ErrForbidden):
		writeError(w, http.StatusUnauthorized, "invalid API key")
		return
	case err != nil:
		s.Log.Error("verifying an API key", "err", err)
		writeError(w, http.StatusServiceUnavailable, "temporarily unavailable")
		return
	}
	tok, err := s.Sessions.Issue(rec.Name, rec.Scopes)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token": tok, "token_type": "Bearer", "expires_in": int(auth.SessionTTL.Seconds()),
	})
}

func (s *Server) requireScope(scope string, next func(http.ResponseWriter, *http.Request, auth.Session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, ok := bearer(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "missing session token")
			return
		}
		sess, err := s.Sessions.Verify(raw)
		if errors.Is(err, auth.ErrInvalidSession) {
			writeError(w, http.StatusUnauthorized, "invalid session token")
			return
		}
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if !sess.HasScope(scope) {
			writeError(w, http.StatusForbidden, "missing scope "+scope)
			return
		}
		next(w, r, sess)
	}
}

func (s *Server) listOrders(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	orders, err := s.Orders.List(r.Context(), 100)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"orders": orders})
}

func (s *Server) createOrder(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	var in struct {
		Customer    string `json:"customer"`
		AmountCents int64  `json:"amount_cents"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil || in.Customer == "" || in.AmountCents <= 0 {
		writeError(w, http.StatusBadRequest, "customer and a positive amount_cents are required")
		return
	}
	o, err := s.Orders.Create(r.Context(), in.Customer, in.AmountCents)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.Log.Info("order created", "order", o.ID, "by", sess.Subject)
	writeJSON(w, http.StatusCreated, o)
}

// paymentWebhook marks an order paid when the provider's signature verifies. Both
// the current and the previous secret are accepted, so rotating the secret doesn't
// drop notifications signed just before the provider switched.
func (s *Server) paymentWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		writeError(w, http.StatusBadRequest, "unreadable body")
		return
	}
	current, err := s.Secrets.Get(secrets.WebhookSecret)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer current.Wipe()
	previous, err := s.Secrets.Optional(secrets.WebhookSecret + "-previous")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer previous.Wipe()
	if err := webhook.Verify(r.Header.Get("Payment-Signature"), body, s.now(), current.Bytes(), previous.Bytes()); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid signature")
		return
	}
	var in struct {
		OrderID int64 `json:"order_id"`
	}
	if err := json.Unmarshal(body, &in); err != nil || in.OrderID <= 0 {
		writeError(w, http.StatusBadRequest, "order_id is required")
		return
	}
	o, err := s.Orders.MarkPaid(r.Context(), in.OrderID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no such order")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if s.Notify != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		msg := fmt.Sprintf("Order %d for %s is paid: %d.%02d", o.ID, o.Customer, o.AmountCents/100, o.AmountCents%100)
		if err := s.Notify.Send(ctx, msg); err != nil {
			s.Log.Warn("notification not sent", "order", o.ID, "err", err)
		}
	}
	writeJSON(w, http.StatusOK, o)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	status := map[string]any{"secrets_generation": s.Secrets.Generation()}
	code := http.StatusOK
	if err := s.Orders.Ping(ctx); err != nil {
		status["database"] = "unreachable"
		code = http.StatusServiceUnavailable
	} else {
		status["database"] = "ok"
	}
	if v, err := s.Secrets.Get(secrets.WebhookSecret); err != nil {
		status["secrets"] = "unavailable"
		code = http.StatusServiceUnavailable
	} else {
		v.Wipe()
		status["secrets"] = "ok"
	}
	writeJSON(w, code, status)
}
