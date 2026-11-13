package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mtnaskari/goraz-example/internal/api"
	"github.com/mtnaskari/goraz-example/internal/auth"
	"github.com/mtnaskari/goraz-example/internal/secrets"
	"github.com/mtnaskari/goraz-example/internal/store"
	"github.com/mtnaskari/goraz-example/internal/testvault"
	"github.com/mtnaskari/goraz-example/internal/webhook"
)

// memOrders stands in for Postgres. The store package has its own integration test.
type memOrders struct {
	mu     sync.Mutex
	orders []store.Order
}

func (m *memOrders) Create(_ context.Context, c string, a int64) (store.Order, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o := store.Order{ID: int64(len(m.orders) + 1), Customer: c, AmountCents: a, Status: "pending", CreatedAt: time.Now()}
	m.orders = append(m.orders, o)
	return o, nil
}

func (m *memOrders) List(context.Context, int) ([]store.Order, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]store.Order(nil), m.orders...), nil
}

func (m *memOrders) MarkPaid(_ context.Context, id int64) (store.Order, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.orders {
		if m.orders[i].ID == id {
			m.orders[i].Status = "paid"
			return m.orders[i], nil
		}
	}
	return store.Order{}, store.ErrNotFound
}

func (m *memOrders) Ping(context.Context) error { return nil }

type sent struct {
	mu   sync.Mutex
	msgs []string
}

func (s *sent) Send(_ context.Context, text string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.msgs = append(s.msgs, text)
	return nil
}

type fixture struct {
	sec    *secrets.Store
	env    *testvault.Env
	srv    *httptest.Server
	notify *sent
	logs   *bytes.Buffer
}

func setup(t *testing.T) *fixture {
	t.Helper()
	env := testvault.New(t)
	sec := env.Open(secrets.Config{})
	logs := &bytes.Buffer{}
	n := &sent{}
	s := &api.Server{
		Secrets: sec, Sessions: auth.New(sec, nil), Orders: &memOrders{}, Notify: n,
		Log: slog.New(slog.NewJSONHandler(logs, nil)),
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return &fixture{sec: sec, env: env, srv: srv, notify: n, logs: logs}
}

func (f *fixture) do(t *testing.T, method, path, bearer string, body []byte, hdr map[string]string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, f.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func (f *fixture) session(t *testing.T) string {
	t.Helper()
	code, out := f.do(t, "POST", "/v1/session", string(f.env.APIKey), nil, nil)
	if code != http.StatusOK {
		t.Fatalf("session: %d %v", code, out)
	}
	tok, ok := out["token"].(string)
	if !ok {
		t.Fatalf("no token in %v", out)
	}
	return tok
}

func idOf(t *testing.T, out map[string]any) int64 {
	t.Helper()
	f, ok := out["id"].(float64)
	if !ok {
		t.Fatalf("no id in %v", out)
	}
	return int64(f)
}

func TestFullFlow(t *testing.T) {
	f := setup(t)
	tok := f.session(t)

	code, out := f.do(t, "POST", "/v1/orders", tok, []byte(`{"customer":"Sara","amount_cents":125000}`), nil)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, out)
	}
	id := idOf(t, out)

	body := []byte(`{"order_id":` + jsonInt(id) + `}`)
	sig := webhook.Sign([]byte(testvault.Values[secrets.WebhookSecret]), body, time.Now())
	code, out = f.do(t, "POST", "/v1/webhooks/payments", "", body, map[string]string{"Payment-Signature": sig})
	if code != http.StatusOK || out["status"] != "paid" {
		t.Fatalf("webhook: %d %v", code, out)
	}
	if len(f.notify.msgs) != 1 || !strings.Contains(f.notify.msgs[0], "Sara") {
		t.Errorf("notifications: %v", f.notify.msgs)
	}

	code, out = f.do(t, "GET", "/v1/orders", tok, nil, nil)
	if orders, ok := out["orders"].([]any); code != http.StatusOK || !ok || len(orders) != 1 {
		t.Fatalf("list: %d %v", code, out)
	}
	code, _ = f.do(t, "GET", "/healthz", "", nil, nil)
	if code != http.StatusOK {
		t.Errorf("health: %d", code)
	}

	// Nothing secret reaches the application log.
	for _, v := range testvault.Values {
		if strings.Contains(f.logs.String(), v) {
			t.Errorf("the log contains a secret")
		}
	}
	if strings.Contains(f.logs.String(), string(f.env.APIKey)) {
		t.Error("the log contains the API key")
	}
}

func jsonInt(n int64) string { b, _ := json.Marshal(n); return string(b) }

func TestAuthFailures(t *testing.T) {
	f := setup(t)
	tok := f.session(t)
	cases := []struct {
		name, method, path, bearer string
		want                       int
	}{
		{"no API key", "POST", "/v1/session", "", 401},
		{"bad API key", "POST", "/v1/session", "goraz_st_bad", 401},
		{"API key used as a session", "GET", "/v1/orders", string(f.env.APIKey), 401},
		{"no session", "GET", "/v1/orders", "", 401},
		{"bad session", "GET", "/v1/orders", "a.b.c", 401},
		{"valid session", "GET", "/v1/orders", tok, 200},
	}
	for _, c := range cases {
		if code, out := f.do(t, c.method, c.path, c.bearer, nil, nil); code != c.want {
			t.Errorf("%s: %d %v", c.name, code, out)
		}
	}
}

func TestScopes(t *testing.T) {
	f := setup(t)
	// A session signed for read only can't create orders.
	readOnly, err := auth.New(f.sec, nil).Issue("reader", []string{"orders:read"})
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := f.do(t, "POST", "/v1/orders", readOnly, []byte(`{"customer":"x","amount_cents":1}`), nil); code != http.StatusForbidden {
		t.Errorf("write with a read-only session: %d", code)
	}
}

func TestWebhookRejections(t *testing.T) {
	f := setup(t)
	body := []byte(`{"order_id":1}`)
	secret := []byte(testvault.Values[secrets.WebhookSecret])
	cases := []struct {
		name string
		sig  string
		want int
	}{
		{"unsigned", "", 401},
		{"wrong secret", webhook.Sign([]byte("other"), body, time.Now()), 401},
		{"replayed later", webhook.Sign(secret, body, time.Now().Add(-time.Hour)), 401},
		{"unknown order", webhook.Sign(secret, body, time.Now()), 404},
	}
	for _, c := range cases {
		if code, out := f.do(t, "POST", "/v1/webhooks/payments", "", body, map[string]string{"Payment-Signature": c.sig}); code != c.want {
			t.Errorf("%s: %d %v", c.name, code, out)
		}
	}
}

// A webhook secret rotation keeps the previous secret valid, so notifications
// signed before the provider switched aren't lost.
func TestWebhookSecretRotation(t *testing.T) {
	f := setup(t)
	tok := f.session(t)
	_, out := f.do(t, "POST", "/v1/orders", tok, []byte(`{"customer":"x","amount_cents":5}`), nil)
	body := []byte(`{"order_id":` + jsonInt(idOf(t, out)) + `}`)
	oldSig := webhook.Sign([]byte(testvault.Values[secrets.WebhookSecret]), body, time.Now())

	f.env.Put(secrets.WebhookSecret+"-previous", testvault.Values[secrets.WebhookSecret])
	f.env.Put(secrets.WebhookSecret, "whsec-rotated")
	f.env.Sync()
	// The running service picks the file up on its next reload; a test forces it.
	if err := f.sec.Reload(); err != nil {
		t.Fatal(err)
	}
	if code, out := f.do(t, "POST", "/v1/webhooks/payments", "", body, map[string]string{"Payment-Signature": oldSig}); code != http.StatusOK {
		t.Errorf("old signature during the overlap: %d %v", code, out)
	}
	newSig := webhook.Sign([]byte("whsec-rotated"), body, time.Now())
	if code, out := f.do(t, "POST", "/v1/webhooks/payments", "", body, map[string]string{"Payment-Signature": newSig}); code != http.StatusOK {
		t.Errorf("new signature: %d %v", code, out)
	}
	// After the overlap, the old secret stops working.
	f.env.Delete(secrets.WebhookSecret + "-previous")
	f.env.Sync()
	if err := f.sec.Reload(); err != nil {
		t.Fatal(err)
	}
	if code, _ := f.do(t, "POST", "/v1/webhooks/payments", "", body, map[string]string{"Payment-Signature": oldSig}); code != http.StatusUnauthorized {
		t.Errorf("old signature after the overlap: %d", code)
	}
}
