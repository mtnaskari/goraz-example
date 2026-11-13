package notify_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mtnaskari/goraz-example/internal/notify"
	"github.com/mtnaskari/goraz-example/internal/secrets"
	"github.com/mtnaskari/goraz-example/internal/testvault"
)

func TestSend(t *testing.T) {
	s := testvault.New(t).Open(secrets.Config{})
	var gotPath, gotText string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotText = body["text"]
	}))
	defer srv.Close()
	tg := &notify.Telegram{BaseURL: srv.URL, ChatID: "42", Tokens: s, Client: srv.Client()}
	if err := tg.Send(context.Background(), "hello"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/bot"+testvault.Values[secrets.TelegramToken]+"/sendMessage" || gotText != "hello" {
		t.Errorf("%s %s", gotPath, gotText)
	}
}

// The token is in the request URL, so errors must never include the URL.
func TestErrorsHideToken(t *testing.T) {
	s := testvault.New(t).Open(secrets.Config{})
	tg := &notify.Telegram{BaseURL: "http://127.0.0.1:1", ChatID: "42", Tokens: s}
	err := tg.Send(context.Background(), "hello")
	if err == nil || strings.Contains(err.Error(), "telegram-token") || strings.Contains(err.Error(), "123456") {
		t.Errorf("err = %v", err)
	}
}

func TestNotConfigured(t *testing.T) {
	e := testvault.New(t)
	e.Delete(secrets.TelegramToken)
	e.Sync()
	s := e.Open(secrets.Config{})
	tg := &notify.Telegram{BaseURL: "http://unused", ChatID: "42", Tokens: s}
	if err := tg.Send(context.Background(), "x"); !errors.Is(err, notify.ErrNotConfigured) {
		t.Errorf("err = %v", err)
	}
}
