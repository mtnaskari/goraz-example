// Package notify sends operator notifications through a Telegram bot. The bot token
// is a secret: it is read from goraz for each message and never logged.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/mtnaskari/goraz/secret"

	"github.com/mtnaskari/goraz-example/internal/secrets"
)

// TokenSource gives the bot token.
type TokenSource interface {
	Optional(name string) (secret.Secret, error)
}

// Telegram sends messages to one chat.
type Telegram struct {
	BaseURL string // https://api.telegram.org, or a test server.
	ChatID  string
	Tokens  TokenSource
	Client  *http.Client
}

// ErrNotConfigured means there is no bot token or chat, so messages are skipped.
var ErrNotConfigured = errors.New("notify: telegram isn't configured")

// Send posts text to the chat. Errors never include the token, because the token
// is part of the request URL.
func (t *Telegram) Send(ctx context.Context, text string) error {
	tok, err := t.Tokens.Optional(secrets.TelegramToken)
	if err != nil {
		return err
	}
	defer tok.Wipe()
	if tok.IsZero() || t.ChatID == "" {
		return ErrNotConfigured
	}
	body, err := json.Marshal(map[string]string{"chat_id": t.ChatID, "text": text})
	if err != nil {
		return err
	}
	url := t.BaseURL + "/bot" + string(tok.Bytes()) + "/sendMessage"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return errors.New("notify: building the request failed")
	}
	req.Header.Set("Content-Type", "application/json")
	client := t.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		// The error from net/http includes the URL, and so the token.
		return errors.New("notify: sending to telegram failed")
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("notify: telegram answered %d", resp.StatusCode)
	}
	return nil
}
