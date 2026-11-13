// Command orders is an example HTTP service that keeps all of its secrets in goraz:
// the database password, the session signing keys, the payment webhook secret and a
// Telegram bot token. None of them is in an environment variable or a config file.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mtnaskari/goraz-example/internal/api"
	"github.com/mtnaskari/goraz-example/internal/auth"
	"github.com/mtnaskari/goraz-example/internal/notify"
	"github.com/mtnaskari/goraz-example/internal/secrets"
	"github.com/mtnaskari/goraz-example/internal/store"
)

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func main() {
	addr := flag.String("addr", env("ORDERS_ADDR", ":8088"), "listen address")
	vaultPath := flag.String("vault", env("ORDERS_VAULT", "/etc/orders/orders.goraz"), "goraz service file")
	keyPath := flag.String("key", env("ORDERS_KEY_FILE", "/run/secrets/goraz-key"), "goraz machine key file")
	dsn := flag.String("db", env("ORDERS_DB", "postgres://orders@localhost:55432/orders?sslmode=disable"), "database URL, with no password")
	tgBase := flag.String("telegram-api", env("ORDERS_TELEGRAM_API", "https://api.telegram.org"), "Telegram API base URL")
	tgChat := flag.String("telegram-chat", env("ORDERS_TELEGRAM_CHAT", ""), "Telegram chat for notifications")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(logger, *addr, *vaultPath, *keyPath, *dsn, *tgBase, *tgChat); err != nil {
		logger.Error("stopped", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger, addr, vaultPath, keyPath, dsn, tgBase, tgChat string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Secret reads are audited on stdout, separate from the application log.
	sec, err := secrets.Open(ctx, secrets.Config{
		VaultPath: vaultPath,
		KeyPath:   keyPath,
		Audit:     os.Stdout,
		OnReloadError: func(err error) {
			logger.Warn("a new secrets file was refused; keeping the current one", "err", err)
		},
	})
	if err != nil {
		return err
	}
	defer sec.Close()

	orders, err := store.Open(ctx, dsn, sec)
	if err != nil {
		return err
	}
	defer orders.Close()

	srv := &api.Server{
		Secrets:  sec,
		Sessions: auth.New(sec, nil),
		Orders:   orders,
		Notify:   &notify.Telegram{BaseURL: tgBase, ChatID: tgChat, Tokens: sec},
		Log:      logger,
	}
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
	}
	errc := make(chan error, 1)
	go func() { errc <- httpServer.ListenAndServe() }()
	logger.Info("listening", "addr", addr, "secrets_generation", sec.Generation())

	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return httpServer.Shutdown(shutdown)
}
