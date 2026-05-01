// Package main starts the CEMA certificate daemon.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/stdpi/cema/internal/daemon"
	"github.com/stdpi/cema/internal/issuer"
	"github.com/stdpi/cema/internal/store"
)

func main() {
	if err := run(); err != nil {
		slog.Error("daemon failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	listen := flag.String("listen", ":8080", "HTTP listen address")
	storageDir := flag.String("storage", "./data", "certificate storage directory")
	apiKey := flag.String("api-key", os.Getenv("CEMA_API_KEY"), "optional API key")
	flag.Parse()

	fileStore, err := store.NewFileStore(*storageDir)
	if err != nil {
		return fmt.Errorf("create file store: %w", err)
	}

	server := daemon.NewServer(daemon.Config{
		Store:  fileStore,
		Issuer: issuer.NewSelfSignedIssuer(),
		APIKey: *apiKey,
		Logger: slog.Default(),
	})

	httpServer := &http.Server{
		Addr:              *listen,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		slog.Info("cema daemon listening", "addr", *listen, "storage", *storageDir)
		errCh <- httpServer.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown server: %w", err)
		}
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve: %w", err)
	}
}
