package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Cyberhunter88/restic-backup-validator/internal/app"
)

func main() {
	if err := run(); err != nil {
		slog.Error("validator failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	mode := "serve"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	if mode == "version" {
		fmt.Println(app.Version)
		return nil
	}
	if mode != "serve" && mode != "run-once" {
		return errors.New("usage: validator [serve|run-once|version]")
	}
	path := os.Getenv("APP_DB_PATH")
	if path == "" {
		path = "/data/validator.db"
	}
	store, err := app.OpenStore(path, os.Getenv("APP_MASTER_KEY"))
	if err != nil {
		return err
	}
	defer store.Close()
	if mode == "run-once" {
		repos, err := store.ListRepositories()
		if err != nil {
			return err
		}
		if len(repos) == 0 {
			return errors.New("keine Repositories konfiguriert")
		}
		runner := app.NewRunner(store)
		failed := false
		for _, repo := range repos {
			run, err := runner.Run(context.Background(), repo.ID, "run-once")
			if err != nil || run.Result != "ok" {
				failed = true
			}
		}
		if failed {
			return errors.New("mindestens eine Repository-Prüfung ist fehlgeschlagen")
		}
		return nil
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	config := app.ServerConfig{Listen: os.Getenv("APP_LISTEN"), PublicURL: os.Getenv("APP_URL"), Issuer: os.Getenv("OIDC_ISSUER"),
		ClientID: os.Getenv("OIDC_CLIENT_ID"), ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"), GroupClaim: os.Getenv("OIDC_GROUP_CLAIM")}
	server, err := app.NewServer(ctx, config, store)
	if err != nil {
		return err
	}
	defer server.Close()
	listen := config.Listen
	if listen == "" {
		listen = ":8080"
	}
	httpServer := &http.Server{Addr: listen, Handler: server, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()
	slog.Info("validator listening", "address", listen, "version", app.Version)
	err = httpServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
