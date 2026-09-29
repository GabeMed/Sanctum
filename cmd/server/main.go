package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/GabeMed/Sanctum/internal/config"
	"github.com/GabeMed/Sanctum/internal/crypto"
	"github.com/GabeMed/Sanctum/internal/db"
	"github.com/GabeMed/Sanctum/internal/handler"
	"github.com/GabeMed/Sanctum/internal/service"
)

type application struct{}

func (app *application) healthcheckHandler(w http.ResponseWriter, r *http.Request) {
	response := map[string]string{
		"status": "Sanctum is alive",
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("Server breached or failed to start: %v", err)
	}
}

// run wires the layers together (see docs/architecture.md, "Dependency
// Injection") and serves until SIGINT or SIGTERM.
func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	conn, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := db.Migrate(ctx, conn); err != nil {
		return err
	}

	engine, err := crypto.NewEngine(cfg.KEK)
	if err != nil {
		return err
	}
	clear(cfg.KEK) // the engine keeps its own copy

	svc := service.NewReflectionService(engine, db.NewPostgresRepository(conn))

	app := &application{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", app.healthcheckHandler)
	handler.NewReflectionHandler(svc).Register(mux, handler.RequireToken(cfg.APIToken))

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler.LogRequests(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		log.Printf("Starting Sanctum vault on %s", cfg.Addr)
		serveErr <- server.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		log.Println("Shutting down: draining in-flight requests")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}
	}
	return nil
}
