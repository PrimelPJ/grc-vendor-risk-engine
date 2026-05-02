// api/main.go
//
// GRC Vendor Risk Engine — Go REST API Server
// Exposes a versioned HTTP API that proxies scoring requests to the
// Python gRPC scoring engine and persists results to PostgreSQL.

package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/primel/grc-vendor-risk-engine/api/middleware"
)

// Config holds server runtime configuration sourced from flags or environment.
type Config struct {
	HTTPAddr    string
	ScoringAddr string
	DBDSN       string
	JWTSecret   string
	LogLevel    string
}

func parseConfig() Config {
	cfg := Config{}
	flag.StringVar(&cfg.HTTPAddr, "addr", ":8080", "HTTP server listen address")
	flag.StringVar(&cfg.ScoringAddr, "scoring-addr", "localhost:50051", "Python gRPC scoring engine address")
	flag.StringVar(&cfg.DBDSN, "db-dsn", os.Getenv("DATABASE_URL"), "PostgreSQL DSN")
	flag.StringVar(&cfg.JWTSecret, "jwt-secret", os.Getenv("JWT_SECRET"), "RS256 public key path for JWT validation")
	flag.StringVar(&cfg.LogLevel, "log-level", "info", "Log level: debug | info | warn | error")
	flag.Parse()
	return cfg
}

func main() {
	cfg := parseConfig()

	// Structured logging via log/slog (Go 1.21+)
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	slog.Info("Starting GRC Vendor Risk API", "addr", cfg.HTTPAddr, "scoring_addr", cfg.ScoringAddr)

	// Build dependency graph
	db, err := newDB(cfg.DBDSN)
	if err != nil {
		slog.Error("Database connection failed", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	scoringClient, err := newScoringClient(cfg.ScoringAddr)
	if err != nil {
		slog.Error("Failed to dial scoring engine", "error", err)
		os.Exit(1)
	}

	h := newHandler(db, scoringClient)

	mux := http.NewServeMux()

	// Health probe — unauthenticated
	mux.HandleFunc("GET /health", handleHealth)

	// Assessment endpoints — JWT required
	mux.Handle("POST /api/v1/assessments",
		middleware.Chain(
			http.HandlerFunc(h.createAssessment),
			middleware.RequireJWT(cfg.JWTSecret),
			middleware.RateLimit(100, time.Minute),
			middleware.RequestID,
			middleware.Logger,
		),
	)
	mux.Handle("GET /api/v1/assessments/{id}",
		middleware.Chain(
			http.HandlerFunc(h.getAssessment),
			middleware.RequireJWT(cfg.JWTSecret),
			middleware.RequestID,
			middleware.Logger,
		),
	)
	mux.Handle("GET /api/v1/vendors/{vendor_id}/history",
		middleware.Chain(
			http.HandlerFunc(h.listVendorHistory),
			middleware.RequireJWT(cfg.JWTSecret),
			middleware.RequestID,
			middleware.Logger,
		),
	)

	srv := &http.Server{
		Addr:         cfg.HTTPAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown on SIGINT / SIGTERM
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		slog.Info("HTTP server ready", "addr", cfg.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Server error", "error", err)
			os.Exit(1)
		}
	}()

	<-stop
	slog.Info("Shutdown signal received, draining connections...")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("Graceful shutdown failed", "error", err)
	}
	slog.Info("Server stopped cleanly")
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok","service":"grc-vendor-risk-engine"}`))
}
