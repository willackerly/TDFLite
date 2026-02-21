// Package server wires together all TDFLite services into a single HTTP server.
package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/willnorris/tdflite/internal/authn"
	"github.com/willnorris/tdflite/internal/config"
)

// Server is the main TDFLite HTTP server.
type Server struct {
	cfg    *config.Config
	mux    *http.ServeMux
	logger *slog.Logger
	auth   authn.Authenticator
}

// New creates a new server with the given configuration.
func New(cfg *config.Config, auth authn.Authenticator, logger *slog.Logger) *Server {
	mux := http.NewServeMux()

	s := &Server{
		cfg:    cfg,
		mux:    mux,
		logger: logger,
		auth:   auth,
	}

	// Health and readiness endpoints (unauthenticated).
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)

	return s
}

// Mux returns the server's HTTP mux for registering additional routes.
func (s *Server) Mux() *http.ServeMux {
	return s.mux
}

// Run starts the server and blocks until shutdown.
func (s *Server) Run(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Server.Host, s.cfg.Server.Port)

	httpServer := &http.Server{
		Addr:         addr,
		Handler:      s.mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
		BaseContext:  func(_ net.Listener) context.Context { return ctx },
	}

	// Graceful shutdown on signals.
	shutdownCh := make(chan os.Signal, 1)
	signal.Notify(shutdownCh, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("starting TDFLite server", "addr", addr)
		if s.cfg.Server.TLS.Enabled {
			errCh <- httpServer.ListenAndServeTLS(s.cfg.Server.TLS.CertFile, s.cfg.Server.TLS.KeyFile)
		} else {
			errCh <- httpServer.ListenAndServe()
		}
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	case sig := <-shutdownCh:
		s.logger.Info("received shutdown signal", "signal", sig)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpServer.Shutdown(shutdownCtx)
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpServer.Shutdown(shutdownCtx)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"ok"}`)
}

func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"ready"}`)
}
