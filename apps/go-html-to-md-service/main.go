package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	defaultPort            = "8080"
	defaultShutdownTimeout = 30 * time.Second
	defaultTimeoutMs       = 300000 // 5 minutes
	maxUploadSize          = 150 * 1024 * 1024
)

func requestTimeout() time.Duration {
	raw := os.Getenv("REQUEST_TIMEOUT_MS")
	if raw == "" {
		return time.Duration(defaultTimeoutMs) * time.Millisecond
	}
	ms, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || ms <= 0 {
		return time.Duration(defaultTimeoutMs) * time.Millisecond
	}
	return time.Duration(ms) * time.Millisecond
}

func main() {
	// Configure logging.
	// RFC3339Nano emits sub-second precision (and an unambiguous string format
	// for Cloud Logging) so log entries from this service can be ordered
	// correctly relative to other services. The previous TimeFormatUnix value
	// produced second-level resolution, which collapsed many events into a
	// single timestamp bucket and made cross-service log correlation flaky.
	zerolog.TimeFieldFormat = time.RFC3339Nano

	env := os.Getenv("ENV")

	if env == "production" {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	} else {
		log.Logger = log.Output(zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
		})
	}

	// Get port from environment or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	timeout := requestTimeout()

	// Initialize handlers (converter is created per-request for thread-safety)
	handler := NewHandler()

	// Setup router
	router := mux.NewRouter()

	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
			next.ServeHTTP(w, r)
		})
	})

	handler.RegisterRoutes(router)

	// Create server
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      router,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
	}

	// Start server in goroutine
	go func() {
		log.Info().
			Str("port", port).
			Str("env", env).
			Dur("request_timeout", timeout).
			Msg("Starting HTML to Markdown service")

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("Failed to start server")
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info().Msg("Shutting down server...")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), defaultShutdownTimeout)
	defer cancel()

	// Attempt graceful shutdown
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal().Err(err).Msg("Server forced to shutdown")
	}

	log.Info().Msg("Server exited")
}
