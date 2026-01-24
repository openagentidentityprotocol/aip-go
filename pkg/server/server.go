package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ArangoGutierrez/agent-identity-protocol/implementations/go-proxy/pkg/identity"
	"github.com/ArangoGutierrez/agent-identity-protocol/implementations/go-proxy/pkg/policy"
)

// Server is the HTTP server for AIP validation.
type Server struct {
	config          *Config
	httpServer      *http.Server
	handler         *Handler
	logger          *log.Logger
	engine          *policy.Engine
	identityManager *identity.Manager
}

// NewServer creates a new AIP HTTP server.
func NewServer(config *Config, engine *policy.Engine, identityManager *identity.Manager, logger *log.Logger) (*Server, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid server config: %w", err)
	}

	if logger == nil {
		logger = log.New(os.Stderr, "[aip-server] ", log.LstdFlags|log.Lmsgprefix)
	}

	handler := NewHandler(engine, identityManager)

	// Create HTTP mux
	mux := http.NewServeMux()
	mux.HandleFunc(config.GetValidatePath(), handler.HandleValidate)
	mux.HandleFunc(config.GetHealthPath(), handler.HandleHealth)
	mux.HandleFunc(config.GetMetricsPath(), handler.HandleMetrics)

	httpServer := &http.Server{
		Addr:              config.GetListen(),
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Configure TLS if enabled
	if config.HasTLS() {
		tlsConfig, err := buildTLSConfig(config.TLS)
		if err != nil {
			return nil, fmt.Errorf("failed to build TLS config: %w", err)
		}
		httpServer.TLSConfig = tlsConfig
	}

	return &Server{
		config:          config,
		httpServer:      httpServer,
		handler:         handler,
		logger:          logger,
		engine:          engine,
		identityManager: identityManager,
	}, nil
}

// buildTLSConfig creates a TLS configuration from the config.
func buildTLSConfig(cfg *TLSConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Load client CA if mTLS is enabled
	if cfg.RequireClientCert && cfg.ClientCA != "" {
		caCert, err := os.ReadFile(cfg.ClientCA)
		if err != nil {
			return nil, fmt.Errorf("failed to read client CA: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse client CA certificate")
		}

		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsConfig, nil
}

// Start starts the HTTP server.
func (s *Server) Start() error {
	if !s.config.Enabled {
		return nil // Server not enabled
	}

	s.logger.Printf("Starting AIP server on %s", s.config.GetListen())
	s.logger.Printf("  Validation endpoint: %s", s.config.GetValidatePath())
	s.logger.Printf("  Health endpoint: %s", s.config.GetHealthPath())
	s.logger.Printf("  Metrics endpoint: %s", s.config.GetMetricsPath())

	if s.config.HasTLS() {
		s.logger.Printf("  TLS: enabled")
		go func() {
			if err := s.httpServer.ListenAndServeTLS(s.config.TLS.Cert, s.config.TLS.Key); err != nil && err != http.ErrServerClosed {
				s.logger.Printf("Server error: %v", err)
			}
		}()
	} else {
		s.logger.Printf("  TLS: disabled (localhost only)")
		go func() {
			if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				s.logger.Printf("Server error: %v", err)
			}
		}()
	}

	return nil
}

// Stop gracefully stops the HTTP server.
func (s *Server) Stop(ctx context.Context) error {
	if !s.config.Enabled || s.httpServer == nil {
		return nil
	}

	s.logger.Printf("Stopping AIP server...")
	return s.httpServer.Shutdown(ctx)
}

// GetMetrics returns the server metrics.
func (s *Server) GetMetrics() *Metrics {
	return s.handler.metrics
}
