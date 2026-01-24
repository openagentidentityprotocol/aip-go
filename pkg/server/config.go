// Package server implements HTTP endpoints for server-side validation in AIP v1alpha2.
//
// The server package provides:
//   - Validation endpoint for remote policy enforcement
//   - Health check endpoint for load balancers
//   - Metrics endpoint for Prometheus integration
//   - TLS support for secure communication
//
// This is a new feature in AIP v1alpha2 that enables distributed policy enforcement
// and centralized validation.
package server

import (
	"fmt"
	"strings"
)

// Config holds the server configuration from the policy spec.
// Maps to spec.server in the policy YAML.
type Config struct {
	// Enabled controls whether the HTTP server is active.
	// Default: false
	Enabled bool `yaml:"enabled,omitempty"`

	// Listen is the address and port to bind.
	// Format: "<host>:<port>" or ":<port>"
	// Default: "127.0.0.1:9443"
	Listen string `yaml:"listen,omitempty"`

	// TLS configures HTTPS.
	// Required if Listen is not localhost.
	TLS *TLSConfig `yaml:"tls,omitempty"`

	// Endpoints configures custom endpoint paths.
	Endpoints *EndpointsConfig `yaml:"endpoints,omitempty"`
}

// TLSConfig holds TLS configuration.
type TLSConfig struct {
	// Cert is the path to the TLS certificate file (PEM format)
	Cert string `yaml:"cert,omitempty"`

	// Key is the path to the TLS private key file (PEM format)
	Key string `yaml:"key,omitempty"`

	// ClientCA is the path to the CA certificate for client verification (mTLS)
	ClientCA string `yaml:"client_ca,omitempty"`

	// RequireClientCert enables mTLS (mutual TLS)
	RequireClientCert bool `yaml:"require_client_cert,omitempty"`
}

// EndpointsConfig holds custom endpoint path configuration.
type EndpointsConfig struct {
	// Validate is the path for the validation endpoint
	// Default: "/v1/validate"
	Validate string `yaml:"validate,omitempty"`

	// Health is the path for the health check endpoint
	// Default: "/health"
	Health string `yaml:"health,omitempty"`

	// Metrics is the path for the Prometheus metrics endpoint
	// Default: "/metrics"
	Metrics string `yaml:"metrics,omitempty"`
}

// DefaultConfig returns the default server configuration.
func DefaultConfig() *Config {
	return &Config{
		Enabled: false,
		Listen:  "127.0.0.1:9443",
		Endpoints: &EndpointsConfig{
			Validate: "/v1/validate",
			Health:   "/health",
			Metrics:  "/metrics",
		},
	}
}

// GetListen returns the listen address.
func (c *Config) GetListen() string {
	if c == nil || c.Listen == "" {
		return "127.0.0.1:9443"
	}
	return c.Listen
}

// GetValidatePath returns the validation endpoint path.
func (c *Config) GetValidatePath() string {
	if c == nil || c.Endpoints == nil || c.Endpoints.Validate == "" {
		return "/v1/validate"
	}
	return c.Endpoints.Validate
}

// GetHealthPath returns the health check endpoint path.
func (c *Config) GetHealthPath() string {
	if c == nil || c.Endpoints == nil || c.Endpoints.Health == "" {
		return "/health"
	}
	return c.Endpoints.Health
}

// GetMetricsPath returns the metrics endpoint path.
func (c *Config) GetMetricsPath() string {
	if c == nil || c.Endpoints == nil || c.Endpoints.Metrics == "" {
		return "/metrics"
	}
	return c.Endpoints.Metrics
}

// IsLocalhost returns true if the listen address is localhost.
func (c *Config) IsLocalhost() bool {
	addr := c.GetListen()
	return strings.HasPrefix(addr, "127.0.0.1:") ||
		strings.HasPrefix(addr, "localhost:") ||
		strings.HasPrefix(addr, "[::1]:")
}

// RequiresTLS returns true if TLS is required (non-localhost).
func (c *Config) RequiresTLS() bool {
	return c.Enabled && !c.IsLocalhost()
}

// HasTLS returns true if TLS is configured.
func (c *Config) HasTLS() bool {
	return c.TLS != nil && c.TLS.Cert != "" && c.TLS.Key != ""
}

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}

	// Check TLS requirement
	if c.RequiresTLS() && !c.HasTLS() {
		return &ConfigError{
			Field:   "tls",
			Message: "TLS is required when listen address is not localhost",
		}
	}

	// Validate TLS config if present
	if c.HasTLS() {
		if c.TLS.Cert == "" {
			return &ConfigError{
				Field:   "tls.cert",
				Message: "TLS certificate path is required",
			}
		}
		if c.TLS.Key == "" {
			return &ConfigError{
				Field:   "tls.key",
				Message: "TLS key path is required",
			}
		}
	}

	return nil
}

// ConfigError represents a configuration validation error.
type ConfigError struct {
	Field   string
	Message string
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf("server config error: %s: %s", e.Field, e.Message)
}
