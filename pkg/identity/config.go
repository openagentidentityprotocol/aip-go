// Package identity implements agent identity tokens and session management for AIP v1alpha2.
//
// The identity package provides:
//   - Token generation with cryptographic nonces
//   - Automatic token rotation before expiry
//   - Session binding (process, policy, strict modes)
//   - Policy hash computation for integrity verification
//
// This is a new feature in AIP v1alpha2 that enables server-side validation
// and distributed policy enforcement.
package identity

import (
	"time"
)

// Config holds the identity configuration from the policy spec.
// Maps to spec.identity in the policy YAML.
type Config struct {
	// Enabled controls whether identity token generation is active.
	// Default: false
	Enabled bool `yaml:"enabled,omitempty"`

	// TokenTTL is the time-to-live for identity tokens.
	// Format: Go duration string (e.g., "5m", "1h", "300s")
	// Default: "5m" (5 minutes)
	TokenTTL string `yaml:"token_ttl,omitempty"`

	// RotationInterval is how often to rotate tokens before expiry.
	// Must be less than TokenTTL.
	// Format: Go duration string
	// Default: "4m" (4 minutes)
	RotationInterval string `yaml:"rotation_interval,omitempty"`

	// RequireToken when true requires all tool calls to include a valid token.
	// Default: false
	RequireToken bool `yaml:"require_token,omitempty"`

	// SessionBinding determines what context is bound to the session identity.
	// Values: "process" (default), "policy", "strict"
	SessionBinding string `yaml:"session_binding,omitempty"`
}

// DefaultConfig returns the default identity configuration.
func DefaultConfig() *Config {
	return &Config{
		Enabled:          false,
		TokenTTL:         "5m",
		RotationInterval: "4m",
		RequireToken:     false,
		SessionBinding:   SessionBindingProcess,
	}
}

// Session binding modes
const (
	// SessionBindingProcess binds the session to the process ID.
	SessionBindingProcess = "process"

	// SessionBindingPolicy binds the session to the policy hash.
	SessionBindingPolicy = "policy"

	// SessionBindingStrict binds the session to process + policy + timestamp.
	SessionBindingStrict = "strict"
)

// GetTokenTTL parses and returns the token TTL as a duration.
// Returns the default (5m) if parsing fails or not set.
func (c *Config) GetTokenTTL() time.Duration {
	if c == nil || c.TokenTTL == "" {
		return 5 * time.Minute
	}
	d, err := time.ParseDuration(c.TokenTTL)
	if err != nil {
		return 5 * time.Minute
	}
	return d
}

// GetRotationInterval parses and returns the rotation interval as a duration.
// Returns the default (4m) if parsing fails or not set.
func (c *Config) GetRotationInterval() time.Duration {
	if c == nil || c.RotationInterval == "" {
		return 4 * time.Minute
	}
	d, err := time.ParseDuration(c.RotationInterval)
	if err != nil {
		return 4 * time.Minute
	}
	return d
}

// GetSessionBinding returns the session binding mode.
// Returns "process" if not set or invalid.
func (c *Config) GetSessionBinding() string {
	if c == nil || c.SessionBinding == "" {
		return SessionBindingProcess
	}
	switch c.SessionBinding {
	case SessionBindingProcess, SessionBindingPolicy, SessionBindingStrict:
		return c.SessionBinding
	default:
		return SessionBindingProcess
	}
}

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	if c == nil {
		return nil
	}

	ttl := c.GetTokenTTL()
	rotation := c.GetRotationInterval()

	if rotation >= ttl {
		return &ConfigError{
			Field:   "rotation_interval",
			Message: "rotation_interval must be less than token_ttl",
		}
	}

	if ttl > time.Hour {
		return &ConfigError{
			Field:   "token_ttl",
			Message: "token_ttl should not exceed 1 hour for security",
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
	return "identity config error: " + e.Field + ": " + e.Message
}
