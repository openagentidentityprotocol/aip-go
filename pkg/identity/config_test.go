package identity

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Enabled {
		t.Error("Default should have Enabled=false")
	}
	if cfg.TokenTTL != "5m" {
		t.Errorf("Default TokenTTL = %q, want %q", cfg.TokenTTL, "5m")
	}
	if cfg.RotationInterval != "4m" {
		t.Errorf("Default RotationInterval = %q, want %q", cfg.RotationInterval, "4m")
	}
	if cfg.RequireToken {
		t.Error("Default should have RequireToken=false")
	}
	if cfg.SessionBinding != SessionBindingProcess {
		t.Errorf("Default SessionBinding = %q, want %q", cfg.SessionBinding, SessionBindingProcess)
	}
}

func TestConfigGetTokenTTL(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected time.Duration
	}{
		{"nil config", nil, 5 * time.Minute},
		{"empty TTL", &Config{}, 5 * time.Minute},
		{"invalid TTL", &Config{TokenTTL: "invalid"}, 5 * time.Minute},
		{"10 minutes", &Config{TokenTTL: "10m"}, 10 * time.Minute},
		{"1 hour", &Config{TokenTTL: "1h"}, 1 * time.Hour},
		{"300 seconds", &Config{TokenTTL: "300s"}, 300 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.GetTokenTTL()
			if got != tt.expected {
				t.Errorf("GetTokenTTL() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestConfigGetRotationInterval(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected time.Duration
	}{
		{"nil config", nil, 4 * time.Minute},
		{"empty interval", &Config{}, 4 * time.Minute},
		{"invalid interval", &Config{RotationInterval: "bad"}, 4 * time.Minute},
		{"8 minutes", &Config{RotationInterval: "8m"}, 8 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.GetRotationInterval()
			if got != tt.expected {
				t.Errorf("GetRotationInterval() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestConfigGetSessionBinding(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected string
	}{
		{"nil config", nil, SessionBindingProcess},
		{"empty binding", &Config{}, SessionBindingProcess},
		{"invalid binding", &Config{SessionBinding: "invalid"}, SessionBindingProcess},
		{"process", &Config{SessionBinding: "process"}, SessionBindingProcess},
		{"policy", &Config{SessionBinding: "policy"}, SessionBindingPolicy},
		{"strict", &Config{SessionBinding: "strict"}, SessionBindingStrict},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.GetSessionBinding()
			if got != tt.expected {
				t.Errorf("GetSessionBinding() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config is valid",
			config:  nil,
			wantErr: false,
		},
		{
			name: "valid config",
			config: &Config{
				TokenTTL:         "10m",
				RotationInterval: "8m",
			},
			wantErr: false,
		},
		{
			name: "rotation >= TTL is invalid",
			config: &Config{
				TokenTTL:         "5m",
				RotationInterval: "5m",
			},
			wantErr: true,
			errMsg:  "rotation_interval",
		},
		{
			name: "rotation > TTL is invalid",
			config: &Config{
				TokenTTL:         "5m",
				RotationInterval: "10m",
			},
			wantErr: true,
			errMsg:  "rotation_interval",
		},
		{
			name: "TTL > 1 hour is invalid",
			config: &Config{
				TokenTTL:         "2h",
				RotationInterval: "1h",
			},
			wantErr: true,
			errMsg:  "token_ttl",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errMsg != "" {
				if cfgErr, ok := err.(*ConfigError); ok {
					if cfgErr.Field != tt.errMsg {
						t.Errorf("Error field = %q, want %q", cfgErr.Field, tt.errMsg)
					}
				}
			}
		})
	}
}

func TestConfigErrorString(t *testing.T) {
	err := &ConfigError{
		Field:   "test_field",
		Message: "test message",
	}

	expected := "identity config error: test_field: test message"
	if err.Error() != expected {
		t.Errorf("Error() = %q, want %q", err.Error(), expected)
	}
}
