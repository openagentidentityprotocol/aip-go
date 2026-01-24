package server

import (
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Enabled {
		t.Error("Default should have Enabled=false")
	}
	if cfg.Listen != "127.0.0.1:9443" {
		t.Errorf("Default Listen = %q, want %q", cfg.Listen, "127.0.0.1:9443")
	}
	if cfg.Endpoints == nil {
		t.Fatal("Default Endpoints should not be nil")
	}
	if cfg.Endpoints.Validate != "/v1/validate" {
		t.Errorf("Default Validate = %q, want %q", cfg.Endpoints.Validate, "/v1/validate")
	}
	if cfg.Endpoints.Health != "/health" {
		t.Errorf("Default Health = %q, want %q", cfg.Endpoints.Health, "/health")
	}
	if cfg.Endpoints.Metrics != "/metrics" {
		t.Errorf("Default Metrics = %q, want %q", cfg.Endpoints.Metrics, "/metrics")
	}
}

func TestConfigGetListen(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected string
	}{
		{"nil config", nil, "127.0.0.1:9443"},
		{"empty listen", &Config{}, "127.0.0.1:9443"},
		{"custom listen", &Config{Listen: "0.0.0.0:8080"}, "0.0.0.0:8080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.GetListen()
			if got != tt.expected {
				t.Errorf("GetListen() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestConfigGetPaths(t *testing.T) {
	cfg := &Config{
		Endpoints: &EndpointsConfig{
			Validate: "/custom/validate",
			Health:   "/custom/health",
			Metrics:  "/custom/metrics",
		},
	}

	if cfg.GetValidatePath() != "/custom/validate" {
		t.Errorf("GetValidatePath() = %q, want %q", cfg.GetValidatePath(), "/custom/validate")
	}
	if cfg.GetHealthPath() != "/custom/health" {
		t.Errorf("GetHealthPath() = %q, want %q", cfg.GetHealthPath(), "/custom/health")
	}
	if cfg.GetMetricsPath() != "/custom/metrics" {
		t.Errorf("GetMetricsPath() = %q, want %q", cfg.GetMetricsPath(), "/custom/metrics")
	}
}

func TestConfigIsLocalhost(t *testing.T) {
	tests := []struct {
		name     string
		listen   string
		expected bool
	}{
		{"127.0.0.1", "127.0.0.1:9443", true},
		{"localhost", "localhost:9443", true},
		{"ipv6 localhost", "[::1]:9443", true},
		{"all interfaces", "0.0.0.0:9443", false},
		{"external IP", "192.168.1.1:9443", false},
		{"hostname", "server.example.com:9443", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Listen: tt.listen}
			if cfg.IsLocalhost() != tt.expected {
				t.Errorf("IsLocalhost() = %v, want %v", cfg.IsLocalhost(), tt.expected)
			}
		})
	}
}

func TestConfigRequiresTLS(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected bool
	}{
		{
			name:     "disabled server",
			config:   &Config{Enabled: false, Listen: "0.0.0.0:9443"},
			expected: false,
		},
		{
			name:     "localhost doesn't require TLS",
			config:   &Config{Enabled: true, Listen: "127.0.0.1:9443"},
			expected: false,
		},
		{
			name:     "external address requires TLS",
			config:   &Config{Enabled: true, Listen: "0.0.0.0:9443"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.config.RequiresTLS() != tt.expected {
				t.Errorf("RequiresTLS() = %v, want %v", tt.config.RequiresTLS(), tt.expected)
			}
		})
	}
}

func TestConfigHasTLS(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected bool
	}{
		{"no TLS config", &Config{}, false},
		{"empty TLS config", &Config{TLS: &TLSConfig{}}, false},
		{"cert only", &Config{TLS: &TLSConfig{Cert: "/path/cert.pem"}}, false},
		{"key only", &Config{TLS: &TLSConfig{Key: "/path/key.pem"}}, false},
		{"cert and key", &Config{TLS: &TLSConfig{Cert: "/cert.pem", Key: "/key.pem"}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.config.HasTLS() != tt.expected {
				t.Errorf("HasTLS() = %v, want %v", tt.config.HasTLS(), tt.expected)
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
			name:    "disabled server is valid",
			config:  &Config{Enabled: false},
			wantErr: false,
		},
		{
			name: "localhost without TLS is valid",
			config: &Config{
				Enabled: true,
				Listen:  "127.0.0.1:9443",
			},
			wantErr: false,
		},
		{
			name: "external address without TLS is invalid",
			config: &Config{
				Enabled: true,
				Listen:  "0.0.0.0:9443",
			},
			wantErr: true,
			errMsg:  "tls",
		},
		{
			name: "external address with TLS is valid",
			config: &Config{
				Enabled: true,
				Listen:  "0.0.0.0:9443",
				TLS: &TLSConfig{
					Cert: "/path/cert.pem",
					Key:  "/path/key.pem",
				},
			},
			wantErr: false,
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
