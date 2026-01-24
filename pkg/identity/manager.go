package identity

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Manager handles identity token lifecycle and rotation.
type Manager struct {
	session *Session
	config  *Config

	// rotationTicker triggers token rotation
	rotationTicker *time.Ticker

	// callbacks for token events
	onTokenIssued  func(*Token)
	onTokenRotated func(oldToken, newToken *Token)

	// stopCh signals the rotation goroutine to stop
	stopCh chan struct{}

	mu sync.RWMutex
}

// NewManager creates a new identity manager.
func NewManager(agentID, policyPath string, policyData []byte, config *Config) (*Manager, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid identity config: %w", err)
	}

	session, err := NewSession(agentID, policyPath, policyData, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &Manager{
		session: session,
		config:  config,
		stopCh:  make(chan struct{}),
	}, nil
}

// Start begins the token rotation loop.
// This should be called after the manager is created.
func (m *Manager) Start(ctx context.Context) error {
	if !m.config.Enabled {
		return nil // Identity not enabled, nothing to do
	}

	// Issue initial token
	token, err := m.session.IssueToken()
	if err != nil {
		return fmt.Errorf("failed to issue initial token: %w", err)
	}

	if m.onTokenIssued != nil {
		m.onTokenIssued(token)
	}

	// Start rotation ticker
	rotationInterval := m.config.GetRotationInterval()
	m.rotationTicker = time.NewTicker(rotationInterval)

	go m.rotationLoop(ctx)

	return nil
}

// Stop stops the identity manager and releases resources.
func (m *Manager) Stop() {
	close(m.stopCh)
	if m.rotationTicker != nil {
		m.rotationTicker.Stop()
	}
}

// rotationLoop handles automatic token rotation.
func (m *Manager) rotationLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-m.rotationTicker.C:
			m.rotate()
		}
	}
}

// rotate creates a new token and notifies listeners.
func (m *Manager) rotate() {
	m.mu.Lock()
	defer m.mu.Unlock()

	oldToken := m.session.currentToken

	newToken, err := m.session.IssueToken()
	if err != nil {
		// Log error but don't crash - old token still valid
		return
	}

	if m.onTokenRotated != nil && oldToken != nil {
		m.onTokenRotated(oldToken, newToken)
	}
}

// GetToken returns the current valid token.
// Issues a new token if none exists or rotation is needed.
func (m *Manager) GetToken() (*Token, error) {
	if !m.config.Enabled {
		return nil, nil // Identity not enabled
	}

	return m.session.GetCurrentToken()
}

// ValidateToken validates an incoming token.
func (m *Manager) ValidateToken(tokenStr string) *ValidationResult {
	if !m.config.Enabled {
		return &ValidationResult{Valid: true} // Identity not enabled = all valid
	}

	token, err := DecodeToken(tokenStr)
	if err != nil {
		return &ValidationResult{
			Valid: false,
			Error: "malformed",
		}
	}

	return m.session.ValidateToken(token)
}

// RequiresToken returns true if tokens are required for tool calls.
func (m *Manager) RequiresToken() bool {
	return m.config.Enabled && m.config.RequireToken
}

// IsEnabled returns true if identity management is enabled.
func (m *Manager) IsEnabled() bool {
	return m.config.Enabled
}

// GetSessionID returns the current session ID.
func (m *Manager) GetSessionID() string {
	return m.session.ID
}

// GetPolicyHash returns the policy hash.
func (m *Manager) GetPolicyHash() string {
	return m.session.PolicyHash
}

// GetStats returns manager statistics.
func (m *Manager) GetStats() ManagerStats {
	sessionStats := m.session.GetStats()
	return ManagerStats{
		Enabled:      m.config.Enabled,
		RequireToken: m.config.RequireToken,
		Session:      sessionStats,
	}
}

// ManagerStats contains manager statistics.
type ManagerStats struct {
	Enabled      bool         `json:"enabled"`
	RequireToken bool         `json:"require_token"`
	Session      SessionStats `json:"session"`
}

// OnTokenIssued sets a callback for when tokens are issued.
func (m *Manager) OnTokenIssued(fn func(*Token)) {
	m.onTokenIssued = fn
}

// OnTokenRotated sets a callback for when tokens are rotated.
func (m *Manager) OnTokenRotated(fn func(oldToken, newToken *Token)) {
	m.onTokenRotated = fn
}
