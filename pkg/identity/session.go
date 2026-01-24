package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/google/uuid"
)

// Session represents an AIP session with identity management.
type Session struct {
	// ID is the unique session identifier (UUID v4)
	ID string

	// AgentID is the policy metadata.name
	AgentID string

	// PolicyHash is the SHA-256 hash of the canonical policy
	PolicyHash string

	// PolicyPath is the path to the policy file
	PolicyPath string

	// Config is the identity configuration
	Config *Config

	// currentToken is the active identity token
	currentToken *Token

	// seenNonces tracks nonces for replay detection
	seenNonces map[string]struct{}

	mu sync.RWMutex
}

// NewSession creates a new session with the given configuration.
func NewSession(agentID, policyPath string, policyData []byte, config *Config) (*Session, error) {
	if config == nil {
		config = DefaultConfig()
	}

	sessionID := uuid.New().String()
	policyHash := ComputePolicyHash(policyData)

	return &Session{
		ID:         sessionID,
		AgentID:    agentID,
		PolicyHash: policyHash,
		PolicyPath: policyPath,
		Config:     config,
		seenNonces: make(map[string]struct{}),
	}, nil
}

// ComputePolicyHash computes the SHA-256 hash of the policy document.
// The policy should be in canonical JSON form for deterministic hashing.
func ComputePolicyHash(policyData []byte) string {
	// Try to canonicalize as JSON first
	var obj interface{}
	if err := json.Unmarshal(policyData, &obj); err == nil {
		// Re-marshal with sorted keys for canonical form
		if canonical, err := json.Marshal(obj); err == nil {
			policyData = canonical
		}
	}

	h := sha256.Sum256(policyData)
	return hex.EncodeToString(h[:])
}

// IssueToken generates a new identity token for this session.
func (s *Session) IssueToken() (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	binding := CreateBinding(s.Config.GetSessionBinding(), s.PolicyPath)
	token, err := NewToken(
		s.AgentID,
		s.PolicyHash,
		s.ID,
		s.Config.GetTokenTTL(),
		binding,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create token: %w", err)
	}

	// Track the nonce for replay detection
	s.seenNonces[token.Nonce] = struct{}{}

	s.currentToken = token
	return token, nil
}

// GetCurrentToken returns the current token, issuing a new one if needed.
func (s *Session) GetCurrentToken() (*Token, error) {
	s.mu.RLock()
	token := s.currentToken
	s.mu.RUnlock()

	if token == nil || s.ShouldRotate() {
		return s.IssueToken()
	}

	return token, nil
}

// ShouldRotate checks if the current token should be rotated.
func (s *Session) ShouldRotate() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.currentToken == nil {
		return true
	}

	remaining := s.currentToken.ExpiresIn()
	rotationThreshold := s.Config.GetTokenTTL() - s.Config.GetRotationInterval()

	return remaining <= rotationThreshold
}

// ValidateToken validates an incoming token against this session.
func (s *Session) ValidateToken(token *Token) *ValidationResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check token version
	if token.Version != TokenVersion {
		return &ValidationResult{
			Valid: false,
			Error: "token_version_mismatch",
		}
	}

	// Check expiration
	if token.IsExpired() {
		return &ValidationResult{
			Valid: false,
			Error: "token_expired",
		}
	}

	// Check policy hash
	if token.PolicyHash != s.PolicyHash {
		return &ValidationResult{
			Valid: false,
			Error: "policy_changed",
		}
	}

	// Check session ID
	if token.SessionID != s.ID {
		return &ValidationResult{
			Valid: false,
			Error: "session_mismatch",
		}
	}

	// Check binding
	if !token.MatchesBinding(s.Config.GetSessionBinding(), s.PolicyPath) {
		return &ValidationResult{
			Valid: false,
			Error: "binding_mismatch",
		}
	}

	// Check for replay (nonce reuse)
	// Note: We only track nonces from tokens WE issued
	// For tokens from other sources, we'd need distributed nonce tracking

	return &ValidationResult{
		Valid:     true,
		ExpiresIn: int(token.ExpiresIn().Seconds()),
	}
}

// ValidationResult contains the result of token validation.
type ValidationResult struct {
	// Valid is true if the token passed all checks
	Valid bool `json:"valid"`

	// Error contains the error code if validation failed
	Error string `json:"error,omitempty"`

	// ExpiresIn is the number of seconds until expiration (if valid)
	ExpiresIn int `json:"expires_in,omitempty"`
}

// GetStats returns session statistics.
func (s *Session) GetStats() SessionStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := SessionStats{
		SessionID:   s.ID,
		AgentID:     s.AgentID,
		PolicyHash:  s.PolicyHash,
		NonceCount:  len(s.seenNonces),
		HasToken:    s.currentToken != nil,
		TokenExpiry: "",
	}

	if s.currentToken != nil {
		stats.TokenExpiry = s.currentToken.ExpiresAt
		stats.TokenExpiresIn = int(s.currentToken.ExpiresIn().Seconds())
	}

	return stats
}

// SessionStats contains session statistics.
type SessionStats struct {
	SessionID      string `json:"session_id"`
	AgentID        string `json:"agent_id"`
	PolicyHash     string `json:"policy_hash"`
	NonceCount     int    `json:"nonce_count"`
	HasToken       bool   `json:"has_token"`
	TokenExpiry    string `json:"token_expiry,omitempty"`
	TokenExpiresIn int    `json:"token_expires_in,omitempty"`
}
