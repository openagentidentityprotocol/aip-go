package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Token represents an AIP identity token.
// This structure is compatible with the AIP v1alpha2 specification.
type Token struct {
	// Version is the token format version (e.g., "aip/v1alpha2")
	Version string `json:"version"`

	// PolicyHash is the SHA-256 hash of the canonical policy document
	PolicyHash string `json:"policy_hash"`

	// SessionID is a UUID identifying this session
	SessionID string `json:"session_id"`

	// AgentID is the value of metadata.name from the policy
	AgentID string `json:"agent_id"`

	// IssuedAt is the token issuance time (ISO 8601)
	IssuedAt string `json:"issued_at"`

	// ExpiresAt is the token expiration time (ISO 8601)
	ExpiresAt string `json:"expires_at"`

	// Nonce is a random value for replay prevention
	Nonce string `json:"nonce"`

	// Binding contains session binding context
	Binding *TokenBinding `json:"binding,omitempty"`
}

// TokenBinding contains the session binding context.
type TokenBinding struct {
	// ProcessID is the current process ID
	ProcessID int `json:"process_id,omitempty"`

	// PolicyPath is the path to the policy file
	PolicyPath string `json:"policy_path,omitempty"`

	// Hostname is the machine hostname
	Hostname string `json:"hostname,omitempty"`
}

// TokenVersion is the current token format version.
const TokenVersion = "aip/v1alpha2"

// NewToken creates a new identity token.
func NewToken(agentID, policyHash, sessionID string, ttl time.Duration, binding *TokenBinding) (*Token, error) {
	nonce, err := generateNonce()
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	now := time.Now().UTC()

	return &Token{
		Version:    TokenVersion,
		PolicyHash: policyHash,
		SessionID:  sessionID,
		AgentID:    agentID,
		IssuedAt:   now.Format(time.RFC3339),
		ExpiresAt:  now.Add(ttl).Format(time.RFC3339),
		Nonce:      nonce,
		Binding:    binding,
	}, nil
}

// generateNonce creates a cryptographically secure random nonce.
// Returns a 32-character hex string (16 bytes of entropy).
func generateNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// IsExpired checks if the token has expired.
func (t *Token) IsExpired() bool {
	exp, err := time.Parse(time.RFC3339, t.ExpiresAt)
	if err != nil {
		return true // Invalid expiration = expired
	}
	return time.Now().UTC().After(exp)
}

// ExpiresIn returns the duration until the token expires.
// Returns 0 if already expired.
func (t *Token) ExpiresIn() time.Duration {
	exp, err := time.Parse(time.RFC3339, t.ExpiresAt)
	if err != nil {
		return 0
	}
	remaining := time.Until(exp)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// Encode serializes the token to a compact base64 string.
func (t *Token) Encode() (string, error) {
	data, err := json.Marshal(t)
	if err != nil {
		return "", fmt.Errorf("failed to marshal token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// DecodeToken decodes a base64-encoded token string.
func DecodeToken(encoded string) (*Token, error) {
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode token: %w", err)
	}

	var token Token
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %w", err)
	}

	return &token, nil
}

// CreateBinding creates a token binding based on the binding mode.
func CreateBinding(mode, policyPath string) *TokenBinding {
	binding := &TokenBinding{}

	switch mode {
	case SessionBindingProcess:
		binding.ProcessID = os.Getpid()
	case SessionBindingPolicy:
		binding.PolicyPath = policyPath
	case SessionBindingStrict:
		binding.ProcessID = os.Getpid()
		binding.PolicyPath = policyPath
		if hostname, err := os.Hostname(); err == nil {
			binding.Hostname = hostname
		}
	}

	return binding
}

// MatchesBinding checks if the token binding matches the current context.
func (t *Token) MatchesBinding(mode, policyPath string) bool {
	if t.Binding == nil {
		return true // No binding = matches everything
	}

	switch mode {
	case SessionBindingProcess:
		return t.Binding.ProcessID == 0 || t.Binding.ProcessID == os.Getpid()
	case SessionBindingPolicy:
		return t.Binding.PolicyPath == "" || t.Binding.PolicyPath == policyPath
	case SessionBindingStrict:
		if t.Binding.ProcessID != 0 && t.Binding.ProcessID != os.Getpid() {
			return false
		}
		if t.Binding.PolicyPath != "" && t.Binding.PolicyPath != policyPath {
			return false
		}
		if t.Binding.Hostname != "" {
			if hostname, err := os.Hostname(); err == nil && t.Binding.Hostname != hostname {
				return false
			}
		}
		return true
	}

	return true
}

// ComputeHash computes a hash that can be used for replay detection.
// This is derived from the nonce and session ID.
func (t *Token) ComputeHash() string {
	h := sha256.New()
	h.Write([]byte(t.SessionID))
	h.Write([]byte(t.Nonce))
	h.Write([]byte(t.IssuedAt))
	return hex.EncodeToString(h.Sum(nil))[:16]
}
