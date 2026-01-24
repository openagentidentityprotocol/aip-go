package identity

import (
	"testing"
	"time"
)

func TestNewToken(t *testing.T) {
	token, err := NewToken("test-agent", "abc123hash", "session-123", 5*time.Minute, nil)
	if err != nil {
		t.Fatalf("NewToken failed: %v", err)
	}

	if token.Version != TokenVersion {
		t.Errorf("Expected version %q, got %q", TokenVersion, token.Version)
	}
	if token.AgentID != "test-agent" {
		t.Errorf("Expected agent ID %q, got %q", "test-agent", token.AgentID)
	}
	if token.PolicyHash != "abc123hash" {
		t.Errorf("Expected policy hash %q, got %q", "abc123hash", token.PolicyHash)
	}
	if token.SessionID != "session-123" {
		t.Errorf("Expected session ID %q, got %q", "session-123", token.SessionID)
	}
	if token.Nonce == "" {
		t.Error("Expected nonce to be set")
	}
	if len(token.Nonce) != 32 {
		t.Errorf("Expected nonce length 32, got %d", len(token.Nonce))
	}
}

func TestTokenExpiration(t *testing.T) {
	// Token that expires in 1 second
	token, err := NewToken("test", "hash", "sess", 1*time.Second, nil)
	if err != nil {
		t.Fatalf("NewToken failed: %v", err)
	}

	if token.IsExpired() {
		t.Error("Fresh token should not be expired")
	}

	expiresIn := token.ExpiresIn()
	if expiresIn <= 0 || expiresIn > 1*time.Second {
		t.Errorf("ExpiresIn should be between 0 and 1s, got %v", expiresIn)
	}

	// Wait for expiration
	time.Sleep(1100 * time.Millisecond)

	if !token.IsExpired() {
		t.Error("Token should be expired after TTL")
	}

	if token.ExpiresIn() != 0 {
		t.Errorf("Expired token ExpiresIn should be 0, got %v", token.ExpiresIn())
	}
}

func TestTokenEncodeDecode(t *testing.T) {
	original, err := NewToken("encode-test", "hash123", "sess456", 5*time.Minute, nil)
	if err != nil {
		t.Fatalf("NewToken failed: %v", err)
	}

	// Encode
	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	if encoded == "" {
		t.Error("Encoded token should not be empty")
	}

	// Decode
	decoded, err := DecodeToken(encoded)
	if err != nil {
		t.Fatalf("DecodeToken failed: %v", err)
	}

	// Verify fields match
	if decoded.Version != original.Version {
		t.Errorf("Version mismatch: %q vs %q", decoded.Version, original.Version)
	}
	if decoded.AgentID != original.AgentID {
		t.Errorf("AgentID mismatch: %q vs %q", decoded.AgentID, original.AgentID)
	}
	if decoded.PolicyHash != original.PolicyHash {
		t.Errorf("PolicyHash mismatch: %q vs %q", decoded.PolicyHash, original.PolicyHash)
	}
	if decoded.SessionID != original.SessionID {
		t.Errorf("SessionID mismatch: %q vs %q", decoded.SessionID, original.SessionID)
	}
	if decoded.Nonce != original.Nonce {
		t.Errorf("Nonce mismatch: %q vs %q", decoded.Nonce, original.Nonce)
	}
}

func TestDecodeTokenInvalid(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"empty string", "", true},
		{"invalid base64", "not-valid-base64!!!", true},
		{"valid base64 but invalid json", "bm90LWpzb24", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeToken(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeToken() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTokenBinding(t *testing.T) {
	binding := CreateBinding(SessionBindingProcess, "/path/to/policy.yaml")

	if binding.ProcessID == 0 {
		t.Error("Process binding should set ProcessID")
	}

	binding = CreateBinding(SessionBindingPolicy, "/path/to/policy.yaml")
	if binding.PolicyPath != "/path/to/policy.yaml" {
		t.Errorf("Policy binding should set PolicyPath, got %q", binding.PolicyPath)
	}

	binding = CreateBinding(SessionBindingStrict, "/path/to/policy.yaml")
	if binding.ProcessID == 0 {
		t.Error("Strict binding should set ProcessID")
	}
	if binding.PolicyPath != "/path/to/policy.yaml" {
		t.Error("Strict binding should set PolicyPath")
	}
}

func TestTokenMatchesBinding(t *testing.T) {
	token, _ := NewToken("test", "hash", "sess", 5*time.Minute, nil)

	// No binding = matches everything
	if !token.MatchesBinding(SessionBindingProcess, "/any/path") {
		t.Error("Token with no binding should match any context")
	}

	// Token with process binding
	token.Binding = CreateBinding(SessionBindingProcess, "/test/policy.yaml")
	if !token.MatchesBinding(SessionBindingProcess, "/test/policy.yaml") {
		t.Error("Token should match its own process")
	}
}

func TestTokenComputeHash(t *testing.T) {
	token1, _ := NewToken("test", "hash", "sess", 5*time.Minute, nil)
	token2, _ := NewToken("test", "hash", "sess", 5*time.Minute, nil)

	hash1 := token1.ComputeHash()
	hash2 := token2.ComputeHash()

	if hash1 == "" {
		t.Error("Hash should not be empty")
	}

	// Different tokens should have different hashes (different nonces)
	if hash1 == hash2 {
		t.Error("Different tokens should have different hashes")
	}

	// Same token should always have same hash
	if token1.ComputeHash() != hash1 {
		t.Error("Same token should produce same hash")
	}
}
