// Package ui tests for the AIP Human-in-the-Loop prompt system.
package ui

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// isCI returns true if running in a CI environment.
func isCI() bool {
	// GitHub Actions, GitLab CI, CircleCI, Travis, etc. all set CI=true
	return os.Getenv("CI") == "true" || os.Getenv("CI") == "1"
}

// TestNewPrompterDefaults tests that NewPrompter uses default values correctly.
func TestNewPrompterDefaults(t *testing.T) {
	p := NewPrompter(nil)

	if p.cfg.Timeout != DefaultTimeout {
		t.Errorf("Default timeout = %v, want %v", p.cfg.Timeout, DefaultTimeout)
	}
	if p.cfg.Title != "AIP Security Alert" {
		t.Errorf("Default title = %q, want %q", p.cfg.Title, "AIP Security Alert")
	}
}

// TestNewPrompterCustomConfig tests that NewPrompter respects custom config.
func TestNewPrompterCustomConfig(t *testing.T) {
	cfg := &PrompterConfig{
		Timeout: 30 * time.Second,
		Title:   "Custom Title",
	}
	p := NewPrompter(cfg)

	if p.cfg.Timeout != 30*time.Second {
		t.Errorf("Custom timeout = %v, want %v", p.cfg.Timeout, 30*time.Second)
	}
	if p.cfg.Title != "Custom Title" {
		t.Errorf("Custom title = %q, want %q", p.cfg.Title, "Custom Title")
	}
}

// TestBuildMessage tests that the dialog message is formatted correctly.
func TestBuildMessage(t *testing.T) {
	p := NewPrompter(nil)

	tests := []struct {
		name     string
		tool     string
		args     map[string]any
		contains []string
	}{
		{
			name:     "Basic tool without args",
			tool:     "test_tool",
			args:     nil,
			contains: []string{"test_tool", "{}", "allow this action"},
		},
		{
			name:     "Tool with simple args",
			tool:     "fetch_url",
			args:     map[string]any{"url": "https://example.com"},
			contains: []string{"fetch_url", "url", "https://example.com"},
		},
		{
			name:     "Tool with multiple args",
			tool:     "run_query",
			args:     map[string]any{"database": "prod", "query": "SELECT *"},
			contains: []string{"run_query", "database", "prod", "query", "SELECT *"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := p.buildMessage(tt.tool, tt.args)

			for _, substr := range tt.contains {
				if !containsString(msg, substr) {
					t.Errorf("Message missing %q:\n%s", substr, msg)
				}
			}
		})
	}
}

// TestAskUserContextCancellation tests that context cancellation returns false.
func TestAskUserContextCancellation(t *testing.T) {
	if isCI() {
		t.Skip("Skipping interactive test in CI environment")
	}

	p := NewPrompter(&PrompterConfig{
		Timeout: 10 * time.Second, // Long timeout to ensure context cancels first
	})

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately
	cancel()

	// Should return false immediately due to cancelled context
	start := time.Now()
	result := p.AskUserContext(ctx, "test_tool", nil)
	elapsed := time.Since(start)

	if result {
		t.Error("Expected false when context is cancelled")
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("Should return immediately on cancelled context, took %v", elapsed)
	}
}

// TestAskUserContextTimeout tests that timeout returns false.
func TestAskUserContextTimeout(t *testing.T) {
	if isCI() {
		t.Skip("Skipping interactive test in CI environment")
	}

	p := NewPrompter(&PrompterConfig{
		Timeout: 100 * time.Millisecond, // Very short timeout
	})

	// In headless test environment, dialog will fail, so this tests
	// that the timeout mechanism works correctly
	start := time.Now()
	result := p.AskUserContext(context.Background(), "test_tool", nil)
	elapsed := time.Since(start)

	// Should return false (either from dialog failure or timeout)
	if result {
		t.Error("Expected false in headless test environment")
	}

	// Should complete within reasonable time (timeout + buffer)
	if elapsed > 2*time.Second {
		t.Errorf("Took too long: %v (expected < 2s)", elapsed)
	}
}

// TestIsHeadless tests headless environment detection.
func TestIsHeadless(t *testing.T) {
	// This test just verifies the function doesn't panic
	// Actual result depends on environment
	_ = IsHeadless()
}

// -----------------------------------------------------------------------------
// Rate Limiting Tests
// -----------------------------------------------------------------------------

// TestRateLimitDefaults tests that rate limiting is enabled by default.
func TestRateLimitDefaults(t *testing.T) {
	p := NewPrompter(nil)

	if p.cfg.MaxPromptsPerMinute != DefaultMaxPromptsPerMinute {
		t.Errorf("Default MaxPromptsPerMinute = %d, want %d",
			p.cfg.MaxPromptsPerMinute, DefaultMaxPromptsPerMinute)
	}
	if p.cfg.CooldownDuration != DefaultCooldownDuration {
		t.Errorf("Default CooldownDuration = %v, want %v",
			p.cfg.CooldownDuration, DefaultCooldownDuration)
	}
}

// TestRateLimitCustomConfig tests custom rate limit configuration.
func TestRateLimitCustomConfig(t *testing.T) {
	cfg := &PrompterConfig{
		MaxPromptsPerMinute: 5,
		CooldownDuration:    2 * time.Minute,
	}
	p := NewPrompter(cfg)

	if p.cfg.MaxPromptsPerMinute != 5 {
		t.Errorf("MaxPromptsPerMinute = %d, want 5", p.cfg.MaxPromptsPerMinute)
	}
	if p.cfg.CooldownDuration != 2*time.Minute {
		t.Errorf("CooldownDuration = %v, want 2m", p.cfg.CooldownDuration)
	}
}

// TestRateLimitDisabled tests that negative value disables rate limiting.
func TestRateLimitDisabled(t *testing.T) {
	cfg := &PrompterConfig{
		MaxPromptsPerMinute: -1, // Disable
	}
	p := NewPrompter(cfg)

	if p.cfg.MaxPromptsPerMinute != 0 {
		t.Errorf("Disabled rate limit should be 0, got %d", p.cfg.MaxPromptsPerMinute)
	}

	// With rate limiting disabled, checkRateLimit should always return true
	for i := 0; i < 100; i++ {
		if !p.checkRateLimit("test_tool") {
			t.Fatal("checkRateLimit should always return true when disabled")
		}
	}
}

// TestRateLimitEnforced tests that rate limiting blocks excessive prompts.
func TestRateLimitEnforced(t *testing.T) {
	cfg := &PrompterConfig{
		MaxPromptsPerMinute: 3,
		CooldownDuration:    100 * time.Millisecond, // Short for testing
	}
	p := NewPrompter(cfg)

	var logMessages []string
	p.SetLogger(func(format string, args ...any) {
		logMessages = append(logMessages, fmt.Sprintf(format, args...))
	})

	// First 3 should be allowed
	for i := 0; i < 3; i++ {
		if !p.checkRateLimit("tool_" + string(rune('a'+i))) {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// 4th should be blocked
	if p.checkRateLimit("tool_blocked") {
		t.Error("4th request should be blocked by rate limit")
	}

	// Verify warning was logged
	if len(logMessages) == 0 {
		t.Error("Expected rate limit warning to be logged")
	}

	// Check status
	count, inCooldown, _ := p.GetRateLimitStatus()
	if count != 3 {
		t.Errorf("Expected 3 prompts in last minute, got %d", count)
	}
	if !inCooldown {
		t.Error("Should be in cooldown after exceeding limit")
	}

	// Wait for cooldown to expire
	time.Sleep(150 * time.Millisecond)

	// After cooldown, we're still within the 1-minute window with 3 entries,
	// so we can't add more until those expire. This is correct behavior.
	// Let's manually age the entries for this test.
	p.mu.Lock()
	for i := range p.promptTimes {
		p.promptTimes[i] = time.Now().Add(-2 * time.Minute) // Age them out
	}
	p.mu.Unlock()

	// Should be allowed again after cooldown and entries expired
	if !p.checkRateLimit("tool_after_cooldown") {
		t.Error("Request should be allowed after cooldown and entries expired")
	}
}

// TestRateLimitCooldown tests that cooldown period works correctly.
func TestRateLimitCooldown(t *testing.T) {
	cfg := &PrompterConfig{
		MaxPromptsPerMinute: 2,
		CooldownDuration:    200 * time.Millisecond,
	}
	p := NewPrompter(cfg)

	// Exhaust the limit
	p.checkRateLimit("tool1")
	p.checkRateLimit("tool2")
	p.checkRateLimit("tool3") // This triggers cooldown

	// Immediate request should be blocked
	if p.checkRateLimit("tool4") {
		t.Error("Should be blocked during cooldown")
	}

	// Check cooldown status
	_, inCooldown, remaining := p.GetRateLimitStatus()
	if !inCooldown {
		t.Error("Should be in cooldown")
	}
	if remaining > 200*time.Millisecond || remaining < 0 {
		t.Errorf("Cooldown remaining %v out of expected range", remaining)
	}

	// Wait for cooldown
	time.Sleep(250 * time.Millisecond)

	// Should be allowed now
	_, inCooldown, _ = p.GetRateLimitStatus()
	if inCooldown {
		t.Error("Should not be in cooldown after waiting")
	}
}

// TestRateLimitReset tests the ResetRateLimit method.
func TestRateLimitReset(t *testing.T) {
	cfg := &PrompterConfig{
		MaxPromptsPerMinute: 2,
		CooldownDuration:    1 * time.Hour, // Long cooldown
	}
	p := NewPrompter(cfg)

	// Exhaust limit and trigger cooldown
	p.checkRateLimit("tool1")
	p.checkRateLimit("tool2")
	p.checkRateLimit("tool3")

	count, inCooldown, _ := p.GetRateLimitStatus()
	if count == 0 || !inCooldown {
		t.Error("Should have prompts recorded and be in cooldown")
	}

	// Reset
	p.ResetRateLimit()

	count, inCooldown, _ = p.GetRateLimitStatus()
	if count != 0 {
		t.Errorf("After reset, count should be 0, got %d", count)
	}
	if inCooldown {
		t.Error("After reset, should not be in cooldown")
	}

	// Should be able to prompt again
	if !p.checkRateLimit("tool_after_reset") {
		t.Error("Should be allowed after reset")
	}
}

// TestRateLimitOldEntriesExpire tests that old prompt records are cleaned up.
func TestRateLimitOldEntriesExpire(t *testing.T) {
	cfg := &PrompterConfig{
		MaxPromptsPerMinute: 100, // High limit so we don't trigger cooldown
		CooldownDuration:    1 * time.Hour,
	}
	p := NewPrompter(cfg)

	// Add some prompts
	p.checkRateLimit("tool1")
	p.checkRateLimit("tool2")

	count1, _, _ := p.GetRateLimitStatus()

	// Manually age the entries (for testing without waiting a minute)
	p.mu.Lock()
	for i := range p.promptTimes {
		p.promptTimes[i] = time.Now().Add(-2 * time.Minute) // 2 minutes ago
	}
	p.mu.Unlock()

	// The old entries should be cleaned up on next check
	p.checkRateLimit("tool3")

	count2, _, _ := p.GetRateLimitStatus()
	if count2 >= count1 {
		t.Errorf("Old entries should have been cleaned up. Before: %d, After: %d", count1, count2)
	}
}

// TestRateLimitFatigueAttackSimulation simulates an approval fatigue attack.
// This is the key security test for this feature.
func TestRateLimitFatigueAttackSimulation(t *testing.T) {
	cfg := &PrompterConfig{
		MaxPromptsPerMinute: 5,
		CooldownDuration:    100 * time.Millisecond,
	}
	p := NewPrompter(cfg)

	var warnings []string
	p.SetLogger(func(format string, args ...any) {
		warnings = append(warnings, fmt.Sprintf(format, args...))
	})

	// Simulate rapid-fire approval requests (fatigue attack pattern)
	allowed := 0
	blocked := 0
	for i := 0; i < 20; i++ {
		if p.checkRateLimit(fmt.Sprintf("malicious_tool_%d", i)) {
			allowed++
		} else {
			blocked++
		}
	}

	// CRITICAL SECURITY CHECK:
	// Only the first 5 should have been allowed
	if allowed != 5 {
		t.Errorf("SECURITY: Expected exactly 5 prompts allowed, got %d", allowed)
	}
	if blocked != 15 {
		t.Errorf("SECURITY: Expected 15 prompts blocked, got %d", blocked)
	}

	// Verify security warning was logged
	foundSecurityWarning := false
	for _, w := range warnings {
		if containsSubstring(w, "fatigue attack") {
			foundSecurityWarning = true
			break
		}
	}
	if !foundSecurityWarning {
		t.Error("SECURITY: Expected fatigue attack warning to be logged")
	}
}

// containsString checks if str contains substr.
func containsString(str, substr string) bool {
	return len(str) >= len(substr) && (str == substr || len(substr) == 0 ||
		(len(str) > 0 && containsSubstring(str, substr)))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
