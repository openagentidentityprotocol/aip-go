package policy

import (
	"testing"
)

func TestNormalizeName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// Basic cases
		{
			name:     "lowercase passthrough",
			input:    "delete_files",
			expected: "delete_files",
		},
		{
			name:     "uppercase to lowercase",
			input:    "DELETE_FILES",
			expected: "delete_files",
		},
		{
			name:     "mixed case",
			input:    "Delete_Files",
			expected: "delete_files",
		},
		{
			name:     "trim whitespace",
			input:    "  delete_files  ",
			expected: "delete_files",
		},

		// Fullwidth Unicode attack vectors
		{
			name:     "fullwidth lowercase",
			input:    "ｄｅｌｅｔｅ",
			expected: "delete",
		},
		{
			name:     "fullwidth with underscore",
			input:    "ｄｅｌｅｔｅ＿ｆｉｌｅｓ",
			expected: "delete_files",
		},
		{
			name:     "fullwidth uppercase",
			input:    "ＤＥＬＥＴＥ",
			expected: "delete",
		},
		{
			name:     "mixed fullwidth and ASCII",
			input:    "deleteｆｉｌｅｓ",
			expected: "deletefiles",
		},

		// Ligatures
		{
			name:     "fi ligature",
			input:    "ﬁle_read",
			expected: "file_read",
		},
		{
			name:     "fl ligature",
			input:    "ﬂag_set",
			expected: "flag_set",
		},
		{
			name:     "ffi ligature",
			input:    "coﬃee",
			expected: "coffiee", // ﬃ expands to "ffi" (3 chars)
		},

		// Superscripts and subscripts
		{
			name:     "superscript 2",
			input:    "tool²",
			expected: "tool2",
		},
		{
			name:     "subscript 1",
			input:    "tool₁",
			expected: "tool1",
		},

		// Zero-width and invisible characters
		{
			name:     "zero-width space",
			input:    "delete\u200Bfiles",
			expected: "deletefiles",
		},
		{
			name:     "zero-width non-joiner",
			input:    "delete\u200Cfiles",
			expected: "deletefiles",
		},
		{
			name:     "byte order mark",
			input:    "\uFEFFdelete_files",
			expected: "delete_files",
		},
		{
			name:     "soft hyphen",
			input:    "delete\u00ADfiles",
			expected: "deletefiles",
		},

		// Path-like inputs (MCP methods)
		{
			name:     "method path",
			input:    "tools/call",
			expected: "tools/call",
		},
		{
			name:     "fullwidth method path",
			input:    "ｔｏｏｌｓ／ｃａｌｌ",
			expected: "tools/call",
		},
		{
			name:     "resources/read attack",
			input:    "ｒｅｓｏｕｒｃｅｓ／ｒｅａｄ",
			expected: "resources/read",
		},

		// Edge cases
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "only whitespace",
			input:    "   ",
			expected: "",
		},
		{
			name:     "numbers unchanged",
			input:    "tool123",
			expected: "tool123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeName(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizeName(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestUnicodeBypassPrevention verifies that Unicode attacks are blocked.
func TestUnicodeBypassPrevention(t *testing.T) {
	policyYAML := `
apiVersion: aip.io/v1alpha1
kind: AgentPolicy
metadata:
  name: unicode-test
spec:
  allowed_tools:
    - delete_files
    - read_file
  denied_methods:
    - resources/read
`
	engine := NewEngine()
	if err := engine.Load([]byte(policyYAML)); err != nil {
		t.Fatalf("Failed to load policy: %v", err)
	}

	// Tool bypass attempts - all should be treated as "delete_files"
	toolAttacks := []struct {
		name    string
		tool    string
		allowed bool
	}{
		{"normal", "delete_files", true},
		{"uppercase", "DELETE_FILES", true},
		{"fullwidth", "ｄｅｌｅｔｅ＿ｆｉｌｅｓ", true},
		{"zero-width space", "delete\u200Bfiles", false}, // becomes "deletefiles", not in list
		{"fi ligature", "ﬁle_read", false},               // becomes "file_read", not in list

		// These should be blocked (not in allowed_tools)
		{"unknown tool", "dangerous_tool", false},
		{"fullwidth unknown", "ｄａｎｇｅｒｏｕｓ", false},
	}

	for _, tt := range toolAttacks {
		t.Run("tool:"+tt.name, func(t *testing.T) {
			decision := engine.IsAllowed(tt.tool, nil)
			if decision.Allowed != tt.allowed {
				t.Errorf("IsAllowed(%q) = %v, want %v (normalized to %q)",
					tt.tool, decision.Allowed, tt.allowed, NormalizeName(tt.tool))
			}
		})
	}

	// Method bypass attempts - resources/read should be denied
	methodAttacks := []struct {
		name    string
		method  string
		allowed bool
	}{
		{"normal tools/call", "tools/call", true},
		{"fullwidth tools/call", "ｔｏｏｌｓ／ｃａｌｌ", true},
		{"resources/read blocked", "resources/read", false},
		{"fullwidth resources/read", "ｒｅｓｏｕｒｃｅｓ／ｒｅａｄ", false},
		{"uppercase resources/read", "RESOURCES/READ", false},
	}

	for _, tt := range methodAttacks {
		t.Run("method:"+tt.name, func(t *testing.T) {
			decision := engine.IsMethodAllowed(tt.method)
			if decision.Allowed != tt.allowed {
				t.Errorf("IsMethodAllowed(%q) = %v, want %v (normalized to %q)",
					tt.method, decision.Allowed, tt.allowed, NormalizeName(tt.method))
			}
		})
	}
}

// TestNormalizeNameConsistency verifies that normalization is consistent.
func TestNormalizeNameConsistency(t *testing.T) {
	// All these should normalize to the same value
	variants := []string{
		"delete_files",
		"DELETE_FILES",
		"Delete_Files",
		"ｄｅｌｅｔｅ＿ｆｉｌｅｓ",
		"  delete_files  ",
	}

	expected := NormalizeName(variants[0])
	for _, v := range variants[1:] {
		result := NormalizeName(v)
		if result != expected {
			t.Errorf("NormalizeName(%q) = %q, expected %q (same as first variant)",
				v, result, expected)
		}
	}
}
