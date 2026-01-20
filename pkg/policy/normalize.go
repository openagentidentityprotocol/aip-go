// Package policy implements the AIP policy engine for tool call authorization.
package policy

import (
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// NormalizeName converts a tool or method name to canonical form for comparison.
//
// This function prevents Unicode-based bypass attacks where an attacker uses
// visually similar characters to evade allowlist checks:
//
//   - Fullwidth characters: ｄｅｌｅｔｅ → delete
//   - Ligatures: ﬁle_read → file_read
//   - Superscripts: tool² → tool2
//   - Zero-width characters: delete\u200Bfiles → deletefiles
//
// Normalization steps:
//  1. NFKC normalization (compatibility decomposition + canonical composition)
//  2. Lowercase conversion
//  3. Whitespace trimming
//  4. Remove non-printable/control characters
//
// Example attacks prevented:
//
//	NormalizeName("ｄｅｌｅｔｅ＿ｆｉｌｅｓ") → "delete_files"
//	NormalizeName("delete\u200Bfiles")    → "deletefiles"
//	NormalizeName("ﬁle_read")             → "file_read"
func NormalizeName(s string) string {
	// Step 1: NFKC normalization
	// NFKC = Compatibility Decomposition, followed by Canonical Composition
	// This converts: ｄ → d, ﬁ → fi, ² → 2, etc.
	normalized := norm.NFKC.String(s)

	// Step 2: Lowercase
	normalized = strings.ToLower(normalized)

	// Step 3: Trim whitespace (including Unicode whitespace)
	normalized = strings.TrimSpace(normalized)

	// Step 4: Remove non-printable and control characters
	// This catches zero-width spaces, BOM, and other invisible chars
	normalized = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) && !unicode.IsControl(r) {
			return r
		}
		return -1 // Remove character
	}, normalized)

	return normalized
}
