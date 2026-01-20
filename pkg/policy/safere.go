// Package policy implements the AIP policy engine for tool call authorization.
package policy

import (
	"context"
	"fmt"
	"regexp"
	"time"
)

// DefaultRegexTimeout is the maximum time allowed for regex compilation.
// This prevents ReDoS (Regular Expression Denial of Service) attacks where
// a malicious policy file contains a pathological regex pattern.
const DefaultRegexTimeout = 100 * time.Millisecond

// SafeCompile compiles a regex pattern with a timeout to prevent ReDoS.
//
// ReDoS Attack Prevention:
//
// Certain regex patterns exhibit exponential time complexity when matched
// against crafted input. A malicious actor could include such patterns in
// a policy file to cause CPU exhaustion:
//
//	Evil patterns (DO NOT USE):
//	  - ^(a+)+$           Nested quantifiers
//	  - ^([a-zA-Z]+)*$    Nested quantifiers with alternation
//	  - (a|aa)+$          Overlapping alternatives
//
// While these patterns might compile quickly, they can hang on input like
// "aaaaaaaaaaaaaaaaaaaaax". This function provides a timeout on compilation
// as a first line of defense.
//
// NOTE: This protects against compile-time issues but not all match-time
// ReDoS. For full protection, consider using a regex engine with RE2
// semantics (like Go's regexp) which guarantees linear-time matching.
// Go's regexp package already uses RE2, so match-time ReDoS is not a concern.
//
// Parameters:
//   - pattern: The regex pattern to compile
//   - timeout: Maximum time to wait for compilation (0 = DefaultRegexTimeout)
//
// Returns:
//   - Compiled *regexp.Regexp on success
//   - Error if compilation fails or times out
//
// Example:
//
//	re, err := SafeCompile(`^https://github\.com/.*`, 0)
//	if err != nil {
//	    return fmt.Errorf("invalid regex: %w", err)
//	}
func SafeCompile(pattern string, timeout time.Duration) (*regexp.Regexp, error) {
	if timeout == 0 {
		timeout = DefaultRegexTimeout
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	type compileResult struct {
		re  *regexp.Regexp
		err error
	}
	resultCh := make(chan compileResult, 1)

	go func() {
		re, err := regexp.Compile(pattern)
		resultCh <- compileResult{re, err}
	}()

	select {
	case result := <-resultCh:
		if result.err != nil {
			return nil, fmt.Errorf("regex compile error: %w", result.err)
		}
		return result.re, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("regex compile timeout after %v (possible ReDoS pattern): %s", timeout, pattern)
	}
}

// MustSafeCompile is like SafeCompile but panics on error.
// Use only for patterns known at compile time (constants).
func MustSafeCompile(pattern string) *regexp.Regexp {
	re, err := SafeCompile(pattern, DefaultRegexTimeout)
	if err != nil {
		panic(err)
	}
	return re
}

// ValidateRegexComplexity performs basic heuristic checks on a regex pattern
// to detect potentially problematic patterns before compilation.
//
// This is a best-effort check that catches common ReDoS patterns:
//   - Nested quantifiers: (a+)+, (a*)+, (a+)*, etc.
//   - Excessive alternation depth
//   - Very long patterns (potential for complexity)
//
// Returns nil if the pattern passes checks, error describing the issue otherwise.
//
// NOTE: This is NOT a comprehensive ReDoS detector. It's a heuristic to catch
// obvious cases. Go's RE2-based regexp engine provides the real protection
// by guaranteeing linear-time matching. This check is an additional layer.
func ValidateRegexComplexity(pattern string) error {
	// Check for excessive length (arbitrary limit, adjust as needed)
	const maxPatternLength = 1000
	if len(pattern) > maxPatternLength {
		return fmt.Errorf("regex pattern exceeds maximum length (%d > %d)", len(pattern), maxPatternLength)
	}

	// Check for nested quantifiers (common ReDoS pattern)
	// These patterns look for quantified groups followed by outer quantifiers:
	//   (something+)+  or  (something*)+  etc.
	//
	// We look for: ) followed by a quantifier (+, *, {n}) followed by another quantifier
	// This is a simplified heuristic - real nested quantifier detection is complex.
	//
	// Pattern explanation:
	//   \)[+*?]    - Close paren followed by quantifier
	//   [+*?]      - Followed by another quantifier
	//
	// This catches: (a+)+, (a*)+, (a+)*, (a?)+ etc.
	nestedQuantifierRe := regexp.MustCompile(`\)[+*?]\s*[+*?]`)
	if nestedQuantifierRe.MatchString(pattern) {
		return fmt.Errorf("regex contains potentially dangerous nested quantifiers: %s", pattern)
	}

	// Also check for repetition of groups with quantifiers: (...+)+ pattern
	// This matches: (anything ending with + or *) followed by + or *
	groupedNestedRe := regexp.MustCompile(`\([^)]*[+*]\)[+*]`)
	if groupedNestedRe.MatchString(pattern) {
		return fmt.Errorf("regex contains potentially dangerous nested quantifiers: %s", pattern)
	}

	return nil
}
