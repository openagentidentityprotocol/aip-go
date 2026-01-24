package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ArangoGutierrez/agent-identity-protocol/implementations/go-proxy/pkg/identity"
	"github.com/ArangoGutierrez/agent-identity-protocol/implementations/go-proxy/pkg/policy"
)

// ValidationRequest is the request body for the validation endpoint.
type ValidationRequest struct {
	// Tool is the name of the tool to validate
	Tool string `json:"tool"`

	// Arguments are the tool arguments
	Arguments map[string]any `json:"arguments"`

	// Token is the identity token (optional, can also be in Authorization header)
	Token string `json:"token,omitempty"`
}

// ValidationResponse is the response body for the validation endpoint.
type ValidationResponse struct {
	// Decision is "allow", "block", or "ask"
	Decision string `json:"decision"`

	// Reason is a human-readable explanation
	Reason string `json:"reason,omitempty"`

	// Violations lists any policy violations
	Violations []Violation `json:"violations,omitempty"`

	// TokenStatus contains token validity information
	TokenStatus *TokenStatus `json:"token_status,omitempty"`
}

// Violation represents a policy violation.
type Violation struct {
	// Type is the violation type (e.g., "argument_validation", "protected_path")
	Type string `json:"type"`

	// Field is the field that caused the violation
	Field string `json:"field,omitempty"`

	// Message is a description of the violation
	Message string `json:"message"`
}

// TokenStatus contains token validity information.
type TokenStatus struct {
	// Valid is true if the token is valid
	Valid bool `json:"valid"`

	// ExpiresIn is the number of seconds until expiration
	ExpiresIn int `json:"expires_in,omitempty"`

	// Error contains the error code if validation failed
	Error string `json:"error,omitempty"`
}

// ErrorResponse is an error response body.
type ErrorResponse struct {
	// Error is the error code
	Error string `json:"error"`

	// Message is a human-readable error description
	Message string `json:"message,omitempty"`

	// TokenError is the specific token error (for token_invalid)
	TokenError string `json:"token_error,omitempty"`
}

// HealthResponse is the response body for the health endpoint.
type HealthResponse struct {
	// Status is "healthy", "degraded", or "unhealthy"
	Status string `json:"status"`

	// Version is the AIP version
	Version string `json:"version"`

	// PolicyHash is the current policy hash
	PolicyHash string `json:"policy_hash,omitempty"`

	// UptimeSeconds is the server uptime
	UptimeSeconds int64 `json:"uptime_seconds"`
}

// Handler handles HTTP requests for the AIP server.
type Handler struct {
	engine          *policy.Engine
	identityManager *identity.Manager
	startTime       time.Time
	metrics         *Metrics
}

// NewHandler creates a new HTTP handler.
func NewHandler(engine *policy.Engine, identityManager *identity.Manager) *Handler {
	return &Handler{
		engine:          engine,
		identityManager: identityManager,
		startTime:       time.Now(),
		metrics:         NewMetrics(),
	}
}

// HandleValidate handles POST requests to the validation endpoint.
func (h *Handler) HandleValidate(w http.ResponseWriter, r *http.Request) {
	h.metrics.IncrementRequests()

	// Only accept POST
	if r.Method != http.MethodPost {
		h.sendError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only POST is allowed", "")
		return
	}

	// Parse request body
	var req ValidationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, http.StatusBadRequest, "invalid_request", "Invalid JSON body", "")
		return
	}

	// Validate required fields
	if req.Tool == "" {
		h.sendError(w, http.StatusBadRequest, "invalid_request", "Missing required field: tool", "")
		return
	}

	// Extract token from Authorization header or request body
	token := req.Token
	if token == "" {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		}
	}

	// Check if token is required
	if h.identityManager != nil && h.identityManager.RequiresToken() && token == "" {
		h.metrics.IncrementDecision("token_required")
		h.sendError(w, http.StatusUnauthorized, "token_required", "Identity token is required", "")
		return
	}

	// Validate token if provided
	var tokenStatus *TokenStatus
	if token != "" && h.identityManager != nil {
		result := h.identityManager.ValidateToken(token)
		tokenStatus = &TokenStatus{
			Valid:     result.Valid,
			ExpiresIn: result.ExpiresIn,
			Error:     result.Error,
		}

		if !result.Valid && h.identityManager.RequiresToken() {
			h.metrics.IncrementDecision("token_invalid")
			h.sendError(w, http.StatusUnauthorized, "token_invalid", "Token validation failed", result.Error)
			return
		}
	}

	// Evaluate policy
	decision := h.engine.IsAllowed(req.Tool, req.Arguments)

	// Build response
	resp := ValidationResponse{
		TokenStatus: tokenStatus,
	}

	switch decision.Action {
	case policy.ActionAllow:
		resp.Decision = "allow"
		resp.Reason = decision.Reason
		h.metrics.IncrementDecision("allow")

	case policy.ActionBlock:
		resp.Decision = "block"
		resp.Reason = decision.Reason
		h.metrics.IncrementDecision("block")

		// Add violation details
		if decision.FailedArg != "" {
			resp.Violations = append(resp.Violations, Violation{
				Type:    "argument_validation",
				Field:   decision.FailedArg,
				Message: "Value does not match pattern: " + decision.FailedRule,
			})
		} else {
			resp.Violations = append(resp.Violations, Violation{
				Type:    "tool_not_allowed",
				Message: decision.Reason,
			})
		}

	case policy.ActionAsk:
		resp.Decision = "ask"
		resp.Reason = "Tool requires user approval"
		h.metrics.IncrementDecision("ask")

	case policy.ActionRateLimited:
		resp.Decision = "block"
		resp.Reason = decision.Reason
		h.metrics.IncrementDecision("rate_limited")
		resp.Violations = append(resp.Violations, Violation{
			Type:    "rate_limited",
			Message: decision.Reason,
		})
		// Return 429 for rate limiting
		h.sendJSON(w, http.StatusTooManyRequests, resp)
		return

	case policy.ActionProtectedPath:
		resp.Decision = "block"
		resp.Reason = "Access to protected path blocked"
		h.metrics.IncrementDecision("protected_path")
		resp.Violations = append(resp.Violations, Violation{
			Type:  "protected_path",
			Field: "path",
		})
	}

	h.sendJSON(w, http.StatusOK, resp)
}

// HandleHealth handles GET requests to the health endpoint.
func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.sendError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET is allowed", "")
		return
	}

	policyHash := ""
	if h.identityManager != nil {
		policyHash = h.identityManager.GetPolicyHash()
	}

	resp := HealthResponse{
		Status:        "healthy",
		Version:       "v1alpha2",
		PolicyHash:    policyHash,
		UptimeSeconds: int64(time.Since(h.startTime).Seconds()),
	}

	h.sendJSON(w, http.StatusOK, resp)
}

// HandleMetrics handles GET requests to the metrics endpoint.
func (h *Handler) HandleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.sendError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET is allowed", "")
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(h.metrics.Prometheus()))
}

// sendJSON sends a JSON response.
func (h *Handler) sendJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// sendError sends an error response.
func (h *Handler) sendError(w http.ResponseWriter, status int, errorCode, message, tokenError string) {
	resp := ErrorResponse{
		Error:      errorCode,
		Message:    message,
		TokenError: tokenError,
	}
	h.sendJSON(w, status, resp)
}
