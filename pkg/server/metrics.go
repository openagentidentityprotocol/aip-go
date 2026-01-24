package server

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
)

// Metrics collects server metrics for Prometheus export.
type Metrics struct {
	requestsTotal   atomic.Int64
	decisionsTotal  map[string]*atomic.Int64
	violationsTotal map[string]*atomic.Int64

	mu sync.RWMutex
}

// NewMetrics creates a new metrics collector.
func NewMetrics() *Metrics {
	return &Metrics{
		decisionsTotal: map[string]*atomic.Int64{
			"allow":          {},
			"block":          {},
			"ask":            {},
			"rate_limited":   {},
			"protected_path": {},
			"token_required": {},
			"token_invalid":  {},
		},
		violationsTotal: map[string]*atomic.Int64{
			"argument_validation": {},
			"tool_not_allowed":    {},
			"rate_limited":        {},
			"protected_path":      {},
		},
	}
}

// IncrementRequests increments the total request counter.
func (m *Metrics) IncrementRequests() {
	m.requestsTotal.Add(1)
}

// IncrementDecision increments a decision counter.
func (m *Metrics) IncrementDecision(decision string) {
	m.mu.RLock()
	counter, ok := m.decisionsTotal[decision]
	m.mu.RUnlock()

	if ok {
		counter.Add(1)
	}
}

// IncrementViolation increments a violation counter.
func (m *Metrics) IncrementViolation(violationType string) {
	m.mu.RLock()
	counter, ok := m.violationsTotal[violationType]
	m.mu.RUnlock()

	if ok {
		counter.Add(1)
	}
}

// GetRequestsTotal returns the total request count.
func (m *Metrics) GetRequestsTotal() int64 {
	return m.requestsTotal.Load()
}

// GetDecisionsTotal returns decision counts by type.
func (m *Metrics) GetDecisionsTotal() map[string]int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]int64)
	for k, v := range m.decisionsTotal {
		result[k] = v.Load()
	}
	return result
}

// Prometheus returns metrics in Prometheus text format.
func (m *Metrics) Prometheus() string {
	var sb strings.Builder

	// requests_total
	sb.WriteString("# HELP aip_requests_total Total number of validation requests\n")
	sb.WriteString("# TYPE aip_requests_total counter\n")
	sb.WriteString(fmt.Sprintf("aip_requests_total %d\n", m.requestsTotal.Load()))
	sb.WriteString("\n")

	// decisions_total
	sb.WriteString("# HELP aip_decisions_total Total decisions by type\n")
	sb.WriteString("# TYPE aip_decisions_total counter\n")
	m.mu.RLock()
	for decision, counter := range m.decisionsTotal {
		sb.WriteString(fmt.Sprintf("aip_decisions_total{decision=\"%s\"} %d\n", decision, counter.Load()))
	}
	m.mu.RUnlock()
	sb.WriteString("\n")

	// violations_total
	sb.WriteString("# HELP aip_violations_total Total violations by type\n")
	sb.WriteString("# TYPE aip_violations_total counter\n")
	m.mu.RLock()
	for violationType, counter := range m.violationsTotal {
		sb.WriteString(fmt.Sprintf("aip_violations_total{type=\"%s\"} %d\n", violationType, counter.Load()))
	}
	m.mu.RUnlock()

	return sb.String()
}
