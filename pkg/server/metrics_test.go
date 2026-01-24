package server

import (
	"strings"
	"testing"
)

func TestNewMetrics(t *testing.T) {
	m := NewMetrics()

	if m == nil {
		t.Fatal("NewMetrics should not return nil")
	}

	if m.GetRequestsTotal() != 0 {
		t.Errorf("Initial requests should be 0, got %d", m.GetRequestsTotal())
	}
}

func TestMetricsIncrementRequests(t *testing.T) {
	m := NewMetrics()

	m.IncrementRequests()
	if m.GetRequestsTotal() != 1 {
		t.Errorf("After 1 increment, requests should be 1, got %d", m.GetRequestsTotal())
	}

	m.IncrementRequests()
	m.IncrementRequests()
	if m.GetRequestsTotal() != 3 {
		t.Errorf("After 3 increments, requests should be 3, got %d", m.GetRequestsTotal())
	}
}

func TestMetricsIncrementDecision(t *testing.T) {
	m := NewMetrics()

	m.IncrementDecision("allow")
	m.IncrementDecision("allow")
	m.IncrementDecision("block")

	decisions := m.GetDecisionsTotal()

	if decisions["allow"] != 2 {
		t.Errorf("allow count should be 2, got %d", decisions["allow"])
	}
	if decisions["block"] != 1 {
		t.Errorf("block count should be 1, got %d", decisions["block"])
	}
}

func TestMetricsIncrementDecisionUnknown(t *testing.T) {
	m := NewMetrics()

	// Should not panic for unknown decision types
	m.IncrementDecision("unknown_decision")
}

func TestMetricsIncrementViolation(t *testing.T) {
	m := NewMetrics()

	m.IncrementViolation("argument_validation")
	m.IncrementViolation("argument_validation")
	m.IncrementViolation("tool_not_allowed")

	// Verify through Prometheus output
	output := m.Prometheus()

	if !strings.Contains(output, `aip_violations_total{type="argument_validation"}`) {
		t.Error("Prometheus output should contain argument_validation violation")
	}
}

func TestMetricsPrometheus(t *testing.T) {
	m := NewMetrics()

	m.IncrementRequests()
	m.IncrementDecision("allow")

	output := m.Prometheus()

	// Check for HELP comments
	if !strings.Contains(output, "# HELP aip_requests_total") {
		t.Error("Prometheus output should contain HELP for aip_requests_total")
	}
	if !strings.Contains(output, "# TYPE aip_requests_total counter") {
		t.Error("Prometheus output should contain TYPE for aip_requests_total")
	}

	// Check for actual metric
	if !strings.Contains(output, "aip_requests_total 1") {
		t.Error("Prometheus output should show requests_total = 1")
	}

	// Check for decisions
	if !strings.Contains(output, "# HELP aip_decisions_total") {
		t.Error("Prometheus output should contain HELP for aip_decisions_total")
	}
	if !strings.Contains(output, `aip_decisions_total{decision="allow"} 1`) {
		t.Error("Prometheus output should show allow decision = 1")
	}

	// Check for violations
	if !strings.Contains(output, "# HELP aip_violations_total") {
		t.Error("Prometheus output should contain HELP for aip_violations_total")
	}
}

func TestMetricsConcurrency(t *testing.T) {
	m := NewMetrics()

	// Run concurrent increments
	done := make(chan bool, 100)
	for i := 0; i < 100; i++ {
		go func() {
			m.IncrementRequests()
			m.IncrementDecision("allow")
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}

	if m.GetRequestsTotal() != 100 {
		t.Errorf("After 100 concurrent increments, requests should be 100, got %d", m.GetRequestsTotal())
	}

	decisions := m.GetDecisionsTotal()
	if decisions["allow"] != 100 {
		t.Errorf("After 100 concurrent increments, allow should be 100, got %d", decisions["allow"])
	}
}
