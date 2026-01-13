package observability

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// ChecksTotal is the total number of checks executed
	ChecksTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "k8s_checker_checks_total",
			Help: "Total number of checks executed",
		},
		[]string{"status", "check_type"},
	)

	// ChecksDuration tracks check execution duration
	ChecksDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "k8s_checker_checks_duration_seconds",
			Help:    "Duration of check execution in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"check_type"},
	)

	// ReportsGenerated tracks number of reports generated
	ReportsGenerated = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "k8s_checker_reports_generated_total",
			Help: "Total number of reports generated",
		},
		[]string{"format"},
	)

	// ComplianceScore tracks compliance scores
	ComplianceScore = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "k8s_checker_compliance_score",
			Help: "Current compliance score",
		},
		[]string{"cluster", "benchmark"},
	)
)

