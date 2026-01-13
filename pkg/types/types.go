package types

import (
	"time"
)

// CheckStatus represents the status of a check execution
type CheckStatus string

const (
	StatusPass  CheckStatus = "PASS"
	StatusFail  CheckStatus = "FAIL"
	StatusWarn  CheckStatus = "WARN"
	StatusError CheckStatus = "ERROR"
	StatusSkip  CheckStatus = "SKIP"
)

// Severity represents the severity level of a check
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Check represents a security check definition
type Check struct {
	ID          string   `json:"id" yaml:"id"`
	Description string   `json:"description" yaml:"description"`
	Severity    Severity `json:"severity" yaml:"severity"`
	Type        string   `json:"type" yaml:"type"`
	Weight      int      `json:"weight" yaml:"weight"` // Weight for scoring (default: 1)
	Remediation string   `json:"remediation" yaml:"remediation"`
	Category    string   `json:"category,omitempty" yaml:"category,omitempty"`
	Framework   string   `json:"framework,omitempty" yaml:"framework,omitempty"` // CIS, NIST, Custom, etc.
	Version     string   `json:"version,omitempty" yaml:"version,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// Result represents the result of executing a check
type Result struct {
	CheckID     string                 `json:"check_id"`
	Status      CheckStatus            `json:"status"`
	Details     []string               `json:"details"` // Resource names, error messages, etc.
	Remediation string                 `json:"remediation"`
	Weight      int                    `json:"weight"`
	Severity    Severity               `json:"severity"`
	Message     string                 `json:"message,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	Duration    time.Duration          `json:"duration,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	// Enterprise requirement: Standardize evidence for every check result
	Evidence    []CheckEvidence       `json:"evidence,omitempty"`
}

// CheckEvidence represents standardized evidence for a check result
// Enterprise requirement: Evidence includes timestamp, data source, object reference, sanitized raw value, evaluation logic
type CheckEvidence struct {
	// Timestamp when evidence was collected
	Timestamp time.Time `json:"timestamp"`
	
	// DataSource identifies where the evidence came from (API, config file, runtime check, etc.)
	DataSource string `json:"data_source"`
	
	// ObjectReference identifies the Kubernetes object (e.g., "pod/default/my-pod")
	ObjectReference string `json:"object_reference,omitempty"`
	
	// RawValue contains the sanitized raw value (secrets redacted)
	RawValue map[string]interface{} `json:"raw_value,omitempty"`
	
	// EvaluationLogic describes how the evidence was evaluated
	EvaluationLogic string `json:"evaluation_logic,omitempty"`
	
	// Type indicates the type of evidence (resource, config, log, query, scan)
	Type string `json:"type"`
	
	// Description explains what this evidence shows
	Description string `json:"description"`
}

// ClusterInfo represents information about the cluster being checked
type ClusterInfo struct {
	K8sVersion   string            `json:"k8s_version,omitempty"`
	Provider     string            `json:"provider,omitempty"` // aws, azure, gcp, on-prem
	Region       string            `json:"region,omitempty"`
	Name         string            `json:"name,omitempty"`
	Nodes        int               `json:"nodes,omitempty"`
	Namespaces   []string          `json:"namespaces,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// Report represents the overall security compliance report
type Report struct {
	ID              string                 `json:"id"`
	Cluster         ClusterInfo            `json:"cluster"`
	ComplianceScore int                    `json:"compliance_score"` // 0-100
	Grade           string                 `json:"grade"`            // A+, A, B, C, D, F
	TotalChecks     int                    `json:"total_checks"`
	PassedChecks    int                    `json:"passed_checks"`
	FailedChecks    int                    `json:"failed_checks"`
	WarnedChecks    int                    `json:"warned_checks"`
	Results         []Result               `json:"results"`
	Benchmark       string                 `json:"benchmark,omitempty"` // CIS, NIST, Custom
	BenchmarkVersion string                `json:"benchmark_version,omitempty"`
	GeneratedAt     time.Time              `json:"generated_at"`
	Duration        time.Duration          `json:"duration"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// Benchmark represents a benchmark framework definition
type Benchmark struct {
	ID          string            `json:"id" yaml:"id"`
	Name        string            `json:"name" yaml:"name"`
	Version     string            `json:"version" yaml:"version"`
	Description string            `json:"description" yaml:"description"`
	Framework   string            `json:"framework" yaml:"framework"` // CIS, NIST, Custom
	Checks      []Check           `json:"checks" yaml:"checks"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// CalculateGrade calculates the letter grade based on compliance score
func CalculateGrade(score int) string {
	switch {
	case score >= 90:
		return "A+"
	case score >= 80:
		return "A"
	case score >= 70:
		return "B"
	case score >= 60:
		return "C"
	case score >= 50:
		return "D"
	default:
		return "F"
	}
}

// CalculateComplianceScore calculates the compliance score from results
// Enterprise requirement: Make scoring deterministic and handle PASS/FAIL/WARN/NOT_APPLICABLE explicitly
//
// Scoring Logic:
// - PASS: Full weight counted toward compliance
// - FAIL: No weight counted toward compliance
// - WARN: Half weight counted toward compliance (partial compliance)
// - ERROR: No weight counted (treated as FAIL)
// - SKIP/NOT_APPLICABLE: Excluded from calculation (weight not counted in total)
//
// Formula: score = (passed_weight + (warn_weight * 0.5)) / total_applicable_weight * 100
func CalculateComplianceScore(results []Result) int {
	if len(results) == 0 {
		return 0
	}

	var totalApplicableWeight int
	var passedWeight int
	var warnWeight int

	for _, result := range results {
		// Skip NOT_APPLICABLE results (they don't count toward score)
		if result.Status == StatusSkip {
			continue
		}

		weight := result.Weight
		if weight == 0 {
			weight = 1 // Default weight
		}

		totalApplicableWeight += weight

		switch result.Status {
		case StatusPass:
			passedWeight += weight
		case StatusWarn:
			// WARN counts as half compliance
			warnWeight += weight
		case StatusFail, StatusError:
			// FAIL and ERROR count as zero compliance
			// No weight added
		}
	}

	if totalApplicableWeight == 0 {
		return 0
	}

	// Calculate score: (passed + warn*0.5) / total * 100
	compliantWeight := passedWeight + (warnWeight / 2)
	score := (compliantWeight * 100) / totalApplicableWeight

	return score
}

