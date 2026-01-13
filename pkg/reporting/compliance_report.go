package reporting

import (
	"time"
)

// ComplianceReport represents a comprehensive compliance report with framework mappings
type ComplianceReport struct {
	// Report metadata
	ID          string    `json:"id"`
	GeneratedAt time.Time `json:"generated_at"`
	Duration    time.Duration `json:"duration"`
	
	// Cluster information
	Cluster ClusterInfo `json:"cluster"`
	
	// Benchmark information
	Benchmark BenchmarkInfo `json:"benchmark"`
	
	// Check results
	CheckResults []CheckResultWithEvidence `json:"check_results"`
	
	// Framework mappings
	FrameworkMappings map[string]FrameworkCompliance `json:"framework_mappings"`
	
	// Risk scoring
	RiskScore RiskScore `json:"risk_score"`
	
	// Overall compliance
	OverallCompliance ComplianceSummary `json:"overall_compliance"`
	
	// Metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// ClusterInfo contains cluster information
type ClusterInfo struct {
	Name       string            `json:"name"`
	K8sVersion string            `json:"k8s_version"`
	Provider   string            `json:"provider"`
	Region     string            `json:"region,omitempty"`
	Nodes      int               `json:"nodes,omitempty"`
	Namespaces []string          `json:"namespaces,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// BenchmarkInfo contains benchmark information
type BenchmarkInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Framework   string `json:"framework"`
	Description string `json:"description,omitempty"`
}

// CheckResultWithEvidence extends check results with evidence
type CheckResultWithEvidence struct {
	// Check information
	CheckID     string   `json:"check_id"`
	CheckName   string   `json:"check_name,omitempty"`
	Category    string   `json:"category,omitempty"`
	
	// Result
	Status      string   `json:"status"` // PASS, FAIL, WARN, ERROR, SKIP
	Severity    string   `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	Message     string   `json:"message"`
	
	// Evidence
	Evidence    []Evidence `json:"evidence"`
	
	// Findings
	Findings    []Finding `json:"findings"`
	
	// Remediation
	Remediation RemediationInfo `json:"remediation"`
	
	// Risk
	RiskScore   float64 `json:"risk_score"`
	
	// Framework mappings
	FrameworkControls []FrameworkControlMapping `json:"framework_controls,omitempty"`
	
	// Timing
	Timestamp time.Time `json:"timestamp"`
	Duration  time.Duration `json:"duration"`
}

// Evidence represents concrete evidence supporting a check result
type Evidence struct {
	Type        string                 `json:"type"` // resource, config, log, query, scan
	Source      string                 `json:"source"`
	Description string                 `json:"description"`
	Content     map[string]interface{} `json:"content"`
	Timestamp   time.Time              `json:"timestamp"`
}

// Finding represents a specific security issue
type Finding struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Resource    string    `json:"resource"`
	EvidenceIDs []string  `json:"evidence_ids,omitempty"` // References to evidence
}

// RemediationInfo contains remediation guidance
type RemediationInfo struct {
	Summary     string   `json:"summary"`
	Steps       []string `json:"steps"`
	Commands    []string `json:"commands,omitempty"`
	References  []string `json:"references,omitempty"`
	Priority    string   `json:"priority"` // IMMEDIATE, HIGH, MEDIUM, LOW
	EstimatedTime string `json:"estimated_time,omitempty"`
}

// FrameworkControlMapping maps a check to compliance framework controls
type FrameworkControlMapping struct {
	Framework     string `json:"framework"`
	ControlID     string `json:"control_id"`
	ControlName   string `json:"control_name"`
	Category      string `json:"category"`
	Status        string `json:"status"` // COMPLIANT, NON_COMPLIANT, PARTIAL
	Weight        float64 `json:"weight"`
}

// FrameworkCompliance represents compliance status for a framework
type FrameworkCompliance struct {
	Framework           string                 `json:"framework"`
	Version             string                 `json:"version"`
	TotalControls       int                    `json:"total_controls"`
	CompliantControls   int                    `json:"compliant_controls"`
	NonCompliantControls int                   `json:"non_compliant_controls"`
	PartialControls     int                    `json:"partial_controls"`
	ComplianceScore     float64                `json:"compliance_score"`
	Grade               string                 `json:"grade"`
	CategoryScores      map[string]CategoryScore `json:"category_scores,omitempty"`
	Controls            []ControlCompliance    `json:"controls,omitempty"`
	Compliant           bool                   `json:"compliant"`
}

// CategoryScore represents score for a category
type CategoryScore struct {
	Category          string  `json:"category"`
	TotalControls     int     `json:"total_controls"`
	CompliantControls int     `json:"compliant_controls"`
	Score             float64 `json:"score"`
}

// ControlCompliance represents compliance status of a control
type ControlCompliance struct {
	ControlID     string    `json:"control_id"`
	ControlName   string    `json:"control_name"`
	Category      string    `json:"category"`
	Status        string    `json:"status"`
	CheckResults  []string  `json:"check_results"` // Check IDs that map to this control
	Evidence      []Evidence `json:"evidence,omitempty"`
	Remediation   RemediationInfo `json:"remediation,omitempty"`
}

// RiskScore represents overall risk assessment
type RiskScore struct {
	OverallScore    float64            `json:"overall_score"` // 0-100, higher = more risk
	RiskLevel       string             `json:"risk_level"` // CRITICAL, HIGH, MEDIUM, LOW, MINIMAL
	SeverityBreakdown map[string]int   `json:"severity_breakdown"` // Count by severity
	CategoryRisks   map[string]float64 `json:"category_risks,omitempty"` // Risk score per category
	TopRisks        []RiskItem         `json:"top_risks"` // Top N risk items
}

// RiskItem represents a specific risk
type RiskItem struct {
	CheckID     string  `json:"check_id"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	RiskScore   float64 `json:"risk_score"`
	Resource    string  `json:"resource,omitempty"`
}

// ComplianceSummary represents overall compliance summary
type ComplianceSummary struct {
	TotalChecks       int     `json:"total_checks"`
	PassedChecks      int     `json:"passed_checks"`
	FailedChecks      int     `json:"failed_checks"`
	WarnedChecks      int     `json:"warned_checks"`
	ErrorChecks       int     `json:"error_checks"`
	SkippedChecks     int     `json:"skipped_checks"`
	ComplianceScore   float64 `json:"compliance_score"` // 0-100
	Grade             string  `json:"grade"` // A+, A, B, C, D, F
	WeightedScore     float64 `json:"weighted_score,omitempty"`
}

// CalculateRiskScore calculates risk score from check results
func CalculateRiskScore(results []CheckResultWithEvidence) RiskScore {
	severityWeights := map[string]float64{
		"CRITICAL": 10.0,
		"HIGH":     7.0,
		"MEDIUM":   4.0,
		"LOW":      2.0,
		"INFO":     0.5,
	}

	severityBreakdown := make(map[string]int)
	var totalRiskScore float64
	var totalWeight float64
	categoryRisks := make(map[string]float64)
	var topRisks []RiskItem

	for _, result := range results {
		if result.Status == "FAIL" || result.Status == "WARN" {
			weight := severityWeights[result.Severity]
			if weight == 0 {
				weight = 1.0
			}

			riskScore := weight * float64(len(result.Findings))
			totalRiskScore += riskScore
			totalWeight += weight

			severityBreakdown[result.Severity]++

			// Category risk
			if result.Category != "" {
				categoryRisks[result.Category] += riskScore
			}

			// Top risks
			for _, finding := range result.Findings {
				topRisks = append(topRisks, RiskItem{
					CheckID:     result.CheckID,
					Description: finding.Description,
					Severity:    finding.Severity,
					RiskScore:   severityWeights[finding.Severity],
					Resource:    finding.Resource,
				})
			}
		}
	}

	// Calculate overall risk score (0-100, higher = more risk)
	var overallScore float64
	if totalWeight > 0 {
		// Normalize to 0-100 scale
		overallScore = (totalRiskScore / totalWeight) * 10
		if overallScore > 100 {
			overallScore = 100
		}
	}

	// Determine risk level
	riskLevel := "MINIMAL"
	if overallScore >= 80 {
		riskLevel = "CRITICAL"
	} else if overallScore >= 60 {
		riskLevel = "HIGH"
	} else if overallScore >= 40 {
		riskLevel = "MEDIUM"
	} else if overallScore >= 20 {
		riskLevel = "LOW"
	}

	// Sort top risks by score (descending)
	// Keep top 10
	if len(topRisks) > 10 {
		topRisks = topRisks[:10]
	}

	return RiskScore{
		OverallScore:      overallScore,
		RiskLevel:         riskLevel,
		SeverityBreakdown: severityBreakdown,
		CategoryRisks:     categoryRisks,
		TopRisks:          topRisks,
	}
}

// CalculateComplianceSummary calculates overall compliance summary
func CalculateComplianceSummary(results []CheckResultWithEvidence) ComplianceSummary {
	total := len(results)
	passed := 0
	failed := 0
	warned := 0
	errors := 0
	skipped := 0
	var totalWeight int
	var passedWeight int

	for _, result := range results {
		weight := 1 // Default weight
		if result.FrameworkControls != nil && len(result.FrameworkControls) > 0 {
			weight = int(result.FrameworkControls[0].Weight)
		}
		totalWeight += weight

		switch result.Status {
		case "PASS":
			passed++
			passedWeight += weight
		case "FAIL":
			failed++
		case "WARN":
			warned++
		case "ERROR":
			errors++
		case "SKIP":
			skipped++
		}
	}

	var complianceScore float64
	if totalWeight > 0 {
		complianceScore = float64(passedWeight) / float64(totalWeight) * 100
	}

	grade := calculateGrade(complianceScore)

	return ComplianceSummary{
		TotalChecks:     total,
		PassedChecks:    passed,
		FailedChecks:    failed,
		WarnedChecks:    warned,
		ErrorChecks:     errors,
		SkippedChecks:   skipped,
		ComplianceScore: complianceScore,
		Grade:           grade,
		WeightedScore:   complianceScore,
	}
}

func calculateGrade(score float64) string {
	switch {
	case score >= 95:
		return "A+"
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}
