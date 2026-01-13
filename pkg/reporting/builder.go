package reporting

import (
	"fmt"
	"time"

	"github.com/k8s-security-baseline-checker/pkg/compliance"
	"github.com/k8s-security-baseline-checker/pkg/core"
	"github.com/k8s-security-baseline-checker/pkg/types"
)

// ReportBuilder builds comprehensive compliance reports
type ReportBuilder struct {
	mappingEngine *compliance.MappingEngine
}

// NewReportBuilder creates a new report builder
func NewReportBuilder(mappingEngine *compliance.MappingEngine) *ReportBuilder {
	return &ReportBuilder{
		mappingEngine: mappingEngine,
	}
}

// BuildComplianceReport builds a comprehensive compliance report from check results
func (b *ReportBuilder) BuildComplianceReport(
	report *types.Report,
	checkMetadata map[string]types.Check, // Check definitions for metadata
) (*ComplianceReport, error) {
	if b.mappingEngine == nil {
		return nil, fmt.Errorf("mapping engine is required")
	}

	// Convert check results with evidence and framework mappings
	checkResults := make([]CheckResultWithEvidence, 0, len(report.Results))
	
	for _, result := range report.Results {
		checkResult, err := b.convertCheckResult(result, checkMetadata[result.CheckID])
		if err != nil {
			return nil, fmt.Errorf("failed to convert check result %s: %w", result.CheckID, err)
		}
		checkResults = append(checkResults, *checkResult)
	}

	// Calculate risk score
	riskScore := CalculateRiskScore(checkResults)

	// Calculate compliance summary
	complianceSummary := CalculateComplianceSummary(checkResults)

	// Build framework mappings
	frameworkMappings, err := b.buildFrameworkMappings(checkResults)
	if err != nil {
		return nil, fmt.Errorf("failed to build framework mappings: %w", err)
	}

	return &ComplianceReport{
		ID:                report.ID,
		GeneratedAt:       report.GeneratedAt,
		Duration:          report.Duration,
		Cluster: ClusterInfo{
			Name:       report.Cluster.Name,
			K8sVersion: report.Cluster.K8sVersion,
			Provider:   report.Cluster.Provider,
			Region:     report.Cluster.Region,
			Nodes:      report.Cluster.Nodes,
			Namespaces: report.Cluster.Namespaces,
			Metadata:   report.Cluster.Metadata,
		},
		Benchmark: BenchmarkInfo{
			ID:          report.Benchmark,
			Name:        report.Benchmark,
			Version:     report.BenchmarkVersion,
			Framework:   report.Benchmark,
		},
		CheckResults:      checkResults,
		FrameworkMappings: frameworkMappings,
		RiskScore:          riskScore,
		OverallCompliance:  complianceSummary,
		Metadata:          report.Metadata,
	}, nil
}

// convertCheckResult converts a types.Result to CheckResultWithEvidence
func (b *ReportBuilder) convertCheckResult(
	result types.Result,
	check types.Check,
) (*CheckResultWithEvidence, error) {
	// Convert evidence from metadata
	evidence := b.extractEvidence(result.Metadata)

	// Convert findings from metadata
	findings := b.extractFindings(result.Metadata, result.CheckID)

	// Build remediation info
	remediation := b.buildRemediationInfo(result, check)

	// Calculate risk score for this check
	riskScore := calculateCheckRiskScore(result.Severity, len(findings))

	// Map to framework controls using mapping engine
	frameworkControls := b.mapToFrameworkControls(result, check)

	return &CheckResultWithEvidence{
		CheckID:           result.CheckID,
		CheckName:         check.Description,
		Category:          check.Category,
		Status:            string(result.Status),
		Severity:          string(result.Severity),
		Message:           result.Message,
		Evidence:          evidence,
		Findings:          findings,
		Remediation:       remediation,
		RiskScore:         riskScore,
		FrameworkControls: frameworkControls,
		Timestamp:         result.Timestamp,
		Duration:         result.Duration,
	}, nil
}

// extractEvidence extracts evidence from result metadata
func (b *ReportBuilder) extractEvidence(metadata map[string]interface{}) []Evidence {
	evidence := []Evidence{}

	if metadata == nil {
		return evidence
	}

	// Try to extract evidence array
	if evData, ok := metadata["evidence"].([]interface{}); ok {
		for _, ev := range evData {
			if evMap, ok := ev.(map[string]interface{}); ok {
				evidence = append(evidence, Evidence{
					Type:        getString(evMap, "type"),
					Source:      getString(evMap, "source"),
					Description: getString(evMap, "description"),
					Content:     getMap(evMap, "content"),
					Timestamp:   time.Now(),
				})
			}
		}
	}

	// Also extract from details if evidence not explicitly provided
	if len(evidence) == 0 {
		// Create evidence from details if available
		if details, ok := metadata["details"].([]interface{}); ok {
			for i, detail := range details {
				evidence = append(evidence, Evidence{
					Type:        "resource",
					Source:      "check_execution",
					Description: fmt.Sprintf("%v", detail),
					Content: map[string]interface{}{
						"detail_index": i,
						"detail":       detail,
					},
					Timestamp: time.Now(),
				})
			}
		}
	}

	return evidence
}

// extractFindings extracts findings from result metadata
func (b *ReportBuilder) extractFindings(metadata map[string]interface{}, checkID string) []Finding {
	findings := []Finding{}

	if metadata == nil {
		return findings
	}

	if findingsData, ok := metadata["findings"].([]interface{}); ok {
		for i, f := range findingsData {
			if fMap, ok := f.(map[string]interface{}); ok {
				findings = append(findings, Finding{
					ID:          fmt.Sprintf("%s-finding-%d", checkID, i),
					Title:       getString(fMap, "title"),
					Description: getString(fMap, "description"),
					Severity:    getString(fMap, "severity"),
					Resource:    getString(fMap, "resource"),
				})
			}
		}
	}

	// If no explicit findings but we have details, create findings from details
	if len(findings) == 0 && metadata["details"] != nil {
		if details, ok := metadata["details"].([]interface{}); ok {
			for i, detail := range details {
				findings = append(findings, Finding{
					ID:          fmt.Sprintf("%s-finding-%d", checkID, i),
					Title:       fmt.Sprintf("Security Issue %d", i+1),
					Description: fmt.Sprintf("%v", detail),
					Severity:    "MEDIUM", // Default severity
					Resource:    getString(metadata, "resource"),
				})
			}
		}
	}

	return findings
}

// buildRemediationInfo builds remediation information
func (b *ReportBuilder) buildRemediationInfo(result types.Result, check types.Check) RemediationInfo {
	remediation := RemediationInfo{
		Summary:  result.Remediation,
		Priority: determinePriority(result.Severity),
	}

	// Use check remediation if result doesn't have one
	if remediation.Summary == "" {
		remediation.Summary = check.Remediation
	}

	// Extract steps from metadata
	if result.Metadata != nil {
		if steps, ok := result.Metadata["remediation_steps"].([]interface{}); ok {
			remediation.Steps = make([]string, 0, len(steps))
			for _, step := range steps {
				remediation.Steps = append(remediation.Steps, fmt.Sprintf("%v", step))
			}
		}

		if commands, ok := result.Metadata["remediation_commands"].([]interface{}); ok {
			remediation.Commands = make([]string, 0, len(commands))
			for _, cmd := range commands {
				remediation.Commands = append(remediation.Commands, fmt.Sprintf("%v", cmd))
			}
		}

		if estimatedTime, ok := result.Metadata["estimated_time"].(string); ok {
			remediation.EstimatedTime = estimatedTime
		}

		if references, ok := result.Metadata["references"].([]interface{}); ok {
			remediation.References = make([]string, 0, len(references))
			for _, ref := range references {
				remediation.References = append(remediation.References, fmt.Sprintf("%v", ref))
			}
		}
	}

	// If no steps extracted, create default step from summary
	if len(remediation.Steps) == 0 && remediation.Summary != "" {
		remediation.Steps = []string{remediation.Summary}
	}

	return remediation
}

// mapToFrameworkControls maps check result to framework controls using mapping engine
func (b *ReportBuilder) mapToFrameworkControls(result types.Result, check types.Check) []FrameworkControlMapping {
	if b.mappingEngine == nil {
		return nil
	}

	// Get mappings directly from engine
	mappings := b.mappingEngine.GetMappingsForCheck(result.CheckID)
	if len(mappings) == 0 {
		return nil
	}

	// Convert to FrameworkControlMapping
	frameworkControls := []FrameworkControlMapping{}
	for _, mapping := range mappings {
		// Determine status based on result status
		status := "COMPLIANT"
		switch result.Status {
		case types.StatusFail:
			status = "NON_COMPLIANT"
		case types.StatusWarn:
			status = "PARTIAL"
		case types.StatusPass:
			status = "COMPLIANT"
		default:
			status = "NOT_APPLICABLE"
		}

		frameworkControls = append(frameworkControls, FrameworkControlMapping{
			Framework:   mapping.Framework,
			ControlID:   mapping.ControlID,
			ControlName: mapping.ControlName,
			Category:    mapping.Category,
			Status:      status,
			Weight:      mapping.Weight,
		})
	}

	return frameworkControls
}

// buildFrameworkMappings builds framework compliance summaries
func (b *ReportBuilder) buildFrameworkMappings(
	checkResults []CheckResultWithEvidence,
) (map[string]FrameworkCompliance, error) {
	if b.mappingEngine == nil {
		return make(map[string]FrameworkCompliance), nil
	}

	frameworkMappings := make(map[string]FrameworkCompliance)

	// Get all frameworks from mapping engine
	frameworks := b.mappingEngine.GetFrameworks()

	for _, framework := range frameworks {
		metadata := b.mappingEngine.GetFrameworkMetadata(framework)
		if metadata.Name == "" {
			continue
		}

		// Collect all controls for this framework
		controls := []ControlCompliance{}
		controlMap := make(map[string]*ControlCompliance)

		// Aggregate controls from check results
		for _, checkResult := range checkResults {
			for _, fc := range checkResult.FrameworkControls {
				if fc.Framework == framework {
					if existing, exists := controlMap[fc.ControlID]; exists {
						// Update existing control
						existing.CheckResults = append(existing.CheckResults, checkResult.CheckID)
						if checkResult.Status == "FAIL" {
							existing.Status = "NON_COMPLIANT"
						} else if checkResult.Status == "WARN" && existing.Status == "COMPLIANT" {
							existing.Status = "PARTIAL"
						}
					} else {
						// Create new control
						control := &ControlCompliance{
							ControlID:    fc.ControlID,
							ControlName:  fc.ControlName,
							Category:     fc.Category,
							Status:       fc.Status,
							CheckResults: []string{checkResult.CheckID},
							Evidence:     checkResult.Evidence,
							Remediation:  checkResult.Remediation,
						}
						controlMap[fc.ControlID] = control
						controls = append(controls, *control)
					}
				}
			}
		}

		// Calculate compliance metrics
		totalControls := len(controls)
		compliantControls := 0
		nonCompliantControls := 0
		partialControls := 0

		for _, control := range controls {
			switch control.Status {
			case "COMPLIANT":
				compliantControls++
			case "NON_COMPLIANT":
				nonCompliantControls++
			case "PARTIAL":
				partialControls++
			}
		}

		// Calculate compliance score
		var complianceScore float64
		if totalControls > 0 {
			complianceScore = float64(compliantControls) / float64(totalControls) * 100
		}

		// Determine if compliant (based on minimum score)
		compliant := complianceScore >= metadata.Scoring.MinimumComplianceScore

		// Calculate category scores
		categoryScores := make(map[string]CategoryScore)
		categoryTotals := make(map[string]int)
		categoryCompliant := make(map[string]int)

		for _, control := range controls {
			categoryTotals[control.Category]++
			if control.Status == "COMPLIANT" {
				categoryCompliant[control.Category]++
			}
		}

		for category, total := range categoryTotals {
			compliant := categoryCompliant[category]
			score := float64(compliant) / float64(total) * 100
			categoryScores[category] = CategoryScore{
				Category:          category,
				TotalControls:     total,
				CompliantControls: compliant,
				Score:             score,
			}
		}

		frameworkMappings[framework] = FrameworkCompliance{
			Framework:             framework,
			Version:                metadata.Version,
			TotalControls:          totalControls,
			CompliantControls:      compliantControls,
			NonCompliantControls:   nonCompliantControls,
			PartialControls:       partialControls,
			ComplianceScore:       complianceScore,
			Grade:                  calculateGrade(complianceScore),
			CategoryScores:         categoryScores,
			Controls:               controls,
			Compliant:              compliant,
		}
	}

	return frameworkMappings, nil
}

// Helper conversion functions

func convertStatus(status types.CheckStatus) core.CheckStatus {
	switch status {
	case types.StatusPass:
		return core.StatusPass
	case types.StatusFail:
		return core.StatusFail
	case types.StatusWarn:
		return core.StatusWarn
	case types.StatusError:
		return core.StatusError
	case types.StatusSkip:
		return core.StatusSkip
	default:
		return core.StatusError
	}
}

func convertSeverity(severity types.Severity) core.SeverityLevel {
	switch severity {
	case types.SeverityCritical:
		return core.SeverityCritical
	case types.SeverityHigh:
		return core.SeverityHigh
	case types.SeverityMedium:
		return core.SeverityMedium
	case types.SeverityLow:
		return core.SeverityLow
	case types.SeverityInfo:
		return core.SeverityInfo
	default:
		return core.SeverityInfo
	}
}


func getString(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		return fmt.Sprintf("%v", val)
	}
	return ""
}

func getMap(m map[string]interface{}, key string) map[string]interface{} {
	if val, ok := m[key].(map[string]interface{}); ok {
		return val
	}
	return make(map[string]interface{})
}

func determinePriority(severity types.Severity) string {
	switch severity {
	case types.SeverityCritical:
		return "IMMEDIATE"
	case types.SeverityHigh:
		return "HIGH"
	case types.SeverityMedium:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func calculateCheckRiskScore(severity types.Severity, findingCount int) float64 {
	severityWeights := map[types.Severity]float64{
		types.SeverityCritical: 10.0,
		types.SeverityHigh:     7.0,
		types.SeverityMedium:   4.0,
		types.SeverityLow:      2.0,
		types.SeverityInfo:     0.5,
	}

	weight := severityWeights[severity]
	if weight == 0 {
		weight = 1.0
	}

	return weight * float64(findingCount)
}
