package compliance

import (
	"fmt"

	"github.com/k8s-security-baseline-checker/pkg/core"
)

// ExampleUsage demonstrates how to use the mapping engine with scoring
func ExampleUsage() {
	// Create mapping engine
	engine := NewMappingEngine()

	// Load mappings from directory
	if err := LoadMappingsFromDirectory(engine, "config/mappings/"); err != nil {
		panic(err)
	}

	// Example: Single check result
	checkResult := &core.CheckResult{
		CheckID:  "cis-2.1.1",
		Status:   core.StatusFail,
		Severity: core.SeverityCritical,
		Evidence: []core.Evidence{
			{
				Type:        core.EvidenceTypeResource,
				Source:      "k8s-api",
				Description: "Pod running as root",
				Content: map[string]interface{}{
					"namespace": "default",
					"pod":       "my-pod",
					"runAsUser": 0,
				},
			},
		},
		Findings: []core.Finding{
			{
				ID:          "finding-1",
				Title:       "Pod running as root",
				Description: "Pod 'my-pod' is running as root user",
				Severity:    core.SeverityCritical,
				Resource:    "pod/default/my-pod",
				Remediation: "Set securityContext.runAsNonRoot=true",
			},
		},
		Message: "Found 1 pod running as root",
	}

	// Map single result to multiple frameworks
	frameworkControls := engine.MapResultToFrameworks(checkResult)

	// This single check result maps to:
	// - NIST AC-3 (Access Enforcement)
	// - ISO 27001 A.9.4.2 (Secure log-on procedures)
	// - SOC 2 CC6.1 (Logical Access Security)
	// - CustomOrgSecurity ORG-CRIT-001 (Prevent Root Access)

	fmt.Printf("Check '%s' maps to %d frameworks:\n", checkResult.CheckID, len(frameworkControls))
	for framework, controls := range frameworkControls {
		fmt.Printf("  - %s: %d controls\n", framework, len(controls))
	}

	// Calculate scores for each framework
	for framework, controls := range frameworkControls {
		score, err := engine.CalculateFrameworkScore(framework, controls)
		if err != nil {
			fmt.Printf("Error calculating score for %s: %v\n", framework, err)
			continue
		}

		fmt.Printf("\n%s Compliance Score:\n", framework)
		fmt.Printf("  Score: %.2f%% (Grade: %s)\n", score.Score, score.Grade)
		fmt.Printf("  Total Controls: %d\n", score.TotalControls)
		fmt.Printf("  Compliant: %d\n", score.CompliantControls)
		fmt.Printf("  Non-Compliant: %d\n", score.NonCompliantControls)
		fmt.Printf("  Compliant Status: %v\n", score.Compliant)

		// Show category scores if available
		if len(score.CategoryScores) > 0 {
			fmt.Printf("  Category Scores:\n")
			for category, catScore := range score.CategoryScores {
				fmt.Printf("    - %s: %.2f%% (%d/%d)\n",
					category, catScore.Score, catScore.CompliantControls, catScore.TotalControls)
			}
		}
	}
}

// ExampleManyToManyMapping demonstrates many-to-many relationships
func ExampleManyToManyMapping() {
	engine := NewMappingEngine()

	// Load mappings
	LoadMappingsFromDirectory(engine, "config/mappings/")

	// Example 1: One check maps to multiple controls
	checkID := "cis-2.1.1"
	frameworks := engine.GetFrameworksForControl(checkID)
	fmt.Printf("Check '%s' maps to frameworks: %v\n", checkID, frameworks)
	// Output: Check 'cis-2.1.1' maps to frameworks: [NIST ISO27001 SOC2 CustomOrgSecurity]

	// Example 2: One control maps to multiple checks
	framework := "NIST"
	controls := engine.GetControlsForFramework(framework)
	fmt.Printf("\nFramework '%s' has %d control mappings:\n", framework, len(controls))

	// Find AC-3 which maps to multiple checks
	for _, control := range controls {
		if control.ControlID == "AC-3" {
			fmt.Printf("  Control '%s' (%s) maps to check: %s\n",
				control.ControlID, control.ControlName, control.CheckID)
			// AC-3 maps to: cis-1.1.1, cis-2.1.1, cis-2.1.2
		}
	}
}

// ExampleScoringMethods demonstrates different scoring methods
func ExampleScoringMethods() {
	engine := NewMappingEngine()

	// Create sample controls with different statuses
	controls := []core.ComplianceControl{
		{
			ID:     "AC-3",
			Status: core.ComplianceStatusCompliant,
			Category: "Access Control",
			CheckResults: []*core.CheckResult{
				{Severity: core.SeverityCritical},
			},
		},
		{
			ID:     "AC-6",
			Status: core.ComplianceStatusNonCompliant,
			Category: "Access Control",
			CheckResults: []*core.CheckResult{
				{Severity: core.SeverityHigh},
			},
		},
		{
			ID:     "SC-7",
			Status: core.ComplianceStatusPartial,
			Category: "System and Communications Protection",
			CheckResults: []*core.CheckResult{
				{Severity: core.SeverityMedium},
			},
		},
	}

	// Test weighted average scoring
	metadata := FrameworkMetadata{
		Scoring: ScoringConfig{
			Method:                 ScoringMethodWeightedAverage,
			WeightedByCategory:     true,
			MinimumComplianceScore: 80.0,
			CategoryWeights: map[string]float64{
				"Access Control": 1.5,
			},
		},
	}
	engine.SetFrameworkMetadata("TestFramework", metadata)

	score, _ := engine.CalculateFrameworkScore("TestFramework", controls)
	fmt.Printf("Weighted Average Score: %.2f%%\n", score.Score)

	// Test pass/fail scoring
	metadata.Scoring.Method = ScoringMethodPassFail
	engine.SetFrameworkMetadata("TestFramework", metadata)
	score, _ = engine.CalculateFrameworkScore("TestFramework", controls)
	fmt.Printf("Pass/Fail Score: %.2f%%\n", score.Score)

	// Test severity-weighted scoring
	metadata.Scoring.Method = ScoringMethodSeverityWeighted
	engine.SetFrameworkMetadata("TestFramework", metadata)
	score, _ = engine.CalculateFrameworkScore("TestFramework", controls)
	fmt.Printf("Severity-Weighted Score: %.2f%%\n", score.Score)
}
