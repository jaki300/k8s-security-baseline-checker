package compliance

import (
	"fmt"
	"sync"

	"github.com/k8s-security-baseline-checker/pkg/core"
)

// MappingEngine handles many-to-many mappings between controls and compliance frameworks
type MappingEngine struct {
	// controlToFrameworks maps control ID -> []framework mappings
	controlToFrameworks map[string][]FrameworkMapping

	// frameworkToControls maps framework -> []control mappings
	frameworkToControls map[string][]FrameworkControlMapping

	// frameworkMetadata stores framework information
	frameworkMetadata map[string]FrameworkMetadata

	mu sync.RWMutex
}

// FrameworkMapping represents how a control maps to a framework
type FrameworkMapping struct {
	Framework     string
	ControlID     string
	ControlName   string
	Category      string
	Weight        float64 // Weight for scoring (default 1.0)
	MappingRule   MappingRule
	Description   string
}

// FrameworkControlMapping represents how a framework control maps to checks
type FrameworkControlMapping struct {
	ControlID     string
	ControlName   string
	Category      string
	CheckID       string
	Weight        float64
	MappingRule   MappingRule
	Description   string
}

// FrameworkMetadata contains metadata about a framework
type FrameworkMetadata struct {
	Name        string
	Version     string
	Description string
	Scoring     ScoringConfig
}

// ScoringConfig defines how scores are calculated for a framework
type ScoringConfig struct {
	// Method defines the scoring method
	Method ScoringMethod

	// WeightedByCategory if true, weights are applied per category
	WeightedByCategory bool

	// MinimumComplianceScore is the minimum score to be considered compliant
	MinimumComplianceScore float64

	// CategoryWeights defines weights per category
	CategoryWeights map[string]float64
}

// ScoringMethod defines how compliance scores are calculated
type ScoringMethod string

const (
	// ScoringMethodWeightedAverage calculates weighted average
	ScoringMethodWeightedAverage ScoringMethod = "weighted_average"

	// ScoringMethodPassFail counts pass/fail only
	ScoringMethodPassFail ScoringMethod = "pass_fail"

	// ScoringMethodSeverityWeighted weights by severity
	ScoringMethodSeverityWeighted ScoringMethod = "severity_weighted"
)

// NewMappingEngine creates a new mapping engine
func NewMappingEngine() *MappingEngine {
	return &MappingEngine{
		controlToFrameworks: make(map[string][]FrameworkMapping),
		frameworkToControls:  make(map[string][]FrameworkControlMapping),
		frameworkMetadata:    make(map[string]FrameworkMetadata),
	}
}

// ValidationError represents a mapping validation error
type ValidationError struct {
	Framework string
	ControlID string
	CheckID   string
	Message   string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error for framework %s, control %s, check %s: %s", 
		e.Framework, e.ControlID, e.CheckID, e.Message)
}

// ValidateMappings validates all framework mappings at startup
// Enterprise requirement: Validate framework mappings at startup, ensure all referenced controls exist
func (e *MappingEngine) ValidateMappings() []error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var errors []error

	// Validate that all control mappings reference valid check IDs
	for checkID, mappings := range e.controlToFrameworks {
		if checkID == "" {
			errors = append(errors, &ValidationError{
				CheckID: checkID,
				Message: "empty check ID in mapping",
			})
			continue
		}

		for _, mapping := range mappings {
			if mapping.ControlID == "" {
				errors = append(errors, &ValidationError{
					Framework: mapping.Framework,
					CheckID:   checkID,
					Message:   "empty control ID in mapping",
				})
			}

			if mapping.Framework == "" {
				errors = append(errors, &ValidationError{
					ControlID: mapping.ControlID,
					CheckID:   checkID,
					Message:   "empty framework name in mapping",
				})
			}
		}
	}

	// Validate that all framework controls have valid metadata
	for framework, controls := range e.frameworkToControls {
		metadata, exists := e.frameworkMetadata[framework]
		if !exists {
			errors = append(errors, &ValidationError{
				Framework: framework,
				Message:   fmt.Sprintf("framework metadata missing for %s", framework),
			})
			continue
		}

		// Validate metadata
		if metadata.Name == "" {
			errors = append(errors, &ValidationError{
				Framework: framework,
				Message:   "framework name missing in metadata",
			})
		}

		if metadata.Version == "" {
			errors = append(errors, &ValidationError{
				Framework: framework,
				Message:   "framework version missing in metadata",
			})
		}

		// Validate control IDs are unique within framework
		controlIDs := make(map[string]bool)
		for _, control := range controls {
			if controlIDs[control.ControlID] {
				errors = append(errors, &ValidationError{
					Framework: framework,
					ControlID: control.ControlID,
					Message:   fmt.Sprintf("duplicate control ID %s in framework", control.ControlID),
				})
			}
			controlIDs[control.ControlID] = true
		}
	}

	return errors
}

// LoadMappingsFromFile loads mappings from a YAML file (deprecated, use LoadMappingsIntoEngine)
func (e *MappingEngine) LoadMappingsFromFile(filePath string) error {
	return LoadMappingsIntoEngine(e, filePath)
}

// AddMapping adds a mapping between a check and a framework control
func (e *MappingEngine) AddMapping(checkID string, mapping FrameworkMapping) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.controlToFrameworks[checkID] = append(e.controlToFrameworks[checkID], mapping)

	// Also build reverse index
	controlMapping := FrameworkControlMapping{
		ControlID:   mapping.ControlID,
		ControlName: mapping.ControlName,
		Category:    mapping.Category,
		CheckID:     checkID,
		Weight:      mapping.Weight,
		MappingRule: mapping.MappingRule,
		Description: mapping.Description,
	}
	e.frameworkToControls[mapping.Framework] = append(
		e.frameworkToControls[mapping.Framework],
		controlMapping,
	)
}

// SetFrameworkMetadata sets metadata for a framework
func (e *MappingEngine) SetFrameworkMetadata(framework string, metadata FrameworkMetadata) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.frameworkMetadata[framework] = metadata
}

// MapResultToFrameworks maps a single check result to all applicable frameworks
func (e *MappingEngine) MapResultToFrameworks(result *core.CheckResult) map[string][]core.ComplianceControl {
	e.mu.RLock()
	defer e.mu.RUnlock()

	frameworkControls := make(map[string][]core.ComplianceControl)

	mappings, exists := e.controlToFrameworks[result.CheckID]
	if !exists {
		return frameworkControls
	}

	for _, mapping := range mappings {
		control := e.mapResultToControl(result, mapping)
		frameworkControls[mapping.Framework] = append(frameworkControls[mapping.Framework], control)
	}

	return frameworkControls
}

// mapResultToControl maps a check result to a compliance control
func (e *MappingEngine) mapResultToControl(result *core.CheckResult, mapping FrameworkMapping) core.ComplianceControl {
	control := core.ComplianceControl{
		ID:          mapping.ControlID,
		Name:        mapping.ControlName,
		Description: mapping.Description,
		Category:    mapping.Category,
		CheckResults: []*core.CheckResult{result},
		Evidence:     result.Evidence,
	}

	// Determine compliance status based on check result and mapping rule
	switch result.Status {
	case core.StatusPass:
		control.Status = mapping.MappingRule.PassStatus
	case core.StatusFail:
		control.Status = mapping.MappingRule.FailStatus
	case core.StatusWarn:
		control.Status = mapping.MappingRule.WarnStatus
	case core.StatusError:
		control.Status = core.ComplianceStatusNotApplicable
	case core.StatusSkip:
		control.Status = core.ComplianceStatusNotApplicable
	default:
		control.Status = core.ComplianceStatusNotApplicable
	}

	return control
}

// CalculateFrameworkScore calculates compliance score for a framework
func (e *MappingEngine) CalculateFrameworkScore(
	framework string,
	controls []core.ComplianceControl,
) (*FrameworkScore, error) {
	e.mu.RLock()
	metadata, exists := e.frameworkMetadata[framework]
	e.mu.RUnlock()

	if !exists {
		// Use default scoring config
		metadata = FrameworkMetadata{
			Scoring: ScoringConfig{
				Method:                 ScoringMethodWeightedAverage,
				WeightedByCategory:     false,
				MinimumComplianceScore: 80.0,
			},
		}
	}

	scoring := metadata.Scoring

	switch scoring.Method {
	case ScoringMethodWeightedAverage:
		return e.calculateWeightedAverageScore(framework, controls, scoring)
	case ScoringMethodPassFail:
		return e.calculatePassFailScore(framework, controls)
	case ScoringMethodSeverityWeighted:
		return e.calculateSeverityWeightedScore(framework, controls, scoring)
	default:
		return e.calculateWeightedAverageScore(framework, controls, scoring)
	}
}

// FrameworkScore represents a compliance score for a framework
type FrameworkScore struct {
	Framework           string
	TotalControls       int
	CompliantControls   int
	NonCompliantControls int
	PartialControls     int
	NotApplicableControls int
	Score               float64
	Grade               string
	CategoryScores      map[string]CategoryScore
	Compliant           bool
}

// CategoryScore represents score for a category
type CategoryScore struct {
	Category            string
	TotalControls       int
	CompliantControls   int
	Score               float64
}

// calculateWeightedAverageScore calculates weighted average compliance score
func (e *MappingEngine) calculateWeightedAverageScore(
	framework string,
	controls []core.ComplianceControl,
	config ScoringConfig,
) (*FrameworkScore, error) {
	e.mu.RLock()
	controlMappings := e.frameworkToControls[framework]
	e.mu.RUnlock()

	// Build weight map
	weightMap := make(map[string]float64)
	for _, mapping := range controlMappings {
		weight := mapping.Weight
		if weight == 0 {
			weight = 1.0 // Default weight
		}
		weightMap[mapping.ControlID] = weight
	}

	var totalWeight float64
	var compliantWeight float64
	var partialWeight float64

	categoryCompliant := make(map[string]float64)
	categoryTotal := make(map[string]float64)

	compliantCount := 0
	nonCompliantCount := 0
	partialCount := 0
	notApplicableCount := 0

	for _, control := range controls {
		weight := weightMap[control.ID]
		if weight == 0 {
			weight = 1.0
		}

		// Apply category weight if configured
		if config.WeightedByCategory && len(config.CategoryWeights) > 0 {
			if catWeight, exists := config.CategoryWeights[control.Category]; exists {
				weight *= catWeight
			}
		}

		totalWeight += weight
		categoryTotal[control.Category] += weight

		switch control.Status {
		case core.ComplianceStatusCompliant:
			compliantWeight += weight
			categoryCompliant[control.Category] += weight
			compliantCount++
		case core.ComplianceStatusNonCompliant:
			nonCompliantCount++
		case core.ComplianceStatusPartial:
			partialWeight += weight * 0.5 // Partial counts as half
			categoryCompliant[control.Category] += weight * 0.5
			partialCount++
		case core.ComplianceStatusNotApplicable:
			notApplicableCount++
		}
	}

	var score float64
	if totalWeight > 0 {
		score = (compliantWeight + partialWeight) / totalWeight * 100
	}

	// Calculate category scores
	categoryScores := make(map[string]CategoryScore)
	for category, total := range categoryTotal {
		var catScore float64
		if total > 0 {
			catScore = categoryCompliant[category] / total * 100
		}
		categoryScores[category] = CategoryScore{
			Category:      category,
			TotalControls: int(total),
			CompliantControls: int(categoryCompliant[category]),
			Score:         catScore,
		}
	}

	grade := calculateGrade(score)
	compliant := score >= config.MinimumComplianceScore

	return &FrameworkScore{
		Framework:             framework,
		TotalControls:         len(controls),
		CompliantControls:     compliantCount,
		NonCompliantControls:   nonCompliantCount,
		PartialControls:       partialCount,
		NotApplicableControls:  notApplicableCount,
		Score:                 score,
		Grade:                 grade,
		CategoryScores:        categoryScores,
		Compliant:             compliant,
	}, nil
}

// calculatePassFailScore calculates simple pass/fail score
func (e *MappingEngine) calculatePassFailScore(
	framework string,
	controls []core.ComplianceControl,
) (*FrameworkScore, error) {
	compliantCount := 0
	nonCompliantCount := 0
	partialCount := 0
	notApplicableCount := 0

	for _, control := range controls {
		switch control.Status {
		case core.ComplianceStatusCompliant:
			compliantCount++
		case core.ComplianceStatusNonCompliant:
			nonCompliantCount++
		case core.ComplianceStatusPartial:
			partialCount++
		case core.ComplianceStatusNotApplicable:
			notApplicableCount++
		}
	}

	totalApplicable := len(controls) - notApplicableCount
	var score float64
	if totalApplicable > 0 {
		score = float64(compliantCount) / float64(totalApplicable) * 100
	}

	grade := calculateGrade(score)

	return &FrameworkScore{
		Framework:            framework,
		TotalControls:        len(controls),
		CompliantControls:    compliantCount,
		NonCompliantControls: nonCompliantCount,
		PartialControls:      partialCount,
		NotApplicableControls: notApplicableCount,
		Score:                score,
		Grade:                grade,
		Compliant:            score >= 80.0,
	}, nil
}

// calculateSeverityWeightedScore calculates score weighted by severity
func (e *MappingEngine) calculateSeverityWeightedScore(
	framework string,
	controls []core.ComplianceControl,
	config ScoringConfig,
) (*FrameworkScore, error) {
	severityWeights := map[core.SeverityLevel]float64{
		core.SeverityCritical: 4.0,
		core.SeverityHigh:      3.0,
		core.SeverityMedium:    2.0,
		core.SeverityLow:       1.0,
		core.SeverityInfo:      0.5,
	}

	var totalWeight float64
	var compliantWeight float64
	var nonCompliantWeight float64

	compliantCount := 0
	nonCompliantCount := 0

	for _, control := range controls {
		if len(control.CheckResults) == 0 {
			continue
		}

		// Use severity from first check result
		severity := control.CheckResults[0].Severity
		weight := severityWeights[severity]
		if weight == 0 {
			weight = 1.0
		}

		totalWeight += weight

		switch control.Status {
		case core.ComplianceStatusCompliant:
			compliantWeight += weight
			compliantCount++
		case core.ComplianceStatusNonCompliant:
			nonCompliantWeight += weight
			nonCompliantCount++
		}
	}

	var score float64
	if totalWeight > 0 {
		score = compliantWeight / totalWeight * 100
	}

	grade := calculateGrade(score)

	return &FrameworkScore{
		Framework:            framework,
		TotalControls:        len(controls),
		CompliantControls:    compliantCount,
		NonCompliantControls: nonCompliantCount,
		Score:                score,
		Grade:                grade,
		Compliant:            score >= config.MinimumComplianceScore,
	}, nil
}

// calculateGrade converts score to letter grade
func calculateGrade(score float64) string {
	switch {
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

// GetFrameworksForControl returns all frameworks that map to a control
func (e *MappingEngine) GetFrameworksForControl(checkID string) []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	mappings, exists := e.controlToFrameworks[checkID]
	if !exists {
		return nil
	}

	frameworks := make([]string, 0, len(mappings))
	seen := make(map[string]bool)
	for _, mapping := range mappings {
		if !seen[mapping.Framework] {
			frameworks = append(frameworks, mapping.Framework)
			seen[mapping.Framework] = true
		}
	}

	return frameworks
}

// GetControlsForFramework returns all controls for a framework
func (e *MappingEngine) GetControlsForFramework(framework string) []FrameworkControlMapping {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.frameworkToControls[framework]
}

// GetMappingsForCheck returns all framework mappings for a check ID
func (e *MappingEngine) GetMappingsForCheck(checkID string) []FrameworkMapping {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.controlToFrameworks[checkID]
}

// GetFrameworks returns all registered frameworks
func (e *MappingEngine) GetFrameworks() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	frameworks := make([]string, 0, len(e.frameworkMetadata))
	for fw := range e.frameworkMetadata {
		frameworks = append(frameworks, fw)
	}
	return frameworks
}

// GetFrameworkMetadata returns metadata for a framework
func (e *MappingEngine) GetFrameworkMetadata(framework string) FrameworkMetadata {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.frameworkMetadata[framework]
}
