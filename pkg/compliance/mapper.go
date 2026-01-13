package compliance

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/k8s-security-baseline-checker/pkg/core"
	"gopkg.in/yaml.v3"
)

// YAMLComplianceMapper implements ComplianceMapper using YAML-based mappings
// This allows adding new compliance frameworks without code changes
type YAMLComplianceMapper struct {
	framework string
	version   string
	mappings  map[string][]ControlMapping
	controls  []core.ComplianceControl
}

// ControlMapping defines how a check maps to compliance controls
type ControlMapping struct {
	// ControlID is the compliance control identifier
	ControlID string `yaml:"control_id"`

	// ControlName is the control name
	ControlName string `yaml:"control_name"`

	// ControlDescription describes the control
	ControlDescription string `yaml:"control_description"`

	// Category is the control category
	Category string `yaml:"category"`

	// CheckID is the check identifier that maps to this control
	CheckID string `yaml:"check_id"`

	// MappingRule defines how the check result maps to compliance status
	MappingRule MappingRule `yaml:"mapping_rule"`
}

// MappingRule defines how check results map to compliance status
type MappingRule struct {
	// PassStatus is the compliance status when check passes
	PassStatus core.ComplianceStatus `yaml:"pass_status"`

	// FailStatus is the compliance status when check fails
	FailStatus core.ComplianceStatus `yaml:"fail_status"`

	// WarnStatus is the compliance status when check warns
	WarnStatus core.ComplianceStatus `yaml:"warn_status"`

	// RequiresEvidence indicates if evidence is required for compliance
	RequiresEvidence bool `yaml:"requires_evidence"`
}

// FrameworkDefinition defines a compliance framework in YAML
type FrameworkDefinition struct {
	Framework string          `yaml:"framework"`
	Version   string          `yaml:"version"`
	Controls  []ControlMapping `yaml:"controls"`
}

// NewYAMLComplianceMapper creates a new YAML-based compliance mapper
func NewYAMLComplianceMapper(mappingFile string) (core.ComplianceMapper, error) {
	data, err := os.ReadFile(mappingFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read mapping file: %w", err)
	}

	var def FrameworkDefinition
	if err := yaml.Unmarshal(data, &def); err != nil {
		return nil, fmt.Errorf("failed to parse mapping file: %w", err)
	}

	mapper := &YAMLComplianceMapper{
		framework: def.Framework,
		version:   def.Version,
		mappings:  make(map[string][]ControlMapping),
		controls:  make([]core.ComplianceControl, 0),
	}

	// Build mappings index by check ID
	for _, control := range def.Controls {
		mapper.mappings[control.CheckID] = append(mapper.mappings[control.CheckID], control)

		// Build controls list
		mapper.controls = append(mapper.controls, core.ComplianceControl{
			ID:          control.ControlID,
			Name:        control.ControlName,
			Description: control.ControlDescription,
			Category:    control.Category,
			Status:      core.ComplianceStatusNotApplicable,
		})
	}

	return mapper, nil
}

// Framework returns the compliance framework name
func (m *YAMLComplianceMapper) Framework() string {
	return m.framework
}

// Version returns the framework version
func (m *YAMLComplianceMapper) Version() string {
	return m.version
}

// Map maps a check result to compliance controls
func (m *YAMLComplianceMapper) Map(result *core.CheckResult) []core.ComplianceControl {
	mappings, exists := m.mappings[result.CheckID]
	if !exists {
		return nil
	}

	controls := make([]core.ComplianceControl, 0, len(mappings))
	for _, mapping := range mappings {
		control := core.ComplianceControl{
			ID:          mapping.ControlID,
			Name:        mapping.ControlName,
			Description: mapping.ControlDescription,
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
		default:
			control.Status = core.ComplianceStatusNotApplicable
		}

		controls = append(controls, control)
	}

	return controls
}

// GetControls returns all controls for this framework
func (m *YAMLComplianceMapper) GetControls() []core.ComplianceControl {
	return m.controls
}

// LoadMappersFromDirectory loads all compliance mappers from a directory
func LoadMappersFromDirectory(dir string) (map[string]core.ComplianceMapper, error) {
	mappers := make(map[string]core.ComplianceMapper)

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		if filepath.Ext(path) != ".yaml" && filepath.Ext(path) != ".yml" {
			return nil
		}

		mapper, err := NewYAMLComplianceMapper(path)
		if err != nil {
			return fmt.Errorf("failed to load mapper from %s: %w", path, err)
		}

		mappers[mapper.Framework()] = mapper
		return nil
	})

	return mappers, err
}
