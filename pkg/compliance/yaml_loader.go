package compliance

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// EnhancedMappingDefinition represents an enhanced YAML mapping with many-to-many support
type EnhancedMappingDefinition struct {
	Framework string                 `yaml:"framework"`
	Version   string                 `yaml:"version"`
	Metadata  FrameworkMetadata      `yaml:"metadata"`
	Mappings  []ControlMappingDef    `yaml:"mappings"`
}

// ControlMappingDef defines a control mapping in YAML
type ControlMappingDef struct {
	ControlID     string      `yaml:"control_id"`
	ControlName   string      `yaml:"control_name"`
	Description   string      `yaml:"description"`
	Category      string      `yaml:"category"`
	CheckIDs      []string    `yaml:"check_ids"` // Many checks can map to one control
	Weight        float64     `yaml:"weight"`
	MappingRule   MappingRule `yaml:"mapping_rule"`
}

// LoadEnhancedMappings loads enhanced mappings from a YAML file
func LoadEnhancedMappings(filePath string) (*EnhancedMappingDefinition, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read mapping file: %w", err)
	}

	var def EnhancedMappingDefinition
	if err := yaml.Unmarshal(data, &def); err != nil {
		return nil, fmt.Errorf("failed to parse mapping file: %w", err)
	}

	return &def, nil
}

// LoadMappingsIntoEngine loads mappings from a YAML file into the mapping engine
func LoadMappingsIntoEngine(engine *MappingEngine, filePath string) error {
	def, err := LoadEnhancedMappings(filePath)
	if err != nil {
		return err
	}

	// Set framework metadata
	engine.SetFrameworkMetadata(def.Framework, def.Metadata)

	// Add mappings (many-to-many: one control can map to multiple checks)
	for _, mapping := range def.Mappings {
		for _, checkID := range mapping.CheckIDs {
			frameworkMapping := FrameworkMapping{
				Framework:   def.Framework,
				ControlID:   mapping.ControlID,
				ControlName: mapping.ControlName,
				Category:    mapping.Category,
				Weight:      mapping.Weight,
				MappingRule: mapping.MappingRule,
				Description: mapping.Description,
			}

			if frameworkMapping.Weight == 0 {
				frameworkMapping.Weight = 1.0 // Default weight
			}

			engine.AddMapping(checkID, frameworkMapping)
		}
	}

	return nil
}

// LoadMappingsFromDirectory loads all mapping files from a directory
func LoadMappingsFromDirectory(engine *MappingEngine, dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		if filepath.Ext(path) != ".yaml" && filepath.Ext(path) != ".yml" {
			return nil
		}

		if err := LoadMappingsIntoEngine(engine, path); err != nil {
			return fmt.Errorf("failed to load mappings from %s: %w", path, err)
		}

		return nil
	})
}

// CreateCustomFramework creates a custom organizational framework
func CreateCustomFramework(
	engine *MappingEngine,
	frameworkName string,
	version string,
	description string,
	scoringConfig ScoringConfig,
	mappings []ControlMappingDef,
) error {
	metadata := FrameworkMetadata{
		Name:        frameworkName,
		Version:     version,
		Description: description,
		Scoring:     scoringConfig,
	}

	engine.SetFrameworkMetadata(frameworkName, metadata)

	for _, mapping := range mappings {
		for _, checkID := range mapping.CheckIDs {
			frameworkMapping := FrameworkMapping{
				Framework:   frameworkName,
				ControlID:   mapping.ControlID,
				ControlName: mapping.ControlName,
				Category:    mapping.Category,
				Weight:      mapping.Weight,
				MappingRule: mapping.MappingRule,
				Description: mapping.Description,
			}

			if frameworkMapping.Weight == 0 {
				frameworkMapping.Weight = 1.0
			}

			engine.AddMapping(checkID, frameworkMapping)
		}
	}

	return nil
}
