package checker

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/k8s-security-baseline-checker/pkg/core"
	"gopkg.in/yaml.v3"
)

// ControlDefinition represents a security control defined in YAML
type ControlDefinition struct {
	ID          string                 `yaml:"id"`
	Name        string                 `yaml:"name"`
	Description string                 `yaml:"description"`
	Category    string                 `yaml:"category"`
	Severity    core.SeverityLevel     `yaml:"severity"`
	CheckerID   string                 `yaml:"checker_id"`
	Metadata    map[string]interface{} `yaml:"metadata,omitempty"`
}

// BenchmarkDefinition represents a benchmark defined in YAML
type BenchmarkDefinition struct {
	ID          string               `yaml:"id"`
	Name        string               `yaml:"name"`
	Description string               `yaml:"description"`
	Version     string               `yaml:"version"`
	Framework   string               `yaml:"framework"`
	Controls    []ControlDefinition  `yaml:"controls"`
	Metadata    map[string]interface{} `yaml:"metadata,omitempty"`
}

// LoadBenchmark loads a benchmark from a YAML file
func LoadBenchmark(filePath string) (*Benchmark, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read benchmark file: %w", err)
	}

	var def BenchmarkDefinition
	if err := yaml.Unmarshal(data, &def); err != nil {
		return nil, fmt.Errorf("failed to parse benchmark file: %w", err)
	}

	benchmark := &Benchmark{
		ID:          def.ID,
		Name:        def.Name,
		Description: def.Description,
		Version:     def.Version,
		Checks:      make([]CheckDefinition, 0, len(def.Controls)),
	}

	for _, control := range def.Controls {
		benchmark.Checks = append(benchmark.Checks, CheckDefinition{
			ID:          control.ID,
			Description: control.Description,
			Severity:    control.Severity,
			Category:    control.Category,
		})
	}

	return benchmark, nil
}

// LoadBenchmarksFromDirectory loads all benchmarks from a directory
func LoadBenchmarksFromDirectory(dir string) (map[string]*Benchmark, error) {
	benchmarks := make(map[string]*Benchmark)

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

		benchmark, err := LoadBenchmark(path)
		if err != nil {
			return fmt.Errorf("failed to load benchmark from %s: %w", path, err)
		}

		benchmarks[benchmark.ID] = benchmark
		return nil
	})

	return benchmarks, err
}
