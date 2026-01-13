package benchmark

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/k8s-security-baseline-checker/pkg/types"
	"github.com/k8s-security-baseline-checker/pkg/validation"
	"gopkg.in/yaml.v3"
)

// Loader handles loading benchmark definitions from files
type Loader struct {
	benchmarkDir string
}

// NewLoader creates a new benchmark loader
func NewLoader(benchmarkDir string) *Loader {
	return &Loader{
		benchmarkDir: benchmarkDir,
	}
}

// LoadBenchmark loads a benchmark from a file (JSON or YAML)
func (l *Loader) LoadBenchmark(filePath string) (*types.Benchmark, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read benchmark file: %w", err)
	}

	var benchmark types.Benchmark

	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".json":
		if err := json.Unmarshal(data, &benchmark); err != nil {
			return nil, fmt.Errorf("failed to parse JSON benchmark: %w", err)
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &benchmark); err != nil {
			return nil, fmt.Errorf("failed to parse YAML benchmark: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported file format: %s (supported: .json, .yaml, .yml)", ext)
	}

	// Validate benchmark
	if err := l.validateBenchmark(&benchmark); err != nil {
		return nil, fmt.Errorf("invalid benchmark: %w", err)
	}

	return &benchmark, nil
}

// LoadBenchmarkByID loads a benchmark by its ID from the benchmark directory
// Enterprise requirement: Validate benchmark ID before loading
func (l *Loader) LoadBenchmarkByID(benchmarkID string) (*types.Benchmark, error) {
	// Validate benchmark ID
	validator := validation.NewValidator()
	if err := validator.ValidateBenchmarkID(benchmarkID); err != nil {
		return nil, fmt.Errorf("invalid benchmark ID: %w", err)
	}

	// Validate file paths before accessing
	possiblePaths := []string{
		filepath.Join(l.benchmarkDir, benchmarkID+".yaml"),
		filepath.Join(l.benchmarkDir, benchmarkID+".yml"),
		filepath.Join(l.benchmarkDir, benchmarkID+".json"),
		filepath.Join(l.benchmarkDir, strings.ToLower(benchmarkID), "benchmark.yaml"),
		filepath.Join(l.benchmarkDir, strings.ToLower(benchmarkID), "benchmark.yml"),
		filepath.Join(l.benchmarkDir, strings.ToLower(benchmarkID), "benchmark.json"),
	}

	for _, path := range possiblePaths {
		// Validate path to prevent path traversal
		if err := validator.ValidateFilePath(path); err != nil {
			continue // Skip invalid paths
		}

		if _, err := os.Stat(path); err == nil {
			return l.LoadBenchmark(path)
		}
	}

	return nil, fmt.Errorf("benchmark '%s' not found in %s", benchmarkID, l.benchmarkDir)
}

// LoadBenchmarksFromDir loads all benchmarks from a directory
func (l *Loader) LoadBenchmarksFromDir(dir string) ([]*types.Benchmark, error) {
	var benchmarks []*types.Benchmark

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".json" && ext != ".yaml" && ext != ".yml" {
			return nil
		}

		benchmark, err := l.LoadBenchmark(path)
		if err != nil {
			// Log error but continue with other files
			fmt.Printf("Warning: failed to load benchmark from %s: %v\n", path, err)
			return nil
		}

		benchmarks = append(benchmarks, benchmark)
		return nil
	})

	return benchmarks, err
}

// LoadBenchmarksByFramework loads all benchmarks for a specific framework (CIS, NIST, Custom)
func (l *Loader) LoadBenchmarksByFramework(framework string) ([]*types.Benchmark, error) {
	frameworkDir := filepath.Join(l.benchmarkDir, strings.ToLower(framework))
	return l.LoadBenchmarksFromDir(frameworkDir)
}

// validateBenchmark validates a benchmark structure
func (l *Loader) validateBenchmark(benchmark *types.Benchmark) error {
	if benchmark.ID == "" {
		return fmt.Errorf("benchmark ID is required")
	}
	if benchmark.Name == "" {
		return fmt.Errorf("benchmark name is required")
	}
	if benchmark.Framework == "" {
		return fmt.Errorf("benchmark framework is required")
	}
	if len(benchmark.Checks) == 0 {
		return fmt.Errorf("benchmark must contain at least one check")
	}

	// Validate checks
	checkIDs := make(map[string]bool)
	for i, check := range benchmark.Checks {
		if check.ID == "" {
			return fmt.Errorf("check at index %d has no ID", i)
		}
		if checkIDs[check.ID] {
			return fmt.Errorf("duplicate check ID: %s", check.ID)
		}
		checkIDs[check.ID] = true

		if check.Description == "" {
			return fmt.Errorf("check %s has no description", check.ID)
		}
		if check.Type == "" {
			return fmt.Errorf("check %s has no type", check.ID)
		}
		if check.Weight == 0 {
			check.Weight = 1 // Set default weight
		}
		if check.Severity == "" {
			check.Severity = types.SeverityMedium // Set default severity
		}
	}

	return nil
}

// Registry manages loaded benchmarks
type Registry struct {
	benchmarks map[string]*types.Benchmark
	loader     *Loader
}

// NewRegistry creates a new benchmark registry
func NewRegistry(benchmarkDir string) *Registry {
	return &Registry{
		benchmarks: make(map[string]*types.Benchmark),
		loader:     NewLoader(benchmarkDir),
	}
}

// LoadAll loads all benchmarks from the benchmark directory
func (r *Registry) LoadAll() error {
	benchmarks, err := r.loader.LoadBenchmarksFromDir(r.loader.benchmarkDir)
	if err != nil {
		return err
	}

	for _, benchmark := range benchmarks {
		r.benchmarks[benchmark.ID] = benchmark
	}

	return nil
}

// LoadFramework loads all benchmarks for a specific framework
func (r *Registry) LoadFramework(framework string) error {
	benchmarks, err := r.loader.LoadBenchmarksByFramework(framework)
	if err != nil {
		return err
	}

	for _, benchmark := range benchmarks {
		r.benchmarks[benchmark.ID] = benchmark
	}

	return nil
}

// Get retrieves a benchmark by ID
func (r *Registry) Get(benchmarkID string) (*types.Benchmark, error) {
	benchmark, exists := r.benchmarks[benchmarkID]
	if !exists {
		// Try to load it
		benchmark, err := r.loader.LoadBenchmarkByID(benchmarkID)
		if err != nil {
			return nil, fmt.Errorf("benchmark '%s' not found", benchmarkID)
		}
		r.benchmarks[benchmarkID] = benchmark
		return benchmark, nil
	}
	return benchmark, nil
}

// List returns all registered benchmark IDs
func (r *Registry) List() []string {
	ids := make([]string, 0, len(r.benchmarks))
	for id := range r.benchmarks {
		ids = append(ids, id)
	}
	return ids
}

// ListByFramework returns benchmark IDs for a specific framework
func (r *Registry) ListByFramework(framework string) []string {
	var ids []string
	for id, benchmark := range r.benchmarks {
		if strings.EqualFold(benchmark.Framework, framework) {
			ids = append(ids, id)
		}
	}
	return ids
}

// Register adds a benchmark to the registry
func (r *Registry) Register(benchmark *types.Benchmark) error {
	if err := r.loader.validateBenchmark(benchmark); err != nil {
		return err
	}
	r.benchmarks[benchmark.ID] = benchmark
	return nil
}

