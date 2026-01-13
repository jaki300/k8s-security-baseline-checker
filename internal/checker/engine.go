package checker

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/k8s-security-baseline-checker/pkg/types"
	"github.com/sirupsen/logrus"
)

// Checker is the interface that all check implementations must satisfy
// This enables a plugin-based architecture where different checkers can be registered
type Checker interface {
	// Name returns the unique name/identifier of this checker
	Name() string

	// Type returns the type of checker (e.g., "k8s", "cloud", "aws", "azure", "gcp")
	Type() string

	// Execute runs the check and returns a Result
	// ctx: context for cancellation and timeout
	// check: the check definition to execute
	// options: additional options for the check execution
	Execute(ctx context.Context, check types.Check, options *ExecutionOptions) (*types.Result, error)

	// Validate checks if this checker can handle the given check type
	Validate(check types.Check) bool
}

// ExecutionOptions contains options for check execution
type ExecutionOptions struct {
	// Namespaces to check (empty means all namespaces)
	Namespaces []string

	// Cluster context information
	ClusterInfo *types.ClusterInfo

	// Additional configuration
	Config map[string]interface{}

	// Logger instance
	Logger *logrus.Logger
}

// Engine is the core checking engine that manages and executes checks
type Engine struct {
	checkers map[string]Checker // Map of checker name -> Checker implementation
	mu       sync.RWMutex
	logger   *logrus.Logger
}

// NewEngine creates a new checker engine instance
func NewEngine(logger *logrus.Logger) *Engine {
	if logger == nil {
		logger = logrus.New()
		logger.SetLevel(logrus.InfoLevel)
	}

	return &Engine{
		checkers: make(map[string]Checker),
		logger:   logger,
	}
}

// Register adds a checker to the engine
// This enables the plugin architecture - new checkers can be registered at runtime
func (e *Engine) Register(checker Checker) error {
	if checker == nil {
		return fmt.Errorf("checker cannot be nil")
	}

	name := checker.Name()
	if name == "" {
		return fmt.Errorf("checker name cannot be empty")
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.checkers[name]; exists {
		return fmt.Errorf("checker with name '%s' already registered", name)
	}

	e.checkers[name] = checker
	e.logger.Debugf("Registered checker: %s (type: %s)", name, checker.Type())
	return nil
}

// Unregister removes a checker from the engine
func (e *Engine) Unregister(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.checkers, name)
	e.logger.Debugf("Unregistered checker: %s", name)
}

// GetChecker retrieves a checker by name
func (e *Engine) GetChecker(name string) (Checker, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	checker, exists := e.checkers[name]
	return checker, exists
}

// ListCheckers returns all registered checker names
func (e *Engine) ListCheckers() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	names := make([]string, 0, len(e.checkers))
	for name := range e.checkers {
		names = append(names, name)
	}
	return names
}

// FindCheckerForCheck finds the appropriate checker for a given check
// It iterates through registered checkers and returns the first one that validates the check
func (e *Engine) FindCheckerForCheck(check types.Check) (Checker, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, checker := range e.checkers {
		if checker.Validate(check) {
			return checker, nil
		}
	}

	return nil, fmt.Errorf("no checker found for check type '%s' (ID: %s)", check.Type, check.ID)
}

// ExecuteCheck executes a single check using the appropriate checker
func (e *Engine) ExecuteCheck(ctx context.Context, check types.Check, options *ExecutionOptions) (*types.Result, error) {
	if options == nil {
		options = &ExecutionOptions{
			Logger: e.logger,
		}
	}
	if options.Logger == nil {
		options.Logger = e.logger
	}

	checker, err := e.FindCheckerForCheck(check)
	if err != nil {
		return &types.Result{
			CheckID:     check.ID,
			Status:      types.StatusError,
			Details:     []string{err.Error()},
			Remediation: check.Remediation,
			Weight:      check.Weight,
			Severity:    check.Severity,
			Message:     fmt.Sprintf("Failed to find checker: %v", err),
			Timestamp:   time.Now(),
		}, err
	}

	startTime := time.Now()
	result, err := checker.Execute(ctx, check, options)
	duration := time.Since(startTime)

	if err != nil {
		return &types.Result{
			CheckID:     check.ID,
			Status:      types.StatusError,
			Details:     []string{err.Error()},
			Remediation: check.Remediation,
			Weight:      check.Weight,
			Severity:    check.Severity,
			Message:     fmt.Sprintf("Check execution failed: %v", err),
			Timestamp:   time.Now(),
			Duration:    duration,
		}, err
	}

	// Ensure result has required fields
	if result.CheckID == "" {
		result.CheckID = check.ID
	}
	if result.Weight == 0 {
		result.Weight = check.Weight
		if result.Weight == 0 {
			result.Weight = 1 // Default weight
		}
	}
	if result.Severity == "" {
		result.Severity = check.Severity
	}
	if result.Remediation == "" {
		result.Remediation = check.Remediation
	}
	if result.Timestamp.IsZero() {
		result.Timestamp = time.Now()
	}
	result.Duration = duration

	return result, nil
}

// ExecuteChecks executes multiple checks, optionally in parallel
func (e *Engine) ExecuteChecks(ctx context.Context, checks []types.Check, options *ExecutionOptions, parallel bool) ([]types.Result, error) {
	if options == nil {
		options = &ExecutionOptions{
			Logger: e.logger,
		}
	}

	results := make([]types.Result, 0, len(checks))

	if parallel {
		// Execute checks in parallel using goroutines
		var wg sync.WaitGroup
		resultChan := make(chan *types.Result, len(checks))
		errChan := make(chan error, len(checks))

		for _, check := range checks {
			wg.Add(1)
			go func(c types.Check) {
				defer wg.Done()
				result, err := e.ExecuteCheck(ctx, c, options)
				if err != nil {
					errChan <- err
					return
				}
				resultChan <- result
			}(check)
		}

		wg.Wait()
		close(resultChan)
		close(errChan)

		// Collect results
		for result := range resultChan {
			results = append(results, *result)
		}

		// Collect errors (non-fatal, just log them)
		for err := range errChan {
			e.logger.Warnf("Check execution error: %v", err)
		}
	} else {
		// Execute checks sequentially
		for _, check := range checks {
			result, err := e.ExecuteCheck(ctx, check, options)
			if err != nil {
				e.logger.Warnf("Check execution error for %s: %v", check.ID, err)
				// Continue with other checks even if one fails
				continue
			}
			results = append(results, *result)
		}
	}

	return results, nil
}

// GenerateReport generates a complete report from check results
func (e *Engine) GenerateReport(clusterInfo types.ClusterInfo, results []types.Result, benchmark string, benchmarkVersion string) *types.Report {
	report := &types.Report{
		ID:              fmt.Sprintf("report-%d", time.Now().Unix()),
		Cluster:         clusterInfo,
		Results:         results,
		Benchmark:       benchmark,
		BenchmarkVersion: benchmarkVersion,
		GeneratedAt:     time.Now(),
		TotalChecks:     len(results),
	}

	// Count checks by status
	for _, result := range results {
		switch result.Status {
		case types.StatusPass:
			report.PassedChecks++
		case types.StatusFail:
			report.FailedChecks++
		case types.StatusWarn:
			report.WarnedChecks++
		}
	}

	// Calculate compliance score
	report.ComplianceScore = types.CalculateComplianceScore(results)
	report.Grade = types.CalculateGrade(report.ComplianceScore)

	return report
}

// ExecuteBenchmark executes all checks from a benchmark
func (e *Engine) ExecuteBenchmark(ctx context.Context, benchmark types.Benchmark, options *ExecutionOptions, parallel bool) (*types.Report, error) {
	if options == nil {
		options = &ExecutionOptions{
			Logger: e.logger,
		}
	}

	startTime := time.Now()
	e.logger.Infof("Executing benchmark: %s (version: %s) with %d checks", benchmark.Name, benchmark.Version, len(benchmark.Checks))

	results, err := e.ExecuteChecks(ctx, benchmark.Checks, options, parallel)
	if err != nil {
		return nil, fmt.Errorf("failed to execute benchmark checks: %w", err)
	}

	duration := time.Since(startTime)

	// Build cluster info if not provided
	clusterInfo := types.ClusterInfo{}
	if options != nil && options.ClusterInfo != nil {
		clusterInfo = *options.ClusterInfo
	}

	report := e.GenerateReport(clusterInfo, results, benchmark.Framework, benchmark.Version)
	report.Duration = duration

	e.logger.Infof("Benchmark execution completed in %v. Score: %d%% (Grade: %s)", duration, report.ComplianceScore, report.Grade)

	return report, nil
}

