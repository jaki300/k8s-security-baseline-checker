package checker

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/k8s-security-baseline-checker/pkg/core"
)

// Engine executes checks and manages the check lifecycle
type Engine struct {
	registry core.PluginRegistry
}

// NewEngine creates a new check execution engine
func NewEngine(registry core.PluginRegistry) *Engine {
	return &Engine{
		registry: registry,
	}
}

// ExecuteCheck executes a single check
func (e *Engine) ExecuteCheck(ctx context.Context, checkID string, target core.CheckTarget) (*core.CheckResult, error) {
	checker, err := e.registry.GetChecker(checkID)
	if err != nil {
		return nil, fmt.Errorf("failed to get checker: %w", err)
	}

	if !checker.Validate(target) {
		return &core.CheckResult{
			CheckID:  checkID,
			Status:   core.StatusSkip,
			Message:  fmt.Sprintf("Checker '%s' cannot validate target type '%s'", checkID, target.Type()),
			Timestamp: time.Now(),
		}, nil
	}

	startTime := time.Now()
	result, err := checker.Execute(ctx, target)
	if err != nil {
		return &core.CheckResult{
			CheckID:   checkID,
			Status:    core.StatusError,
			Message:   fmt.Sprintf("Check execution failed: %v", err),
			Timestamp: time.Now(),
			Duration:  time.Since(startTime),
		}, err
	}

	result.Duration = time.Since(startTime)
	if result.Timestamp.IsZero() {
		result.Timestamp = time.Now()
	}

	return result, nil
}

// ExecuteChecks executes multiple checks in parallel
func (e *Engine) ExecuteChecks(ctx context.Context, checkIDs []string, target core.CheckTarget, parallel bool) ([]*core.CheckResult, error) {
	if !parallel {
		return e.executeSequential(ctx, checkIDs, target)
	}

	return e.executeParallel(ctx, checkIDs, target)
}

// executeSequential executes checks sequentially
func (e *Engine) executeSequential(ctx context.Context, checkIDs []string, target core.CheckTarget) ([]*core.CheckResult, error) {
	results := make([]*core.CheckResult, 0, len(checkIDs))

	for _, checkID := range checkIDs {
		result, err := e.ExecuteCheck(ctx, checkID, target)
		if err != nil {
			return results, err
		}
		results = append(results, result)
	}

	return results, nil
}

// executeParallel executes checks in parallel
func (e *Engine) executeParallel(ctx context.Context, checkIDs []string, target core.CheckTarget) ([]*core.CheckResult, error) {
	var wg sync.WaitGroup
	results := make([]*core.CheckResult, len(checkIDs))
	errors := make([]error, len(checkIDs))

	for i, checkID := range checkIDs {
		wg.Add(1)
		go func(idx int, id string) {
			defer wg.Done()
			result, err := e.ExecuteCheck(ctx, id, target)
			results[idx] = result
			errors[idx] = err
		}(i, checkID)
	}

	wg.Wait()

	// Check for errors
	for _, err := range errors {
		if err != nil {
			return results, err
		}
	}

	return results, nil
}

// ExecuteBenchmark executes all checks defined in a benchmark
func (e *Engine) ExecuteBenchmark(ctx context.Context, benchmark *Benchmark, target core.CheckTarget, parallel bool) ([]*core.CheckResult, error) {
	checkIDs := make([]string, 0, len(benchmark.Checks))
	for _, check := range benchmark.Checks {
		checkIDs = append(checkIDs, check.ID)
	}

	return e.ExecuteChecks(ctx, checkIDs, target, parallel)
}

// Benchmark represents a collection of checks
type Benchmark struct {
	ID          string
	Name        string
	Description string
	Version     string
	Checks      []CheckDefinition
}

// CheckDefinition defines a check in a benchmark
type CheckDefinition struct {
	ID          string
	Description string
	Severity    core.SeverityLevel
	Category    string
}
