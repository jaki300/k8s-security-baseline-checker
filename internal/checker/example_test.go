package checker

import (
	"context"
	"fmt"
	"time"

	"github.com/k8s-security-baseline-checker/pkg/types"
	"github.com/sirupsen/logrus"
)

// ExampleChecker demonstrates how to implement a custom checker
type ExampleChecker struct {
	*BaseChecker
}

// NewExampleChecker creates a new example checker
func NewExampleChecker(logger *logrus.Logger) *ExampleChecker {
	base := NewBaseChecker("example-checker", "example", logger)
	return &ExampleChecker{
		BaseChecker: base,
	}
}

// Execute implements the Checker interface
func (c *ExampleChecker) Execute(ctx context.Context, check types.Check, options *ExecutionOptions) (*types.Result, error) {
	// Example check logic
	// In a real implementation, this would perform actual security checks

	// Simulate check execution
	time.Sleep(10 * time.Millisecond)

	// Example: Check passes
	if check.ID == "example-pass" {
		return c.CreatePassResult(check, "Example check passed"), nil
	}

	// Example: Check fails
	if check.ID == "example-fail" {
		return c.CreateFailResult(
			check,
			[]string{"resource1", "resource2"},
			"Example check failed: found 2 violations",
		), nil
	}

	// Default: return error
	return c.CreateErrorResult(check, fmt.Errorf("unknown check ID: %s", check.ID)), nil
}

// ExampleEngineUsage demonstrates how to use the engine
func ExampleEngineUsage() {
	// Create logger
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	// Create engine
	engine := NewEngine(logger)

	// Register checkers
	exampleChecker := NewExampleChecker(logger)
	engine.Register(exampleChecker)

	// Create a check
	check := types.Check{
		ID:          "example-pass",
		Description: "Example check that passes",
		Severity:    types.SeverityMedium,
		Type:        "example",
		Weight:      1,
		Remediation: "No action needed",
	}

	// Create execution options
	options := &ExecutionOptions{
		Logger: logger,
		Config: map[string]interface{}{
			"namespace": "default",
		},
	}

	// Execute check
	ctx := context.Background()
	result, err := engine.ExecuteCheck(ctx, check, options)
	if err != nil {
		logger.Errorf("Check execution failed: %v", err)
		return
	}

	logger.Infof("Check result: %s - %s", result.Status, result.Message)
}

