package checker

import (
	"context"
	"fmt"
	"time"

	"github.com/k8s-security-baseline-checker/pkg/types"
	"github.com/sirupsen/logrus"
)

// BaseChecker provides a base implementation of the Checker interface
// that can be embedded by specific checker implementations
type BaseChecker struct {
	name     string
	checkType string
	logger   *logrus.Logger
}

// NewBaseChecker creates a new base checker instance
func NewBaseChecker(name, checkType string, logger *logrus.Logger) *BaseChecker {
	if logger == nil {
		logger = logrus.New()
		logger.SetLevel(logrus.InfoLevel)
	}

	return &BaseChecker{
		name:      name,
		checkType: checkType,
		logger:    logger,
	}
}

// Name returns the checker name
func (b *BaseChecker) Name() string {
	return b.name
}

// Type returns the checker type
func (b *BaseChecker) Type() string {
	return b.checkType
}

// Logger returns the logger instance
func (b *BaseChecker) Logger() *logrus.Logger {
	return b.logger
}

// Validate provides a default validation that checks if the check type matches
// Specific checkers can override this method for custom validation logic
func (b *BaseChecker) Validate(check types.Check) bool {
	return check.Type == b.checkType || check.Type == ""
}

// Execute provides a default implementation that returns an error
// Specific checkers must override this method
func (b *BaseChecker) Execute(ctx context.Context, check types.Check, options *ExecutionOptions) (*types.Result, error) {
	return nil, fmt.Errorf("Execute method must be implemented by specific checker")
}

// CreateResult is a helper method to create a Result with common fields populated
func (b *BaseChecker) CreateResult(check types.Check, status types.CheckStatus, details []string, message string) *types.Result {
	weight := check.Weight
	if weight == 0 {
		weight = 1 // Default weight
	}

	return &types.Result{
		CheckID:     check.ID,
		Status:      status,
		Details:     details,
		Remediation: check.Remediation,
		Weight:      weight,
		Severity:    check.Severity,
		Message:     message,
		Timestamp:   time.Now(), // Engine may override this with actual execution time
	}
}

// CreatePassResult creates a PASS result
func (b *BaseChecker) CreatePassResult(check types.Check, message string) *types.Result {
	return b.CreateResult(check, types.StatusPass, nil, message)
}

// CreateFailResult creates a FAIL result
func (b *BaseChecker) CreateFailResult(check types.Check, details []string, message string) *types.Result {
	return b.CreateResult(check, types.StatusFail, details, message)
}

// CreateWarnResult creates a WARN result
func (b *BaseChecker) CreateWarnResult(check types.Check, details []string, message string) *types.Result {
	return b.CreateResult(check, types.StatusWarn, details, message)
}

// CreateErrorResult creates an ERROR result
func (b *BaseChecker) CreateErrorResult(check types.Check, err error) *types.Result {
	return b.CreateResult(check, types.StatusError, []string{err.Error()}, fmt.Sprintf("Check failed: %v", err))
}

