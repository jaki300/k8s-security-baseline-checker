package cloud

import (
	"context"
	"fmt"

	"github.com/k8s-security-baseline-checker/internal/checker"
	"github.com/k8s-security-baseline-checker/pkg/types"
	"github.com/sirupsen/logrus"
)

// CloudChecker is the base interface for cloud provider checkers
type CloudChecker interface {
	checker.Checker
	Provider() string
}

// BaseCloudChecker provides base implementation for cloud checkers
type BaseCloudChecker struct {
	*checker.BaseChecker
	provider string
}

// NewBaseCloudChecker creates a new base cloud checker
func NewBaseCloudChecker(name, provider string, logger *logrus.Logger) *BaseCloudChecker {
	base := checker.NewBaseChecker(name, "cloud", logger)
	return &BaseCloudChecker{
		BaseChecker: base,
		provider:    provider,
	}
}

// Provider returns the cloud provider name
func (b *BaseCloudChecker) Provider() string {
	return b.provider
}

// Validate checks if this checker can handle the given check
func (b *BaseCloudChecker) Validate(check types.Check) bool {
	// Cloud checks should have type starting with "cloud_" or framework matching provider
	return check.Type != "" && (check.Framework == b.provider || check.Framework == "cloud")
}

// Execute provides default implementation
func (b *BaseCloudChecker) Execute(ctx context.Context, check types.Check, options *checker.ExecutionOptions) (*types.Result, error) {
	return b.CreateErrorResult(check, fmt.Errorf("cloud check execution not implemented for %s", b.provider)), nil
}

