package compliance

import (
	"context"
	"fmt"
	"time"

	"github.com/k8s-security-baseline-checker/pkg/core"
	"github.com/k8s-security-baseline-checker/pkg/checker"
)

// Orchestrator coordinates check execution and compliance mapping
type Orchestrator struct {
	checkEngine       checker.Engine
	registry          core.PluginRegistry
	complianceMappers map[string]core.ComplianceMapper
}

// NewOrchestrator creates a new compliance orchestrator
func NewOrchestrator(engine checker.Engine, registry core.PluginRegistry) *Orchestrator {
	return &Orchestrator{
		checkEngine:       engine,
		registry:          registry,
		complianceMappers: make(map[string]core.ComplianceMapper),
	}
}

// RegisterComplianceMapper registers a compliance mapper
func (o *Orchestrator) RegisterComplianceMapper(mapper core.ComplianceMapper) {
	o.complianceMappers[mapper.Framework()] = mapper
}

// ExecuteBenchmarkWithCompliance executes checks and maps results to compliance frameworks
func (o *Orchestrator) ExecuteBenchmarkWithCompliance(
	ctx context.Context,
	benchmark *checker.Benchmark,
	target core.CheckTarget,
	frameworks []string,
	parallel bool,
) (*ComplianceReport, error) {
	// Execute checks
	checkIDs := make([]string, 0, len(benchmark.Checks))
	for _, check := range benchmark.Checks {
		checkIDs = append(checkIDs, check.ID)
	}

	results, err := o.checkEngine.ExecuteChecks(ctx, checkIDs, target, parallel)
	if err != nil {
		return nil, fmt.Errorf("failed to execute checks: %w", err)
	}

	// Map results to compliance frameworks
	complianceControls := make(map[string][]core.ComplianceControl)
	for _, framework := range frameworks {
		mapper, exists := o.complianceMappers[framework]
		if !exists {
			return nil, fmt.Errorf("compliance mapper for framework '%s' not found", framework)
		}

		controls := make([]core.ComplianceControl, 0)
		for _, result := range results {
			mappedControls := mapper.Map(result)
			controls = append(controls, mappedControls...)
		}

		complianceControls[framework] = controls
	}

	return &ComplianceReport{
		Benchmark:          benchmark,
		CheckResults:       results,
		ComplianceControls: complianceControls,
		Timestamp:          time.Now(),
	}, nil
}

// ComplianceReport represents a comprehensive compliance report
type ComplianceReport struct {
	Benchmark          *checker.Benchmark
	CheckResults       []*core.CheckResult
	ComplianceControls map[string][]core.ComplianceControl
	Timestamp          time.Time
}
