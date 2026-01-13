# Usage Guide - Enterprise Architecture

## Quick Start

### 1. Initialize Components

```go
package main

import (
    "context"
    "github.com/k8s-security-baseline-checker/pkg/core"
    "github.com/k8s-security-baseline-checker/pkg/checker"
    "github.com/k8s-security-baseline-checker/pkg/compliance"
)

func main() {
    // Create plugin registry
    registry := core.NewPluginRegistry()
    
    // Register your checkers
    registry.RegisterChecker(&MyK8sChecker{})
    
    // Create check engine
    engine := checker.NewEngine(registry)
    
    // Create compliance orchestrator
    orchestrator := compliance.NewOrchestrator(engine, registry)
    
    // Load compliance mappings from YAML
    mappers, err := compliance.LoadMappersFromDirectory("config/mappings/")
    if err != nil {
        panic(err)
    }
    
    // Register compliance mappers
    for _, mapper := range mappers {
        orchestrator.RegisterComplianceMapper(mapper)
    }
}
```

### 2. Load Benchmark

```go
benchmark, err := checker.LoadBenchmark("config/controls/cis-kubernetes.yaml")
if err != nil {
    panic(err)
}
```

### 3. Execute with Compliance Mapping

```go
target := &K8sClusterTarget{
    ClusterID: "production-cluster",
    // ... cluster data
}

// Execute checks and map to multiple frameworks
report, err := orchestrator.ExecuteBenchmarkWithCompliance(
    context.Background(),
    benchmark,
    target,
    []string{"NIST", "ISO27001", "SOC2"}, // Multiple frameworks
    true, // Execute in parallel
)

if err != nil {
    panic(err)
}

// Report contains:
// - CheckResults: Evidence-based check results
// - ComplianceControls: Mapped compliance controls per framework
```

## Adding a New Compliance Framework

### Step 1: Create Mapping File

Create `config/mappings/my-framework.yaml`:

```yaml
framework: MyFramework
version: "1.0"
controls:
  - control_id: "MF-AC-1"
    control_name: "Access Control"
    control_description: "Ensure proper access controls are in place"
    category: "Access Control"
    check_id: "cis-2.1.1"  # Maps to CIS control
    mapping_rule:
      pass_status: COMPLIANT
      fail_status: NON_COMPLIANT
      warn_status: PARTIAL
      requires_evidence: true
  
  - control_id: "MF-SC-1"
    control_name: "Security Configuration"
    control_description: "Ensure secure configurations"
    category: "Security Configuration"
    check_id: "cis-2.1.2"
    mapping_rule:
      pass_status: COMPLIANT
      fail_status: NON_COMPLIANT
      warn_status: PARTIAL
      requires_evidence: true
```

### Step 2: Load at Runtime

```go
// The mapper will be automatically loaded from config/mappings/
mappers, _ := compliance.LoadMappersFromDirectory("config/mappings/")
orchestrator.RegisterComplianceMapper(mappers["MyFramework"])
```

**That's it! No code changes needed.**

## Adding a New Check

### Step 1: Implement Checker Interface

```go
package plugins

import (
    "context"
    "github.com/k8s-security-baseline-checker/pkg/core"
)

type MySecurityChecker struct {
    // Your fields
}

func (c *MySecurityChecker) ID() string {
    return "my-security-check"
}

func (c *MySecurityChecker) Name() string {
    return "My Security Check"
}

func (c *MySecurityChecker) Description() string {
    return "Checks for specific security issue"
}

func (c *MySecurityChecker) Execute(ctx context.Context, target core.CheckTarget) (*core.CheckResult, error) {
    // Your check logic here
    
    // Collect evidence
    evidence := []core.Evidence{
        {
            Type:        core.EvidenceTypeResource,
            Source:      "k8s-api",
            Description: "Pod configuration retrieved",
            Content: map[string]interface{}{
                "namespace": "default",
                "pod": "my-pod",
            },
        },
    }
    
    // Create findings if issues found
    findings := []core.Finding{
        {
            ID:          "finding-1",
            Title:       "Security Issue Found",
            Description: "Detailed description",
            Severity:    core.SeverityHigh,
            Resource:    "pod/default/my-pod",
            Remediation: "Fix instructions here",
            Evidence:    evidence,
        },
    }
    
    return &core.CheckResult{
        CheckID:   c.ID(),
        Status:    core.StatusFail,
        Severity:  core.SeverityHigh,
        Evidence:  evidence,
        Findings:  findings,
        Message:   "Found 1 security issue",
        Timestamp: time.Now(),
    }, nil
}

func (c *MySecurityChecker) Validate(target core.CheckTarget) bool {
    return target.Type() == "k8s-cluster"
}

func (c *MySecurityChecker) Metadata() core.CheckMetadata {
    return core.CheckMetadata{
        Category:  "Security",
        Tags:      []string{"security", "k8s"},
        References: []string{"https://example.com/docs"},
    }
}
```

### Step 2: Register Checker

```go
registry.RegisterChecker(&MySecurityChecker{})
```

### Step 3: Add to Control Definition

Add to `config/controls/cis-kubernetes.yaml`:

```yaml
controls:
  - id: "cis-X.X.X"
    name: "My Security Check"
    description: "Checks for specific security issue"
    category: "Security"
    severity: HIGH
    checker_id: "my-security-check"  # References your checker ID
```

### Step 4: Map to Compliance Frameworks

Add to compliance mapping files (e.g., `config/mappings/nist-800-53.yaml`):

```yaml
controls:
  - control_id: "AC-3"
    control_name: "Access Enforcement"
    check_id: "cis-X.X.X"  # References the control ID
    mapping_rule:
      pass_status: COMPLIANT
      fail_status: NON_COMPLIANT
```

## Evidence-Based Results

All results include concrete evidence:

```go
result := &core.CheckResult{
    CheckID: "check-pods-nonroot",
    Status:  core.StatusFail,
    Evidence: []core.Evidence{
        {
            Type:        core.EvidenceTypeResource,
            Source:      "k8s-api",
            Description: "Pod running as root user",
            Content: map[string]interface{}{
                "namespace": "default",
                "pod": "my-pod",
                "runAsUser": 0,
            },
        },
    },
    Findings: []core.Finding{
        {
            ID:          "finding-1",
            Title:       "Pod running as root",
            Description: "Pod 'my-pod' in namespace 'default' is running as root (UID 0)",
            Severity:    core.SeverityCritical,
            Resource:    "pod/default/my-pod",
            Remediation: "Set securityContext.runAsNonRoot=true",
            Evidence:    []core.Evidence{...},
        },
    },
}
```

## Multi-Framework Compliance

Execute checks once, map to multiple frameworks:

```go
report, err := orchestrator.ExecuteBenchmarkWithCompliance(
    ctx,
    benchmark,
    target,
    []string{"NIST", "ISO27001", "SOC2", "PCI-DSS"}, // All frameworks
    true,
)

// Access compliance status per framework
nistControls := report.ComplianceControls["NIST"]
isoControls := report.ComplianceControls["ISO27001"]
soc2Controls := report.ComplianceControls["SOC2"]
```

## Report Generation

```go
// Generate JSON report
jsonReport, err := generator.Generate(
    ctx,
    report.CheckResults,
    report.ComplianceControls,
    core.ReportFormatJSON,
)

// Generate HTML report
htmlReport, err := generator.Generate(
    ctx,
    report.CheckResults,
    report.ComplianceControls,
    core.ReportFormatHTML,
)
```

## Benefits

1. **No Code Changes**: Add frameworks via YAML
2. **Separation**: Checks independent from compliance
3. **Evidence**: Audit-ready evidence in all results
4. **Multi-Framework**: One execution, multiple frameworks
5. **Extensible**: Easy to add checks and frameworks
