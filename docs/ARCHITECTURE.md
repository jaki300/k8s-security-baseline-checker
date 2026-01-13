# Enterprise Kubernetes Security Baseline Checker - Architecture

## Overview

This document describes the enterprise-grade architecture of the Kubernetes Security Baseline Checker, designed with a plugin-based system that separates security checks from compliance mappings.

## Core Principles

1. **Separation of Concerns**: Checks are independent from compliance frameworks
2. **Plugin Architecture**: New checks and frameworks can be added without code changes
3. **Evidence-Based**: All results include concrete evidence
4. **YAML-Driven**: Frameworks and controls defined in YAML for easy extension
5. **Extensible**: Add new compliance frameworks without modifying core code

## Architecture Components

### 1. Core Interfaces (`pkg/core/`)

#### `Checker` Interface
- Defines the contract for all security checks
- Each check implements `Execute()` to return evidence-based results
- Checks are independent and can be registered as plugins

#### `ComplianceMapper` Interface
- Maps check results to compliance framework controls
- Implementations can be YAML-based (no code changes needed)
- Supports multiple frameworks simultaneously

#### `PluginRegistry`
- Manages registered checkers and compliance mappers
- Enables dynamic plugin loading
- Provides discovery and lookup capabilities

### 2. Check Execution (`pkg/checker/`)

#### `Engine`
- Executes checks sequentially or in parallel
- Manages check lifecycle and error handling
- Coordinates with plugin registry

#### `Loader`
- Loads benchmark definitions from YAML files
- Parses control definitions
- Supports directory-based loading

### 3. Compliance Mapping (`pkg/compliance/`)

#### `YAMLComplianceMapper`
- Loads compliance mappings from YAML files
- Maps check results to framework controls
- Supports multiple frameworks (NIST, ISO27001, SOC2, etc.)

#### `Orchestrator`
- Coordinates check execution and compliance mapping
- Generates comprehensive compliance reports
- Supports multiple frameworks in a single run

### 4. Configuration (`config/`)

#### `config/controls/`
- YAML files defining security controls
- Each control references a checker ID
- Independent of compliance frameworks

#### `config/mappings/`
- YAML files mapping controls to compliance frameworks
- One file per framework (NIST, ISO27001, SOC2)
- Can be added/modified without code changes

## Folder Structure

```
k8s-security-baseline-checker/
├── pkg/
│   ├── core/                    # Core interfaces and types
│   │   ├── interfaces.go        # Checker, ComplianceMapper, PluginRegistry interfaces
│   │   └── registry.go          # Plugin registry implementation
│   ├── checker/                  # Check execution engine
│   │   ├── engine.go             # Check execution engine
│   │   └── loader.go            # YAML benchmark loader
│   └── compliance/               # Compliance mapping system
│       ├── mapper.go             # YAML-based compliance mapper
│       └── orchestrator.go      # Compliance orchestrator
├── internal/
│   └── plugins/                  # Plugin implementations
│       └── k8s/                  # Kubernetes-specific checkers
├── config/
│   ├── controls/                 # Control definitions (YAML)
│   │   └── cis-kubernetes.yaml
│   └── mappings/                 # Compliance framework mappings (YAML)
│       ├── nist-800-53.yaml
│       ├── iso-27001.yaml
│       └── soc2.yaml
└── docs/
    └── ARCHITECTURE.md           # This file
```

## Data Flow

```
1. Load Benchmark (YAML)
   └─> Defines controls and checker IDs

2. Execute Checks
   └─> Plugin Registry finds checkers
   └─> Engine executes checks
   └─> Returns evidence-based results

3. Map to Compliance Frameworks
   └─> Load compliance mappings (YAML)
   └─> Map check results to controls
   └─> Generate compliance status

4. Generate Report
   └─> Combine check results + compliance mappings
   └─> Generate evidence-based report
```

## Adding New Compliance Frameworks

### Step 1: Create Mapping File

Create `config/mappings/my-framework.yaml`:

```yaml
framework: MyFramework
version: "1.0"
controls:
  - control_id: "MF-1.1"
    control_name: "Access Control"
    control_description: "Ensure proper access controls"
    category: "Access Control"
    check_id: "cis-2.1.1"
    mapping_rule:
      pass_status: COMPLIANT
      fail_status: NON_COMPLIANT
      warn_status: PARTIAL
      requires_evidence: true
```

### Step 2: Load at Runtime

```go
mapper, err := compliance.LoadMappersFromDirectory("config/mappings/")
orchestrator.RegisterComplianceMapper(mapper["MyFramework"])
```

**No code changes required!**

## Adding New Checks

### Step 1: Implement Checker Interface

```go
type MyChecker struct {
    // Your implementation
}

func (c *MyChecker) Execute(ctx context.Context, target core.CheckTarget) (*core.CheckResult, error) {
    // Your check logic
    return &core.CheckResult{
        CheckID: "my-check-id",
        Status: core.StatusPass,
        Evidence: []core.Evidence{...},
    }, nil
}
```

### Step 2: Register Checker

```go
registry.RegisterChecker(&MyChecker{})
```

### Step 3: Add to Control Definition

Add to `config/controls/cis-kubernetes.yaml`:

```yaml
- id: "cis-X.X.X"
  checker_id: "my-check-id"
  # ... other fields
```

## Evidence-Based Results

All check results include:

- **Evidence**: Concrete proof supporting the result
  - Resource configurations
  - Query results
  - Scan outputs
  - Log entries

- **Findings**: Specific issues found
  - Resource identifiers
  - Severity levels
  - Remediation guidance

- **Metadata**: Additional context
  - Timestamps
  - Execution duration
  - Check version

## Benefits

1. **No Code Changes for Frameworks**: Add NIST, ISO27001, SOC2 via YAML
2. **Separation of Concerns**: Checks independent from compliance
3. **Evidence-Based**: Audit-ready reports with concrete evidence
4. **Extensible**: Easy to add new checks and frameworks
5. **Enterprise-Ready**: Supports multiple frameworks simultaneously

## Example Usage

```go
// 1. Initialize
registry := core.NewPluginRegistry()
engine := checker.NewEngine(registry)
orchestrator := compliance.NewOrchestrator(engine, registry)

// 2. Load compliance mappings
mappers, _ := compliance.LoadMappersFromDirectory("config/mappings/")
for _, mapper := range mappers {
    orchestrator.RegisterComplianceMapper(mapper)
}

// 3. Execute with compliance mapping
report, _ := orchestrator.ExecuteBenchmarkWithCompliance(
    ctx,
    benchmark,
    target,
    []string{"NIST", "ISO27001", "SOC2"},
    true, // parallel
)
```

## Compliance Framework Support

- **CIS**: Center for Internet Security Kubernetes Benchmark
- **NIST**: NIST 800-53 Rev 5
- **ISO 27001**: ISO/IEC 27001:2022
- **SOC 2**: Trust Services Criteria 2022
- **Custom**: Add your own via YAML
