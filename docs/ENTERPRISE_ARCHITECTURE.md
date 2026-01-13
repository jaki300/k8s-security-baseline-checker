# Enterprise Architecture Summary

## Overview

This document summarizes the enterprise-grade architecture redesign that separates security checks from compliance mappings, enabling framework additions without code changes.

## Key Design Decisions

### 1. Separation of Concerns

- **Checks**: Independent security checks that produce evidence-based results
- **Compliance Mappings**: YAML-based mappings that connect checks to framework controls
- **No Coupling**: Checks don't know about compliance frameworks

### 2. Plugin Architecture

- **Checker Interface**: All checks implement a common interface
- **Plugin Registry**: Dynamic registration and discovery
- **Extensibility**: Add new checks without modifying core code

### 3. YAML-Driven Configuration

- **Control Definitions**: Security controls defined in YAML
- **Compliance Mappings**: Framework mappings defined in YAML
- **No Code Changes**: Add frameworks by adding YAML files

### 4. Evidence-Based Results

- **Concrete Evidence**: All results include supporting evidence
- **Audit-Ready**: Evidence suitable for compliance audits
- **Transparency**: Clear traceability from check to evidence

## Folder Structure

```
k8s-security-baseline-checker/
├── pkg/
│   ├── core/                          # Core interfaces and types
│   │   ├── interfaces.go              # Checker, ComplianceMapper, PluginRegistry
│   │   └── registry.go                # Plugin registry implementation
│   ├── checker/                       # Check execution engine
│   │   ├── engine.go                  # Execution engine
│   │   └── loader.go                  # YAML benchmark loader
│   └── compliance/                   # Compliance mapping system
│       ├── mapper.go                  # YAML-based compliance mapper
│       └── orchestrator.go            # Compliance orchestrator
│
├── config/
│   ├── controls/                      # Control definitions (YAML)
│   │   └── cis-kubernetes.yaml        # CIS controls
│   └── mappings/                      # Compliance framework mappings (YAML)
│       ├── nist-800-53.yaml          # NIST 800-53 mappings
│       ├── iso-27001.yaml            # ISO 27001 mappings
│       └── soc2.yaml                 # SOC 2 mappings
│
└── docs/
    ├── ARCHITECTURE.md                # Detailed architecture
    ├── USAGE.md                      # Usage guide
    └── ENTERPRISE_ARCHITECTURE.md     # This file
```

## Core Components

### 1. Core Interfaces (`pkg/core/interfaces.go`)

**Checker Interface**
- `Execute()`: Runs check and returns evidence-based results
- `Validate()`: Checks if checker can handle target
- `Metadata()`: Returns check metadata

**ComplianceMapper Interface**
- `Map()`: Maps check results to compliance controls
- `Framework()`: Returns framework name
- `GetControls()`: Returns all controls

**PluginRegistry Interface**
- `RegisterChecker()`: Register new checker
- `RegisterComplianceMapper()`: Register mapper
- `GetChecker()`: Retrieve checker by ID
- `GetComplianceMapper()`: Retrieve mapper by framework

### 2. Check Execution (`pkg/checker/`)

**Engine**
- Executes checks sequentially or in parallel
- Manages check lifecycle
- Coordinates with plugin registry

**Loader**
- Loads benchmarks from YAML
- Parses control definitions
- Supports directory-based loading

### 3. Compliance Mapping (`pkg/compliance/`)

**YAMLComplianceMapper**
- Loads mappings from YAML files
- Maps check results to framework controls
- Supports multiple frameworks

**Orchestrator**
- Coordinates check execution and mapping
- Generates comprehensive reports
- Supports multi-framework execution

## Data Flow

```
┌─────────────────┐
│  Load Benchmark │ (YAML)
│  (Controls)     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Execute Checks │ (Plugin Registry)
│  (Evidence)     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Map to Frameworks│ (YAML Mappings)
│ (NIST/ISO/SOC2) │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Generate Report  │ (Evidence-Based)
│ (Compliance)    │
└─────────────────┘
```

## Adding New Compliance Framework

### Example: Adding ISO 27001

**Step 1**: Create `config/mappings/iso-27001.yaml`

```yaml
framework: ISO27001
version: "ISO/IEC 27001:2022"
controls:
  - control_id: "A.9.2.1"
    control_name: "User registration"
    check_id: "cis-2.1.1"
    mapping_rule:
      pass_status: COMPLIANT
      fail_status: NON_COMPLIANT
```

**Step 2**: Load at runtime

```go
mappers, _ := compliance.LoadMappersFromDirectory("config/mappings/")
orchestrator.RegisterComplianceMapper(mappers["ISO27001"])
```

**Result**: ISO 27001 compliance reporting without code changes!

## Evidence-Based Results

Every check result includes:

```go
CheckResult{
    CheckID: "check-pods-nonroot",
    Status: StatusFail,
    Evidence: []Evidence{
        {
            Type: EvidenceTypeResource,
            Source: "k8s-api",
            Content: map[string]interface{}{
                "pod": "my-pod",
                "runAsUser": 0,
            },
        },
    },
    Findings: []Finding{
        {
            Title: "Pod running as root",
            Remediation: "Set runAsNonRoot=true",
        },
    },
}
```

## Benefits

1. ✅ **No Code Changes**: Add frameworks via YAML
2. ✅ **Separation**: Checks independent from compliance
3. ✅ **Evidence**: Audit-ready evidence in all results
4. ✅ **Multi-Framework**: One execution, multiple frameworks
5. ✅ **Extensible**: Easy to add checks and frameworks
6. ✅ **Enterprise-Ready**: Supports industry standards

## Supported Frameworks

- **CIS**: Center for Internet Security Kubernetes Benchmark
- **NIST**: NIST 800-53 Rev 5
- **ISO 27001**: ISO/IEC 27001:2022
- **SOC 2**: Trust Services Criteria 2022
- **Custom**: Add your own via YAML

## Next Steps

1. Implement example checkers using the new architecture
2. Migrate existing checks to new plugin system
3. Add more compliance framework mappings
4. Build report generators for each framework
5. Add CLI integration for the new architecture

## Migration Path

The new architecture can coexist with the existing system:

1. **Phase 1**: New architecture alongside existing (current)
2. **Phase 2**: Migrate checks to plugin system
3. **Phase 3**: Switch to new architecture as default
4. **Phase 4**: Deprecate old architecture

This allows gradual migration without breaking changes.
