# Compliance Mapping Engine Documentation

## Overview

The compliance mapping engine provides a sophisticated system for mapping security check results to multiple compliance frameworks with support for many-to-many relationships and flexible scoring.

## Key Features

### 1. Many-to-Many Mappings

- **One Check → Many Controls**: A single security check can map to multiple controls across different frameworks
- **One Control → Many Checks**: A single compliance control can be satisfied by multiple security checks
- **Bidirectional**: Full support for complex mapping relationships

### 2. Per-Framework Scoring

- **Weighted Average**: Weight controls by importance or category
- **Pass/Fail**: Simple binary compliance scoring
- **Severity-Weighted**: Weight by security severity levels
- **Category-Based**: Different weights per control category

### 3. Custom Frameworks

- **YAML-Based**: Define custom frameworks without code changes
- **Flexible Scoring**: Configure scoring methods per framework
- **Organization-Specific**: Tailor to internal policies

## Architecture

### Mapping Engine

```go
type MappingEngine struct {
    controlToFrameworks map[string][]FrameworkMapping
    frameworkToControls  map[string][]ControlMapping
    frameworkMetadata    map[string]FrameworkMetadata
}
```

### Data Flow

```
Security Check Result
    ↓
Mapping Engine
    ↓
Map to Multiple Frameworks (Many-to-Many)
    ↓
Calculate Per-Framework Scores
    ↓
Generate Compliance Report
```

## YAML Mapping Format

### Basic Structure

```yaml
framework: NIST
version: "800-53 Rev 5"
metadata:
  name: "NIST SP 800-53 Rev 5"
  scoring:
    method: weighted_average
    weighted_by_category: true
    minimum_compliance_score: 80.0
    category_weights:
      "Access Control": 1.5

mappings:
  - control_id: "AC-3"
    control_name: "Access Enforcement"
    category: "Access Control"
    check_ids:                    # Many checks → One control
      - "cis-2.1.1"
      - "cis-2.1.2"
    weight: 1.5
    mapping_rule:
      pass_status: COMPLIANT
      fail_status: NON_COMPLIANT
      warn_status: PARTIAL
```

### Many-to-Many Example

**One Check → Many Controls:**
```yaml
# Check "cis-2.1.1" maps to:
# - NIST AC-3
# - ISO 27001 A.9.4.2
# - SOC 2 CC6.1
# - CustomOrgSecurity ORG-CRIT-001
```

**One Control → Many Checks:**
```yaml
# NIST AC-3 is satisfied by:
# - cis-1.1.1 (RBAC wildcard)
# - cis-2.1.1 (Pods non-root)
# - cis-2.1.2 (Privileged containers)
```

## Scoring Methods

### 1. Weighted Average

Calculates weighted average based on control weights:

```yaml
scoring:
  method: weighted_average
  weighted_by_category: true
  category_weights:
    "Access Control": 1.5
    "Network Security": 1.3
```

**Formula:**
```
Score = (Σ(Compliant Weights) + Σ(Partial Weights × 0.5)) / Σ(Total Weights) × 100
```

### 2. Pass/Fail

Simple binary scoring:

```yaml
scoring:
  method: pass_fail
```

**Formula:**
```
Score = (Compliant Controls / Total Applicable Controls) × 100
```

### 3. Severity-Weighted

Weights by security severity:

```yaml
scoring:
  method: severity_weighted
```

**Weights:**
- Critical: 4.0
- High: 3.0
- Medium: 2.0
- Low: 1.0
- Info: 0.5

## Usage Examples

### Basic Usage

```go
// Create engine
engine := compliance.NewMappingEngine()

// Load mappings
compliance.LoadMappingsFromDirectory(engine, "config/mappings/")

// Map single check result to frameworks
result := &core.CheckResult{
    CheckID: "cis-2.1.1",
    Status:  core.StatusFail,
}

frameworkControls := engine.MapResultToFrameworks(result)
// Returns: map[string][]ComplianceControl
// {
//   "NIST": [AC-3],
//   "ISO27001": [A.9.4.2],
//   "SOC2": [CC6.1],
// }
```

### Calculate Scores

```go
// Calculate score for a framework
score, err := engine.CalculateFrameworkScore("NIST", controls)

fmt.Printf("Score: %.2f%% (Grade: %s)\n", score.Score, score.Grade)
fmt.Printf("Compliant: %d/%d\n", score.CompliantControls, score.TotalControls)
fmt.Printf("Category Scores: %v\n", score.CategoryScores)
```

### Custom Framework

```go
// Create custom framework programmatically
mappings := []compliance.ControlMappingDef{
    {
        ControlID:   "ORG-CRIT-001",
        ControlName: "Prevent Root Access",
        Category:    "Critical Security",
        CheckIDs:    []string{"cis-2.1.1"},
        Weight:      2.0,
    },
}

scoringConfig := compliance.ScoringConfig{
    Method:                 compliance.ScoringMethodWeightedAverage,
    MinimumComplianceScore: 90.0,
}

compliance.CreateCustomFramework(
    engine,
    "CustomOrgSecurity",
    "1.0",
    "Custom organizational framework",
    scoringConfig,
    mappings,
)
```

## Example YAML Files

### NIST 800-53 (`config/mappings/enhanced-nist-800-53.yaml`)

- Maps CIS controls to NIST 800-53 Rev 5
- Weighted by category
- Minimum compliance: 80%

### ISO 27001 (`config/mappings/enhanced-iso-27001.yaml`)

- Maps CIS controls to ISO/IEC 27001:2022
- Severity-weighted scoring
- Minimum compliance: 75%

### SOC 2 (`config/mappings/enhanced-soc2.yaml`)

- Maps CIS controls to SOC 2 Trust Services Criteria
- Category-weighted scoring
- Minimum compliance: 85%

### Custom Framework (`config/mappings/custom-org-framework.yaml`)

- Example organizational framework
- Custom categories and weights
- Higher compliance threshold (90%)

## Scoring Output

```go
FrameworkScore{
    Framework:            "NIST",
    TotalControls:        15,
    CompliantControls:    12,
    NonCompliantControls:  2,
    PartialControls:      1,
    Score:                85.5,
    Grade:                "B",
    CategoryScores: map[string]CategoryScore{
        "Access Control": {
            Category:        "Access Control",
            TotalControls:   8,
            CompliantControls: 7,
            Score:           87.5,
        },
    },
    Compliant: true,  // Score >= minimum (80%)
}
```

## Benefits

1. **Flexibility**: Many-to-many mappings support complex relationships
2. **Accuracy**: Multiple scoring methods for different use cases
3. **Extensibility**: Add custom frameworks via YAML
4. **Transparency**: Clear scoring logic and evidence
5. **Enterprise-Ready**: Supports industry standards and custom requirements

## Best Practices

1. **Weight Critical Controls**: Assign higher weights to critical security controls
2. **Use Categories**: Organize controls by category for better reporting
3. **Set Appropriate Thresholds**: Configure minimum compliance scores per framework
4. **Document Mappings**: Include descriptions for each control mapping
5. **Validate Evidence**: Ensure evidence requirements are met for compliance
