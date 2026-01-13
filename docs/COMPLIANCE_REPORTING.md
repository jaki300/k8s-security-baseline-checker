# Enterprise Compliance Reporting Module

## Overview

The Enterprise Compliance Reporting Module generates comprehensive compliance reports in multiple formats (JSON, HTML, CSV) with detailed information about:

- **Control Results**: Individual check execution results with status and severity
- **Framework Mapping**: Maps checks to compliance frameworks (NIST, ISO 27001, SOC 2, CIS, etc.)
- **Risk Scoring**: Calculates overall risk scores and risk breakdown by severity/category
- **Evidence**: Detailed evidence supporting each check result
- **Remediation Steps**: Actionable remediation guidance with priority levels

## Features

### Report Formats

1. **JSON** (Machine-readable)
   - Complete structured data
   - Suitable for automation and integration
   - Includes all metadata and evidence

2. **HTML** (Executive Dashboard)
   - Visual dashboard with compliance scores
   - Framework compliance overview
   - Risk assessment visualization
   - Detailed check results with expandable evidence
   - Remediation guidance

3. **CSV** (Auditor-friendly)
   - Tabular format for analysis
   - One row per check with framework mappings
   - Framework compliance summary section
   - Easy to import into spreadsheets

### Report Components

#### 1. Executive Dashboard
- Overall compliance score and grade
- Risk score and risk level
- Total checks breakdown (passed/failed/warned)
- Framework count

#### 2. Framework Compliance
- Per-framework compliance scores
- Compliant/non-compliant/partial control counts
- Category-level scores
- Compliance status (COMPLIANT/NON-COMPLIANT)

#### 3. Risk Assessment
- Overall risk score (0-100, higher = more risk)
- Risk level (CRITICAL, HIGH, MEDIUM, LOW, MINIMAL)
- Severity breakdown
- Category risk scores
- Top risks list

#### 4. Detailed Check Results
- Check ID and name
- Status (PASS/FAIL/WARN/ERROR/SKIP)
- Severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- Category
- Risk score
- Framework control mappings
- Evidence (expandable in HTML)
- Remediation steps with priority

## Usage

### Basic Usage

```go
package main

import (
    "github.com/k8s-security-baseline-checker/pkg/compliance"
    "github.com/k8s-security-baseline-checker/pkg/reporting"
    "github.com/k8s-security-baseline-checker/pkg/types"
)

func main() {
    // 1. Create mapping engine and load mappings
    mappingEngine := compliance.NewMappingEngine()
    err := mappingEngine.LoadMappingsFromFile("config/mappings/enhanced-nist-800-53.yaml")
    if err != nil {
        panic(err)
    }

    // 2. Create report builder
    builder := reporting.NewReportBuilder(mappingEngine)

    // 3. Build compliance report from types.Report
    report := &types.Report{
        ID: "report-123",
        Cluster: types.ClusterInfo{
            Name:       "production-cluster",
            K8sVersion: "1.28.0",
            Provider:   "aws",
        },
        Benchmark: "cis",
        BenchmarkVersion: "1.8",
        Results: []types.Result{
            // ... check results
        },
        // ... other fields
    }

    checkMetadata := make(map[string]types.Check)
    // Populate checkMetadata with check definitions

    complianceReport, err := builder.BuildComplianceReport(report, checkMetadata)
    if err != nil {
        panic(err)
    }

    // 4. Generate reports in different formats
    generator := reporting.NewReportGenerator("./reports")

    // Generate JSON report
    err = generator.GenerateComplianceReport(complianceReport, "json", "report.json")
    if err != nil {
        panic(err)
    }

    // Generate HTML dashboard
    err = generator.GenerateComplianceReport(complianceReport, "html", "report.html")
    if err != nil {
        panic(err)
    }

    // Generate CSV report
    err = generator.GenerateComplianceReport(complianceReport, "csv", "report.csv")
    if err != nil {
        panic(err)
    }
}
```

### Integration with Check Execution

```go
// After executing checks
results := executeChecks(...)

// Build types.Report
report := &types.Report{
    ID:          generateReportID(),
    Cluster:     clusterInfo,
    Benchmark:   "cis",
    Results:     results,
    GeneratedAt: time.Now(),
    Duration:    executionDuration,
}

// Build compliance report with framework mappings
complianceReport, err := builder.BuildComplianceReport(report, checkMetadata)
```

## Report Structure

### JSON Report Structure

```json
{
  "id": "report-123",
  "generated_at": "2024-01-15T10:30:00Z",
  "duration": "2m30s",
  "cluster": {
    "name": "production-cluster",
    "k8s_version": "1.28.0",
    "provider": "aws"
  },
  "benchmark": {
    "id": "cis",
    "name": "CIS Kubernetes Benchmark",
    "version": "1.8"
  },
  "check_results": [
    {
      "check_id": "cis-1.2.1",
      "status": "FAIL",
      "severity": "CRITICAL",
      "evidence": [...],
      "findings": [...],
      "remediation": {
        "summary": "Fix API server flags",
        "steps": ["Step 1", "Step 2"],
        "priority": "IMMEDIATE"
      },
      "framework_controls": [
        {
          "framework": "NIST-800-53",
          "control_id": "AC-3",
          "status": "NON_COMPLIANT"
        }
      ]
    }
  ],
  "framework_mappings": {
    "NIST-800-53": {
      "framework": "NIST-800-53",
      "compliance_score": 75.5,
      "grade": "C",
      "compliant": false
    }
  },
  "risk_score": {
    "overall_score": 65.0,
    "risk_level": "HIGH",
    "severity_breakdown": {
      "CRITICAL": 5,
      "HIGH": 10
    }
  },
  "overall_compliance": {
    "total_checks": 50,
    "passed_checks": 30,
    "failed_checks": 15,
    "compliance_score": 75.0,
    "grade": "C"
  }
}
```

## Risk Scoring

Risk scores are calculated based on:

1. **Severity Weights**:
   - CRITICAL: 10.0
   - HIGH: 7.0
   - MEDIUM: 4.0
   - LOW: 2.0
   - INFO: 0.5

2. **Finding Count**: Number of security findings per check

3. **Risk Score Formula**: `severity_weight × finding_count`

4. **Overall Risk Score**: Normalized to 0-100 scale (higher = more risk)

5. **Risk Levels**:
   - CRITICAL: ≥80
   - HIGH: ≥60
   - MEDIUM: ≥40
   - LOW: ≥20
   - MINIMAL: <20

## Framework Compliance Scoring

Each framework can use different scoring methods:

1. **Weighted Average**: Controls weighted by importance
2. **Pass/Fail**: Simple pass/fail counting
3. **Severity Weighted**: Weighted by severity of findings

Compliance status is determined by comparing the score to the framework's minimum compliance score threshold.

## Evidence Collection

Evidence is extracted from check result metadata:

```go
result.Metadata["evidence"] = []interface{}{
    map[string]interface{}{
        "type":        "resource",
        "source":      "k8s-api",
        "description": "Pod security context configuration",
        "content": map[string]interface{}{
            "pod": "default/my-pod",
            "runAsNonRoot": false,
        },
    },
}
```

## Remediation Guidance

Remediation information includes:

- **Summary**: Brief description of the issue
- **Steps**: Step-by-step remediation instructions
- **Commands**: Executable commands (if applicable)
- **Priority**: IMMEDIATE, HIGH, MEDIUM, LOW
- **Estimated Time**: Time to remediate
- **References**: Links to documentation

## HTML Dashboard Features

- **Responsive Design**: Works on desktop and mobile
- **Expandable Evidence**: Click to view detailed evidence
- **Color-coded Status**: Visual indicators for status and severity
- **Framework Cards**: Quick overview of framework compliance
- **Risk Indicators**: Visual risk level indicators
- **Print-friendly**: Optimized for printing

## CSV Report Format

The CSV report includes:

1. **Main Section**: One row per check with all details
2. **Framework Summary Section**: Per-framework compliance metrics

Columns:
- Check ID, Name, Category
- Status, Severity, Risk Score
- Framework, Control ID, Control Status
- Evidence details
- Findings
- Remediation information
- Timestamp

## Best Practices

1. **Load All Mappings**: Ensure all framework mappings are loaded before building reports
2. **Include Check Metadata**: Provide complete check definitions for better report quality
3. **Evidence Collection**: Populate evidence in check result metadata for detailed reports
4. **Remediation Steps**: Provide actionable remediation steps in metadata
5. **Regular Reports**: Generate reports regularly to track compliance trends

## Integration Points

- **Check Execution**: Integrates with check execution results
- **Compliance Mapping**: Uses mapping engine for framework mappings
- **Storage**: Reports can be stored in databases or file systems
- **APIs**: JSON reports can be consumed by APIs and automation tools

## Future Enhancements

- PDF report generation
- Trend analysis and historical comparisons
- Custom report templates
- Automated remediation workflows
- Integration with ticketing systems
