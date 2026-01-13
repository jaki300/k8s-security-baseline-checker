# Compliance Documentation

## Overview

This document describes how the Kubernetes Security Baseline Checker ensures compliance accuracy and audit readiness.

## Compliance Scoring

### Scoring Logic

Compliance scores are calculated deterministically using weighted scoring:

**Formula**: `score = (passed_weight + (warn_weight * 0.5)) / total_applicable_weight * 100`

### Status Handling

- **PASS**: Full weight counted toward compliance
- **FAIL**: No weight counted (0% compliance)
- **WARN**: Half weight counted (50% compliance)
- **ERROR**: Treated as FAIL (0% compliance)
- **SKIP/NOT_APPLICABLE**: Excluded from calculation

### Grade Calculation

- **A+**: 90-100%
- **A**: 80-89%
- **B**: 70-79%
- **C**: 60-69%
- **D**: 50-59%
- **F**: 0-49%

### Example

```
Check 1: PASS, Weight 2 → +2
Check 2: WARN, Weight 1 → +0.5
Check 3: FAIL, Weight 1 → +0
Total Weight: 4
Score: (2 + 0.5) / 4 * 100 = 62.5% (Grade: C)
```

## Evidence Model

### Evidence Structure

Every check result includes standardized evidence:

```json
{
  "evidence": [
    {
      "timestamp": "2024-01-15T10:30:00Z",
      "data_source": "kubernetes-api",
      "object_reference": "pod/default/my-pod",
      "raw_value": {
        "securityContext": {
          "runAsUser": 0
        }
      },
      "evaluation_logic": "Checked securityContext.runAsUser == 0",
      "type": "resource",
      "description": "Pod is running as root user (UID 0)"
    }
  ]
}
```

### Evidence Requirements

- **Timestamp**: When evidence was collected
- **Data Source**: Where evidence came from (API, config file, runtime check)
- **Object Reference**: Kubernetes resource identifier
- **Raw Value**: Sanitized raw data (secrets redacted)
- **Evaluation Logic**: How the evidence was evaluated
- **Type**: Evidence type (resource, config, log, query, scan)
- **Description**: Human-readable explanation

## Framework Mapping Validation

### Validation at Startup

Framework mappings are validated when the system starts:

1. **Control ID Validation**: All control IDs must be non-empty
2. **Check ID Validation**: All referenced check IDs must exist
3. **Framework Metadata**: All frameworks must have name and version
4. **Duplicate Detection**: Control IDs must be unique within a framework

### Mapping Structure

```yaml
mappings:
  - control_id: "AC-3"
    control_name: "Access Enforcement"
    check_ids:
      - "cis-1.1.1"
      - "cis-2.1.1"
    weight: 1.5
    mapping_rule:
      pass_status: COMPLIANT
      fail_status: NON_COMPLIANT
      warn_status: PARTIAL
```

### Version Tracking

Framework mappings are versioned:

- Mapping files include version metadata
- Reports reference mapping versions
- Version mismatches are logged

## Compliance Frameworks

### CIS Kubernetes Benchmark v1.8

- **Coverage**: 50+ controls
- **Categories**: Control Plane, Node, RBAC, Pod Security, Network
- **Validation**: Checks validated against CIS v1.8 specification

### NIST SP 800-53 Rev 5

- **Coverage**: ~20 controls mapped
- **Categories**: Access Control, System Protection, Configuration Management
- **Scoring**: Weighted average with category weights

### ISO/IEC 27001:2022

- **Coverage**: ~15 controls mapped
- **Categories**: Access Control, Operations Security, Communications Security
- **Scoring**: Pass/fail with severity weighting

### SOC 2 Type II

- **Coverage**: ~10 criteria mapped
- **Categories**: Logical Access, System Operations, Monitoring
- **Scoring**: Weighted average

## Report Generation

### Report Formats

1. **JSON**: Machine-readable format for automation
2. **HTML**: Executive dashboard with visualizations
3. **CSV**: Auditor-friendly tabular format

### Report Contents

- Executive summary with compliance scores
- Per-framework compliance breakdown
- Detailed check results with evidence
- Remediation guidance for each finding
- Risk assessment and prioritization

### Evidence Trail

Every finding includes:

- Evidence collection timestamp
- Data source attribution
- Object references
- Sanitized raw values
- Evaluation logic

## Audit Readiness

### Requirements Met

✅ **Evidence-Based**: Every finding includes concrete evidence  
✅ **Multi-Framework**: Single check maps to multiple frameworks  
✅ **Deterministic Scoring**: Consistent, reproducible scores  
✅ **Version Tracking**: Framework and mapping versions tracked  
✅ **Remediation Guidance**: Step-by-step remediation for each finding  

### Auditor Workflow

1. Import CSV report into audit tool
2. Filter by framework (NIST, ISO 27001, SOC 2)
3. Review evidence for each non-compliant control
4. Verify remediation steps have been implemented
5. Track compliance trends over time

## Compliance Validation

### Pre-Release Validation

Before production release:

1. ✅ Framework mappings validated at startup
2. ✅ Scoring logic tested and documented
3. ✅ Evidence model standardized
4. ⚠️ Check accuracy validated against framework specs (ongoing)
5. ⚠️ Mapping accuracy verified with framework experts (recommended)

### Ongoing Validation

- Regular validation against framework updates
- Auditor feedback incorporation
- Mapping accuracy reviews
- Check coverage expansion

## Limitations

### Current Limitations

1. **Check Coverage**: Not all CIS v1.8 controls implemented
2. **Framework Coverage**: Partial coverage for NIST, ISO, SOC 2
3. **Validation**: Check accuracy requires ongoing validation
4. **Mapping Accuracy**: Mappings should be reviewed by framework experts

### Recommendations

1. Engage CIS-certified auditor for CIS validation
2. Review NIST mappings with NIST experts
3. Validate ISO mappings against ISO 27001:2022
4. Obtain SOC 2 auditor feedback on report format

## References

- [CIS Kubernetes Benchmark v1.8](https://www.cisecurity.org/benchmark/kubernetes)
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [ISO/IEC 27001:2022](https://www.iso.org/standard/27001)
- [SOC 2 Trust Services Criteria](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report.html)
