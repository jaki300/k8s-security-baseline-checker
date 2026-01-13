# Enterprise Kubernetes Security Compliance Platform

**Automated security compliance validation for Kubernetes clusters aligned with CIS, NIST, ISO 27001, and SOC 2 frameworks.**

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)](https://golang.org)

## Overview

The Enterprise Kubernetes Security Compliance Platform provides continuous, automated security compliance validation for Kubernetes environments. Built for security teams, compliance officers, and auditors, the platform delivers evidence-based compliance reports that map security checks to multiple industry frameworks simultaneously.

### Compliance Philosophy

**Continuous Compliance Through Automation**
- **Evidence-Based**: Every finding includes concrete evidence (resource configurations, API queries, scan results)
- **Multi-Framework Mapping**: Execute checks once, map results to CIS, NIST, ISO 27001, SOC 2, and custom frameworks
- **Risk-Prioritized**: Findings are scored by severity and risk, enabling efficient remediation
- **Auditor-Ready**: Reports include detailed evidence trails and remediation guidance suitable for compliance audits
- **Extensible**: Add custom frameworks and checks without code changes via YAML configuration

## Supported Compliance Frameworks

### Industry Standards

| Framework | Version | Coverage | Use Case |
|-----------|---------|----------|----------|
| **CIS Kubernetes Benchmark** | v1.8 | 50+ controls | Security hardening baseline |
| **NIST SP 800-53** | Rev 5 | Access Control, System Protection | Federal and government compliance |
| **ISO/IEC 27001** | 2022 | Access Control, Operations Security | International security management |
| **SOC 2** | Type II | Logical Access, System Operations | Service organization controls |

### Framework Coverage

**CIS Kubernetes Benchmark v1.8**
- Control Plane Security (API Server, etcd, Controller Manager)
- Node Security Configuration
- RBAC and Service Account Security
- Pod Security Standards and Policies
- Network Policies and Namespace Isolation
- Encryption at Rest and in Transit

**NIST SP 800-53 Rev 5**
- Access Control (AC-3, AC-6, AC-7)
- System and Communications Protection (SC-7, SC-8, SC-12)
- Configuration Management (CM-2, CM-6, CM-7)
- Audit and Accountability (AU-2, AU-3)

**ISO/IEC 27001:2022**
- Access Control (A.9.2, A.9.4)
- Operations Security (A.12.2, A.12.4)
- Communications Security (A.13.1, A.13.2)
- System Acquisition, Development, and Maintenance (A.14.2)

**SOC 2 Trust Services Criteria**
- CC6.1: Logical and Physical Access Controls
- CC6.2: Logical Access Security
- CC7.1: System Operations
- CC7.2: System Monitoring

## How Auditors Use the Output

### CSV Reports (Auditor-Friendly Format)

The CSV format provides a comprehensive, tabular view ideal for audit analysis:

**Main Section**: One row per security check with:
- Check ID, name, category, status, severity
- Risk score and framework control mappings
- Evidence details (type, source, description)
- Findings (ID, title, resource, severity)
- Remediation steps, commands, and priority

**Framework Summary Section**: Per-framework compliance metrics:
- Total controls, compliant/non-compliant/partial counts
- Compliance score (0-100) and letter grade
- Compliance status (COMPLIANT/NON-COMPLIANT)

**Audit Workflow**:
1. Import CSV into spreadsheet or audit tool
2. Filter by framework (NIST, ISO 27001, SOC 2)
3. Review evidence for each non-compliant control
4. Verify remediation steps have been implemented
5. Track compliance trends over time

### Evidence Trail

Every finding includes:
- **Evidence Type**: Resource configuration, API query result, scan output
- **Source**: Kubernetes API, configuration file, runtime check
- **Description**: What was checked and what was found
- **Content**: Raw evidence data for verification

### Remediation Guidance

Each finding provides:
- **Priority**: IMMEDIATE, HIGH, MEDIUM, LOW
- **Summary**: Brief description of the issue
- **Steps**: Step-by-step remediation instructions
- **Commands**: Executable commands (where applicable)
- **Estimated Time**: Time to remediate
- **References**: Links to documentation

## Example Compliance Report

### Executive Summary

```
Enterprise Compliance Report
Generated: 2024-01-15 10:30:00 UTC
Cluster: production-cluster (Kubernetes 1.28.0, AWS)

Overall Compliance Score: 75.0% (Grade: C)
Risk Score: 65.0 (Risk Level: HIGH)

Framework Compliance:
├─ CIS Kubernetes Benchmark: 82.5% (Grade: B) ✓ COMPLIANT
├─ NIST SP 800-53 Rev 5: 71.2% (Grade: C) ✗ NON-COMPLIANT
├─ ISO/IEC 27001:2022: 68.8% (Grade: D) ✗ NON-COMPLIANT
└─ SOC 2 Type II: 78.3% (Grade: C) ✓ COMPLIANT

Check Summary:
├─ Total Checks: 50
├─ Passed: 30 (60%)
├─ Failed: 15 (30%)
└─ Warnings: 5 (10%)
```

### Framework Compliance Detail

**NIST SP 800-53 Rev 5 Compliance**

| Control ID | Control Name | Category | Status | Evidence |
|------------|--------------|----------|--------|----------|
| AC-3 | Access Enforcement | Access Control | NON_COMPLIANT | 3 findings |
| AC-6 | Least Privilege | Access Control | COMPLIANT | ✓ Verified |
| SC-7 | Boundary Protection | System Protection | PARTIAL | 1 warning |
| SC-12 | Cryptographic Key Management | System Protection | NON_COMPLIANT | 2 findings |

**Compliance Score**: 71.2% (Grade: C)
- Compliant Controls: 12/20 (60%)
- Non-Compliant Controls: 6/20 (30%)
- Partial Controls: 2/20 (10%)

### Detailed Finding Example

**Check ID**: `cis-1.2.1`  
**Status**: FAIL  
**Severity**: CRITICAL  
**Risk Score**: 10.0  
**Category**: Control Plane - API Server

**Framework Mappings**:
- NIST AC-3 (Access Enforcement) - NON_COMPLIANT
- ISO 27001 A.9.4.2 (Secure log-on) - NON_COMPLIANT
- SOC 2 CC6.1 (Logical Access Security) - NON_COMPLIANT

**Evidence**:
```
Type: config
Source: kube-system/kube-apiserver-master-1
Description: API server pod configuration
Content:
  - Flag: --anonymous-auth
    Value: true
    Required: false
    Issue: Anonymous authentication enabled
```

**Findings**:
1. **Finding ID**: `cis-1.2.1-finding-1`
   - **Title**: Anonymous Authentication Enabled
   - **Resource**: `pod/kube-system/kube-apiserver-master-1`
   - **Severity**: CRITICAL
   - **Description**: API server allows anonymous requests without authentication

**Remediation**:
- **Priority**: IMMEDIATE
- **Summary**: Disable anonymous authentication on API server
- **Steps**:
  1. Edit API server manifest: `/etc/kubernetes/manifests/kube-apiserver.yaml`
  2. Add flag: `--anonymous-auth=false`
  3. Restart API server pod
- **Commands**:
  ```bash
  kubectl edit pod kube-apiserver-master-1 -n kube-system
  # Add: --anonymous-auth=false
  ```
- **Estimated Time**: 5 minutes
- **References**: 
  - CIS Kubernetes Benchmark v1.8, Control 1.2.1
  - NIST SP 800-53 Rev 5, AC-3

## Installation

### Binary Download

Download pre-built binaries from [releases](https://github.com/yourorg/k8s-security-checker/releases).

### Build from Source

```bash
git clone https://github.com/yourorg/k8s-security-baseline-checker.git
cd k8s-security-baseline-checker
make build-cli
```

### Docker

```bash
docker build -f deployments/docker/Dockerfile -t k8s-compliance:latest .
docker run -v ~/.kube:/root/.kube k8s-compliance:latest check k8s --benchmark cis
```

### Kubernetes Deployment

```bash
kubectl apply -f deployments/kubernetes/
```

## Usage

### CLI - Single Framework

```bash
# CIS Kubernetes Benchmark
./k8s-checker check k8s --benchmark cis --output cis-report.html

# NIST SP 800-53
./k8s-checker check k8s --benchmark nist --output nist-report.html

# ISO 27001
./k8s-checker check k8s --benchmark iso-27001 --output iso-report.html

# SOC 2
./k8s-checker check k8s --benchmark soc2 --output soc2-report.html
```

### CLI - Multi-Framework Report

```bash
# Generate compliance report with all frameworks
./k8s-checker check k8s \
  --benchmark cis \
  --frameworks nist,iso-27001,soc2 \
  --output compliance-report.html

# Generate CSV for auditors
./k8s-checker check k8s \
  --benchmark cis \
  --frameworks nist,iso-27001,soc2 \
  --format csv \
  --output audit-report.csv
```

### CLI - Namespace-Specific

```bash
# Check production namespace
./k8s-checker check k8s \
  --namespace production \
  --benchmark cis \
  --frameworks nist,soc2 \
  --output production-compliance.html
```

### API Server

```bash
# Start API server
./k8s-checker-server --port 8080

# Run compliance check via API
curl -X POST http://localhost:8080/api/v1/compliance/check \
  -H "Content-Type: application/json" \
  -d '{
    "benchmark": "cis",
    "frameworks": ["nist", "iso-27001", "soc2"],
    "format": "json"
  }'
```

## Report Formats

### JSON (Machine-Readable)

Structured data format for automation and integration:

```json
{
  "id": "report-20240115-103000",
  "generated_at": "2024-01-15T10:30:00Z",
  "cluster": {
    "name": "production-cluster",
    "k8s_version": "1.28.0"
  },
  "overall_compliance": {
    "compliance_score": 75.0,
    "grade": "C",
    "total_checks": 50,
    "passed_checks": 30
  },
  "framework_mappings": {
    "NIST-800-53": {
      "compliance_score": 71.2,
      "grade": "C",
      "compliant": false
    }
  },
  "risk_score": {
    "overall_score": 65.0,
    "risk_level": "HIGH"
  },
  "check_results": [...]
}
```

### HTML (Executive Dashboard)

Interactive web-based dashboard with:
- Executive summary cards
- Framework compliance visualization
- Risk assessment breakdown
- Detailed check results with expandable evidence
- Remediation guidance

### CSV (Auditor-Friendly)

Tabular format with:
- One row per check with framework mappings
- Evidence details
- Findings and remediation steps
- Framework compliance summary section

## Configuration

Create `config.yaml`:

```yaml
kubeconfig: ~/.kube/config
benchmark_dir: ./benchmarks
mapping_dir: ./config/mappings
output_dir: ./reports

server:
  port: 8080
  address: 0.0.0.0

clusters:
  - name: production
    kubeconfig: ~/.kube/prod-config
  - name: staging
    kubeconfig: ~/.kube/staging-config

frameworks:
  - name: nist
    mapping_file: ./config/mappings/enhanced-nist-800-53.yaml
  - name: iso-27001
    mapping_file: ./config/mappings/enhanced-iso-27001.yaml
  - name: soc2
    mapping_file: ./config/mappings/enhanced-soc2.yaml
```

## Architecture

### Plugin-Based Design

- **Check Plugins**: Security checks implemented as plugins
- **Compliance Mappers**: Framework mappings defined in YAML
- **Report Generators**: Multiple output formats
- **Evidence Collection**: Automated evidence gathering

### Many-to-Many Mapping

A single security check can map to multiple compliance controls across frameworks:

```
cis-2.1.1 (Pods non-root)
├─ NIST AC-3 (Access Enforcement)
├─ ISO 27001 A.9.4.2 (Secure log-on)
├─ SOC 2 CC6.1 (Logical Access Security)
└─ Custom Framework ORG-CRIT-001
```

### Scoring Methods

- **Weighted Average**: Controls weighted by importance
- **Pass/Fail**: Binary compliance scoring
- **Severity-Weighted**: Weighted by security severity

## Development

```bash
# Run tests
make test

# Build for all platforms
make build-all

# Run linter
make lint

# Format code
make fmt
```

## Documentation

### Getting Started
- **[How to Use Guide](docs/HOW_TO_USE.md)** - Complete usage guide for CLI and API
- [Usage Examples](docs/USAGE.md)

### Enterprise Features
- **[Security Documentation](docs/SECURITY.md)** - Authentication, authorization, and security controls
- **[Compliance Documentation](docs/COMPLIANCE.md)** - Compliance features and audit readiness
- [Enterprise Implementation Report](docs/ENTERPRISE_IMPLEMENTATION_REPORT.md) - Technical details

### Technical Documentation
- [Architecture Documentation](docs/ARCHITECTURE.md)
- [Compliance Mapping Guide](docs/COMPLIANCE_MAPPING.md)
- [Compliance Reporting Guide](docs/COMPLIANCE_REPORTING.md)
- [CIS v1.8 Checks](docs/CIS_V1.8_CHECKS.md)

### Quality Assurance
- [QA Report](QA_REPORT.md) - Initial quality assessment
- [Enterprise QA Report](docs/QA_REPORT_ENTERPRISE.md) - Post-implementation QA

## License

See [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please see our contributing guidelines.

---

**Built for security teams, compliance officers, and auditors who need continuous, evidence-based compliance validation for Kubernetes environments.**
