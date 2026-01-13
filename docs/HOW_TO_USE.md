# How to Use - Enterprise Kubernetes Security Baseline Checker

## Table of Contents

1. [Quick Start](#quick-start)
2. [CLI Usage](#cli-usage)
3. [API Server Usage](#api-server-usage)
4. [Authentication](#authentication)
5. [Configuration](#configuration)
6. [Common Use Cases](#common-use-cases)
7. [Troubleshooting](#troubleshooting)

---

## Quick Start

### Installation

```bash
# Build from source
make build-cli
make build-server

# Or use pre-built binaries
# Download from releases page
```

### Basic CLI Usage

```bash
# Run CIS benchmark check
./k8s-checker check k8s --benchmark cis --output report.json

# Run with specific namespace
./k8s-checker check k8s --benchmark cis --namespace production --output report.html

# Run with multiple frameworks
./k8s-checker check k8s --benchmark cis --format csv --output compliance.csv
```

### Basic API Usage

```bash
# Start server
./k8s-checker-server --port 8080

# List benchmarks (requires auth)
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/v1/benchmarks
```

---

## CLI Usage

### Command Structure

```bash
k8s-checker [global-flags] <command> [command-flags]
```

### Global Flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--config` | | Config file path | `~/.k8s-checker.yaml` |
| `--verbose` | `-v` | Enable verbose logging | `false` |
| `--output` | `-o` | Output file path | Auto-generated |
| `--format` | `-f` | Output format (json, html, csv, pdf) | `json` |

### Commands

#### Check Kubernetes

```bash
k8s-checker check k8s [flags]
```

**Flags:**
- `--benchmark, -b`: Benchmark ID (cis, nist, iso-27001, soc2, custom)
- `--namespace, -n`: Kubernetes namespace (empty for all)
- `--parallel`: Run checks in parallel (default: true)

**Examples:**

```bash
# Basic check
./k8s-checker check k8s --benchmark cis

# Check specific namespace
./k8s-checker check k8s --benchmark cis --namespace production

# Generate HTML report
./k8s-checker check k8s --benchmark cis --format html --output report.html

# Generate CSV for auditors
./k8s-checker check k8s --benchmark cis --format csv --output audit-report.csv

# Verbose output
./k8s-checker check k8s --benchmark cis -v
```

#### Check Cloud (Not Yet Implemented)

```bash
k8s-checker check cloud [flags]
```

#### Check All

```bash
k8s-checker check all [flags]
```

### Input Validation

The CLI automatically validates all inputs:

**Valid Benchmark IDs:**
- `cis` or `cis-kubernetes`
- `nist`
- `iso-27001`
- `soc2`
- `custom`

**Valid Output Formats:**
- `json` - Machine-readable JSON
- `html` - Executive dashboard
- `csv` - Auditor-friendly CSV
- `pdf` - PDF report (not fully implemented)

**Namespace Validation:**
- Must follow Kubernetes naming rules (RFC 1123)
- Lowercase alphanumeric or `-`
- Max 63 characters
- Cannot start/end with `-`

**Error Examples:**

```bash
# Invalid benchmark ID
$ ./k8s-checker check k8s --benchmark invalid
Error: validation failed for field 'benchmark_id': invalid benchmark ID

# Invalid namespace
$ ./k8s-checker check k8s --namespace Invalid_Namespace
Error: validation failed for field 'namespace': invalid namespace format

# Path traversal attempt
$ ./k8s-checker check k8s --output ../../../etc/passwd
Error: validation failed for field 'file_path': path traversal detected
```

---

## API Server Usage

### Starting the Server

```bash
# Basic start
./k8s-checker-server --port 8080

# With authentication enabled
./k8s-checker-server --port 8080 --auth

# With custom address
./k8s-checker-server --address 0.0.0.0 --port 8080

# With configuration file
./k8s-checker-server --config /etc/k8s-checker/config.yaml
```

### Health Check

```bash
# No authentication required
curl http://localhost:8080/health

# Response:
{
  "status": "healthy",
  "service": "k8s-security-checker"
}
```

### API Endpoints

All API endpoints (except `/health`) require authentication when `--auth` is enabled.

#### List Benchmarks

```bash
GET /api/v1/benchmarks

# Example
curl -H "Authorization: Bearer <token>" \
  http://localhost:8080/api/v1/benchmarks

# Response:
{
  "benchmarks": [
    {
      "id": "cis-kubernetes",
      "name": "CIS Kubernetes Benchmark",
      "version": "1.8",
      "framework": "CIS",
      "checks_count": 50
    }
  ],
  "count": 1
}
```

#### Get Benchmark

```bash
GET /api/v1/benchmarks/:id

# Example
curl -H "Authorization: Bearer <token>" \
  http://localhost:8080/api/v1/benchmarks/cis-kubernetes
```

#### Run Kubernetes Checks

```bash
POST /api/v1/checks/k8s

# Request body
{
  "benchmark_id": "cis",
  "namespace": "production",
  "kubeconfig": "/path/to/kubeconfig",
  "parallel": true,
  "format": "json"
}

# Example
curl -X POST \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "benchmark_id": "cis",
    "namespace": "production",
    "format": "json"
  }' \
  http://localhost:8080/api/v1/checks/k8s

# Response:
{
  "report_id": "report-1234567890",
  "compliance_score": 75,
  "grade": "C",
  "total_checks": 50,
  "passed_checks": 30,
  "failed_checks": 15,
  "warned_checks": 5,
  "generated_at": "2024-01-15T10:30:00Z",
  "duration": "2m30s"
}
```

#### Get Report

```bash
GET /api/v1/reports/:id

# Example
curl -H "Authorization: Bearer <token>" \
  http://localhost:8080/api/v1/reports/report-1234567890
```

#### List Reports

```bash
GET /api/v1/reports

# Example
curl -H "Authorization: Bearer <token>" \
  http://localhost:8080/api/v1/reports
```

### Rate Limiting

Rate limiting is enabled by default:

- **Default**: 100 requests per second per IP
- **Burst**: 200 requests

When rate limit is exceeded:

```json
{
  "error": "rate limit exceeded"
}
```

HTTP Status: `429 Too Many Requests`

---

## Authentication

### Authentication Methods

The API supports two authentication methods:

1. **JWT Tokens** (Bearer tokens)
2. **API Keys**

### Using JWT Tokens

#### Generate Token (Programmatic)

```go
import "github.com/k8s-security-baseline-checker/internal/auth"

authenticator := auth.NewAuthenticator("your-secret", 24*time.Hour)
token, err := authenticator.GenerateToken("user-123", "username", []auth.Role{auth.RoleOperator})
```

#### Use Token in Requests

```bash
curl -H "Authorization: Bearer <jwt-token>" \
  http://localhost:8080/api/v1/benchmarks
```

### Using API Keys

#### Configure API Keys

In `config.yaml`:

```yaml
auth:
  enabled: true
  api_keys:
    "api-key-123": "user-1"
    "api-key-456": "user-2"
  api_key_roles:
    "api-key-123": "operator"
    "api-key-456": "viewer"
```

#### Use API Key in Requests

```bash
curl -H "Authorization: ApiKey api-key-123" \
  http://localhost:8080/api/v1/benchmarks
```

### Roles and Permissions

| Role | Permissions |
|------|-------------|
| **viewer** | View benchmarks, View reports |
| **operator** | View benchmarks, Execute checks, View reports |
| **admin** | All permissions + Manage config, Manage users |

### Authentication Errors

```bash
# Missing authorization header
$ curl http://localhost:8080/api/v1/benchmarks
{
  "error": "authentication required"
}
# HTTP 401 Unauthorized

# Invalid token
$ curl -H "Authorization: Bearer invalid-token" \
  http://localhost:8080/api/v1/benchmarks
{
  "error": "invalid or expired token"
}
# HTTP 401 Unauthorized

# Insufficient permissions
$ curl -H "Authorization: Bearer <viewer-token>" \
  -X POST http://localhost:8080/api/v1/checks/k8s
{
  "error": "permission denied: checks:execute"
}
# HTTP 403 Forbidden
```

---

## Configuration

### Configuration File

Create `config.yaml` or `~/.k8s-checker.yaml`:

```yaml
# Kubernetes configuration
kubeconfig: ~/.kube/config
benchmark_dir: ./benchmarks
mapping_dir: ./config/mappings
output_dir: ./reports

# Server configuration
server:
  port: 8080
  address: 0.0.0.0
  tls_enabled: false
  tls_cert: /path/to/cert.pem
  tls_key: /path/to/key.pem

# Authentication
auth:
  enabled: false
  jwt_secret: "change-me-in-production"
  token_expiry: 24h
  api_keys:
    "api-key-123": "user-1"
  api_key_roles:
    "api-key-123": "operator"

# Rate limiting
rate_limit:
  rps: 100      # Requests per second
  burst: 200    # Burst capacity

# Logging
debug: false
log_level: info
```

### Environment Variables

```bash
# Server
export K8S_CHECKER_SERVER_PORT=8080
export K8S_CHECKER_SERVER_ADDRESS=0.0.0.0

# Authentication
export K8S_CHECKER_AUTH_ENABLED=true
export K8S_CHECKER_AUTH_JWT_SECRET="your-secret-key"

# Rate limiting
export K8S_CHECKER_RATE_LIMIT_RPS=100
export K8S_CHECKER_RATE_LIMIT_BURST=200

# Paths
export K8S_CHECKER_KUBECONFIG=~/.kube/config
export K8S_CHECKER_BENCHMARK_DIR=./benchmarks
export K8S_CHECKER_OUTPUT_DIR=./reports
```

### Command Line Flags

**Server:**
```bash
./k8s-checker-server \
  --port 8080 \
  --address 0.0.0.0 \
  --auth \
  --auth-type jwt \
  --config /path/to/config.yaml
```

**CLI:**
```bash
./k8s-checker \
  --config /path/to/config.yaml \
  --verbose \
  check k8s \
  --benchmark cis \
  --output report.json
```

---

## Common Use Cases

### Use Case 1: Daily Compliance Check

```bash
# Run daily compliance check and save to CSV
./k8s-checker check k8s \
  --benchmark cis \
  --format csv \
  --output compliance-$(date +%Y%m%d).csv
```

### Use Case 2: Production Namespace Audit

```bash
# Check production namespace only
./k8s-checker check k8s \
  --benchmark cis \
  --namespace production \
  --format html \
  --output production-audit.html
```

### Use Case 3: API Integration

```bash
# Generate token (example - implement in your app)
TOKEN=$(generate-jwt-token.sh)

# Run check via API
REPORT_ID=$(curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"benchmark_id": "cis", "format": "json"}' \
  http://localhost:8080/api/v1/checks/k8s | jq -r '.report_id')

# Get report
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/reports/$REPORT_ID > report.json
```

### Use Case 4: Multi-Framework Report

```bash
# Generate report with multiple frameworks
# (Requires framework mapping configuration)

./k8s-checker check k8s \
  --benchmark cis \
  --format csv \
  --output multi-framework-report.csv
```

### Use Case 5: CI/CD Integration

```yaml
# GitHub Actions example
- name: Run Security Check
  run: |
    ./k8s-checker check k8s \
      --benchmark cis \
      --format json \
      --output compliance.json
    
    # Check compliance score
    SCORE=$(jq -r '.compliance_score' compliance.json)
    if [ $SCORE -lt 80 ]; then
      echo "Compliance score $SCORE is below threshold"
      exit 1
    fi
```

---

## Troubleshooting

### Common Issues

#### 1. Authentication Required Error

**Problem:**
```json
{"error": "authentication required"}
```

**Solution:**
- Enable authentication: `./k8s-checker-server --auth`
- Or disable authentication (not recommended for production)
- Include Authorization header in requests

#### 2. Invalid Benchmark ID

**Problem:**
```
Error: validation failed for field 'benchmark_id': invalid benchmark ID
```

**Solution:**
- Use valid benchmark ID: `cis`, `nist`, `iso-27001`, `soc2`, or `custom`
- Check benchmark files exist in `benchmark_dir`

#### 3. Rate Limit Exceeded

**Problem:**
```json
{"error": "rate limit exceeded"}
```

**Solution:**
- Wait before retrying
- Increase rate limit in config: `rate_limit.rps: 200`
- Use exponential backoff in your client

#### 4. Path Traversal Detected

**Problem:**
```
Error: validation failed for field 'file_path': path traversal detected
```

**Solution:**
- Use relative paths: `./report.json` or `report.json`
- Avoid `../` in paths
- Use absolute paths only if in allowlist

#### 5. Invalid Namespace

**Problem:**
```
Error: validation failed for field 'namespace': invalid namespace format
```

**Solution:**
- Use lowercase alphanumeric characters and `-`
- Max 63 characters
- Cannot start/end with `-`
- Example: `production`, `my-namespace`, `ns123`

#### 6. Kubeconfig Not Found

**Problem:**
```
Error: failed to create Kubernetes client
```

**Solution:**
- Set `KUBECONFIG` environment variable
- Or specify in config: `kubeconfig: /path/to/kubeconfig`
- Verify kubeconfig file exists and is valid

### Debug Mode

Enable verbose logging:

```bash
# CLI
./k8s-checker --verbose check k8s --benchmark cis

# Server
./k8s-checker-server --debug
```

Or in config:
```yaml
debug: true
log_level: debug
```

### Getting Help

```bash
# CLI help
./k8s-checker --help
./k8s-checker check k8s --help

# Server help
./k8s-checker-server --help
```

### Logs

Check logs for detailed error information:

```bash
# Server logs show:
# - Authentication attempts
# - Rate limit violations
# - Validation errors (redacted)
# - Execution errors (redacted)
```

---

## Best Practices

### Security

1. **Always enable authentication in production**
2. **Use strong JWT secrets** (change default)
3. **Enable TLS/HTTPS** in production
4. **Rotate API keys** regularly
5. **Use least-privilege roles** (viewer when possible)

### Performance

1. **Use parallel execution** for large clusters (default)
2. **Set appropriate rate limits** based on load
3. **Cache reports** when possible
4. **Use namespace filtering** to reduce check scope

### Compliance

1. **Generate CSV reports** for auditors
2. **Include evidence** in reports (automatic)
3. **Track compliance scores** over time
4. **Review remediation guidance** for failed checks

### Operations

1. **Monitor rate limit violations**
2. **Set up alerting** for low compliance scores
3. **Regular benchmark updates**
4. **Backup configuration files**

---

## Examples

### Complete Workflow Example

```bash
# 1. Start server with authentication
./k8s-checker-server --auth --port 8080

# 2. Generate API token (in your application)
TOKEN="your-jwt-token-here"

# 3. List available benchmarks
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/benchmarks

# 4. Run compliance check
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "benchmark_id": "cis",
    "namespace": "production",
    "format": "csv"
  }' \
  http://localhost:8080/api/v1/checks/k8s

# 5. Get report
REPORT_ID="report-1234567890"
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/reports/$REPORT_ID > report.csv

# 6. Analyze results
# Import CSV into spreadsheet or audit tool
```

### Python Client Example

```python
import requests

API_BASE = "http://localhost:8080/api/v1"
TOKEN = "your-api-key-or-jwt-token"

headers = {"Authorization": f"Bearer {TOKEN}"}

# Run check
response = requests.post(
    f"{API_BASE}/checks/k8s",
    json={"benchmark_id": "cis", "format": "json"},
    headers=headers
)
report_id = response.json()["report_id"]

# Get report
report = requests.get(
    f"{API_BASE}/reports/{report_id}",
    headers=headers
).json()

print(f"Compliance Score: {report['compliance_score']}%")
print(f"Grade: {report['grade']}")
```

---

## Additional Resources

- [Security Documentation](SECURITY.md) - Security controls and configuration
- [Compliance Documentation](COMPLIANCE.md) - Compliance features and audit readiness
- [Implementation Report](ENTERPRISE_IMPLEMENTATION_REPORT.md) - Technical implementation details
- [Change Summary](../CHANGES.md) - List of all changes

---

**Need Help?** Check the troubleshooting section or review the documentation files.
