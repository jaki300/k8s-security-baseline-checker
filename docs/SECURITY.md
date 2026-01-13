# Security Documentation

## Overview

This document describes the security controls implemented in the Kubernetes Security Baseline Checker to ensure enterprise-ready security posture.

## Authentication & Authorization

### Authentication Methods

The system supports two authentication methods:

1. **JWT Tokens**: JSON Web Tokens signed with HS256 algorithm
2. **API Keys**: Static API keys with associated roles

### Configuration

Authentication is enabled via the `--auth` flag or `auth.enabled` configuration:

```yaml
auth:
  enabled: true
  jwt_secret: "your-secret-key-change-in-production"
  token_expiry: 24h
  api_keys:
    "api-key-123": "user-id-1"
  api_key_roles:
    "api-key-123": "operator"
```

### Roles & Permissions

Three roles are supported:

- **viewer**: Can view benchmarks and reports
- **operator**: Can execute checks and view reports
- **admin**: Full access including configuration management

### API Usage

All API endpoints (except `/health`) require authentication when enabled:

```bash
# Using JWT token
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/v1/benchmarks

# Using API key
curl -H "Authorization: ApiKey <key>" http://localhost:8080/api/v1/benchmarks
```

## Input Validation

### Validated Inputs

All user inputs are validated before processing:

- **Benchmark IDs**: Must be in allowlist (cis, nist, iso-27001, soc2, custom)
- **Framework Names**: Must be in allowlist
- **Output Formats**: Must be in allowlist (json, html, csv, pdf)
- **File Paths**: Sanitized to prevent path traversal attacks
- **Kubernetes Namespaces**: Validated against RFC 1123 naming requirements

### Path Traversal Protection

File paths are sanitized to prevent directory traversal:

- `../` sequences are rejected
- Absolute paths are validated against allowlist
- Null bytes and control characters are rejected

## Sensitive Data Protection

### Data Redaction

The system automatically redacts sensitive data from:

- Logs
- Error messages
- Reports

### Redacted Data Types

- JWT tokens
- API keys
- Passwords and secrets
- Certificates (PEM format)
- AWS access keys
- Private IP addresses
- Kubeconfig content

### Example

```go
redactor := redaction.NewRedactor()
safeLog := redactor.Redact("password: secret123")
// Output: "password: [REDACTED_SECRET]"
```

## Rate Limiting

### Configuration

Rate limiting is configured via:

```yaml
rate_limit:
  rps: 100      # Requests per second
  burst: 200    # Burst capacity
```

### Implementation

Token bucket algorithm is used:

- Default: 100 requests/second per IP
- Burst: 200 requests
- Per-IP or per-token limiting

### Response

When rate limit is exceeded:

```json
{
  "error": "rate limit exceeded"
}
```

HTTP Status: `429 Too Many Requests`

## Error Handling

### Error Model

All errors follow a standardized format:

```go
type AppError struct {
    Code            ErrorCode
    Severity        ErrorSeverity
    Message         string        // User-safe message
    InternalMessage string        // Internal details (not exposed)
    Cause           error
}
```

### Error Codes

- `VALIDATION_ERROR`: Input validation failure
- `AUTHENTICATION_ERROR`: Authentication failure
- `AUTHORIZATION_ERROR`: Authorization failure
- `EXECUTION_ERROR`: Check execution failure
- `TIMEOUT_ERROR`: Operation timeout
- `RATE_LIMIT_ERROR`: Rate limit exceeded

### Panic Recovery

All API endpoints have panic recovery middleware that:

- Catches panics
- Logs stack traces
- Returns user-safe error messages
- Prevents server crashes

## TLS/HTTPS

### Production Requirements

In production, TLS must be enabled:

```yaml
server:
  tls_enabled: true
  tls_cert: /path/to/cert.pem
  tls_key: /path/to/key.pem
```

The server will reject HTTP connections when TLS is enabled.

## Security Best Practices

### Configuration

1. **Change Default Secrets**: Never use default JWT secrets in production
2. **Enable Authentication**: Always enable auth in production
3. **Use TLS**: Always use HTTPS in production
4. **Rotate API Keys**: Regularly rotate API keys
5. **Limit Permissions**: Use least-privilege principle for roles

### Logging

1. **Never Log Secrets**: All sensitive data is automatically redacted
2. **Structured Logging**: Use structured logging for better analysis
3. **Log Levels**: Use appropriate log levels (DEBUG for development, INFO for production)

### API Security

1. **Rate Limiting**: Always enable rate limiting
2. **Input Validation**: All inputs are validated automatically
3. **Error Messages**: User-facing errors don't leak internal details

## Reporting Security Issues

If you discover a security vulnerability, please report it to: security@example.com

Do not open public GitHub issues for security vulnerabilities.

## Compliance

This system implements security controls aligned with:

- NIST SP 800-53 (Access Control, System Protection)
- ISO 27001 (Access Control, Operations Security)
- SOC 2 (Logical Access Controls)
