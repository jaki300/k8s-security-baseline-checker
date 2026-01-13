package redaction

import (
	"regexp"
	"strings"
)

// Redactor provides sensitive data redaction for logs and reports
// Enterprise requirement: Ensure logs and reports never expose secrets
type Redactor struct {
	patterns []*redactionPattern
}

type redactionPattern struct {
	name    string
	pattern *regexp.Regexp
	replace string
}

// NewRedactor creates a new redactor with default patterns
func NewRedactor() *Redactor {
	r := &Redactor{
		patterns: []*redactionPattern{},
	}

	// Add default patterns for common sensitive data
	r.AddPattern("jwt_token", regexp.MustCompile(`(?i)(bearer\s+)?eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`), "[REDACTED_JWT]")
	r.AddPattern("api_key", regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*([A-Za-z0-9_-]{20,})`), "$1: [REDACTED_API_KEY]")
	r.AddPattern("secret", regexp.MustCompile(`(?i)(secret|password|token|credential)\s*[:=]\s*([^\s"']{10,})`), "$1: [REDACTED_SECRET]")
	
	// Certificate patterns - Go regexp doesn't support backreferences, so we create separate patterns
	r.AddPattern("certificate", regexp.MustCompile(`-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----`), "[REDACTED_CERTIFICATE]")
	r.AddPattern("private_key", regexp.MustCompile(`-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----`), "[REDACTED_CERTIFICATE]")
	r.AddPattern("rsa_private_key", regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----`), "[REDACTED_CERTIFICATE]")
	
	r.AddPattern("base64_secret", regexp.MustCompile(`(?i)(data|value)\s*[:=]\s*([A-Za-z0-9+/]{50,}={0,2})`), "$1: [REDACTED_BASE64]")
	r.AddPattern("aws_access_key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "[REDACTED_AWS_KEY]")
	r.AddPattern("aws_secret_key", regexp.MustCompile(`(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*([A-Za-z0-9/+=]{40})`), "$1: [REDACTED_AWS_SECRET]")
	r.AddPattern("private_ip", regexp.MustCompile(`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`), "[REDACTED_IP]")

	return r
}

// AddPattern adds a custom redaction pattern
func (r *Redactor) AddPattern(name string, pattern *regexp.Regexp, replace string) {
	r.patterns = append(r.patterns, &redactionPattern{
		name:    name,
		pattern: pattern,
		replace: replace,
	})
}

// Redact applies all redaction patterns to the input string
func (r *Redactor) Redact(input string) string {
	if input == "" {
		return input
	}

	result := input
	for _, pattern := range r.patterns {
		result = pattern.pattern.ReplaceAllString(result, pattern.replace)
	}

	return result
}

// RedactMap redacts sensitive values in a map structure
func (r *Redactor) RedactMap(data map[string]interface{}) map[string]interface{} {
	if data == nil {
		return data
	}

	redacted := make(map[string]interface{})
	for k, v := range data {
		key := strings.ToLower(k)
		
		// Redact known sensitive keys
		if strings.Contains(key, "secret") || 
		   strings.Contains(key, "password") || 
		   strings.Contains(key, "token") || 
		   strings.Contains(key, "credential") ||
		   strings.Contains(key, "key") ||
		   strings.Contains(key, "certificate") ||
		   strings.Contains(key, "kubeconfig") {
			redacted[k] = "[REDACTED]"
			continue
		}

		// Recursively redact nested maps
		if nestedMap, ok := v.(map[string]interface{}); ok {
			redacted[k] = r.RedactMap(nestedMap)
		} else if str, ok := v.(string); ok {
			redacted[k] = r.Redact(str)
		} else {
			redacted[k] = v
		}
	}

	return redacted
}

// RedactSlice redacts sensitive data in a slice
func (r *Redactor) RedactSlice(slice []string) []string {
	if slice == nil {
		return slice
	}

	redacted := make([]string, len(slice))
	for i, item := range slice {
		redacted[i] = r.Redact(item)
	}

	return redacted
}

// RedactKubeconfig redacts sensitive content from kubeconfig data
func (r *Redactor) RedactKubeconfig(kubeconfig string) string {
	if kubeconfig == "" {
		return kubeconfig
	}

	// Redact certificates
	kubeconfig = r.Redact(kubeconfig)
	
	// Additional kubeconfig-specific patterns
	patterns := []struct {
		pattern *regexp.Regexp
		replace string
	}{
		{regexp.MustCompile(`(?i)(certificate-authority-data|client-certificate-data|client-key-data):\s*[^\s]+`), "$1: [REDACTED]"},
		{regexp.MustCompile(`(?i)(token|bearer-token):\s*[^\s]+`), "$1: [REDACTED]"},
	}

	result := kubeconfig
	for _, p := range patterns {
		result = p.pattern.ReplaceAllString(result, p.replace)
	}

	return result
}
