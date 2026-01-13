package validation

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// Validator provides centralized input validation for CLI, API, and benchmark loader
// Enterprise requirement: Input validation layer to prevent injection attacks and invalid input
type Validator struct {
	allowedBenchmarks  map[string]bool
	allowedFrameworks  map[string]bool
	allowedFormats     map[string]bool
	allowedPathPrefixes []string // Whitelist of allowed path prefixes
}

// NewValidator creates a new validator with default allowlists
func NewValidator() *Validator {
	return &Validator{
		allowedBenchmarks: map[string]bool{
			"cis":           true,
			"cis-kubernetes": true,
			"nist":          true,
			"iso-27001":     true,
			"soc2":          true,
			"custom":        true,
		},
		allowedFrameworks: map[string]bool{
			"cis":       true,
			"nist":      true,
			"iso-27001": true,
			"soc2":      true,
			"custom":    true,
		},
		allowedFormats: map[string]bool{
			"json": true,
			"html": true,
			"csv":  true,
			"pdf":  true,
		},
		allowedPathPrefixes: []string{
			"./",
			"/tmp/",
			"/var/tmp/",
		},
	}
}

// ValidationError represents a validation failure
type ValidationError struct {
	Field   string
	Value   string
	Reason  string
	Code    string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation failed for field '%s' with value '%s': %s", e.Field, e.Value, e.Reason)
}

// ValidateBenchmarkID validates benchmark ID against allowlist
func (v *Validator) ValidateBenchmarkID(benchmarkID string) error {
	if benchmarkID == "" {
		return &ValidationError{
			Field:  "benchmark_id",
			Value:  "",
			Reason: "benchmark ID cannot be empty",
			Code:   "EMPTY_BENCHMARK_ID",
		}
	}

	// Normalize to lowercase for comparison
	normalized := strings.ToLower(benchmarkID)
	if !v.allowedBenchmarks[normalized] {
		return &ValidationError{
			Field:  "benchmark_id",
			Value:  benchmarkID,
			Reason: fmt.Sprintf("benchmark ID '%s' is not in allowed list", benchmarkID),
			Code:   "INVALID_BENCHMARK_ID",
		}
	}

	return nil
}

// ValidateFramework validates framework name against allowlist
func (v *Validator) ValidateFramework(framework string) error {
	if framework == "" {
		return &ValidationError{
			Field:  "framework",
			Value:  "",
			Reason: "framework cannot be empty",
			Code:   "EMPTY_FRAMEWORK",
		}
	}

	normalized := strings.ToLower(framework)
	if !v.allowedFrameworks[normalized] {
		return &ValidationError{
			Field:  "framework",
			Value:  framework,
			Reason: fmt.Sprintf("framework '%s' is not in allowed list", framework),
			Code:   "INVALID_FRAMEWORK",
		}
	}

	return nil
}

// ValidateOutputFormat validates output format against allowlist
func (v *Validator) ValidateOutputFormat(format string) error {
	if format == "" {
		return &ValidationError{
			Field:  "output_format",
			Value:  "",
			Reason: "output format cannot be empty",
			Code:   "EMPTY_FORMAT",
		}
	}

	normalized := strings.ToLower(format)
	if !v.allowedFormats[normalized] {
		return &ValidationError{
			Field:  "output_format",
			Value:  format,
			Reason: fmt.Sprintf("output format '%s' is not in allowed list", format),
			Code:   "INVALID_FORMAT",
		}
	}

	return nil
}

// ValidateFilePath sanitizes and validates file paths to prevent path traversal attacks
func (v *Validator) ValidateFilePath(filePath string) error {
	if filePath == "" {
		return &ValidationError{
			Field:  "file_path",
			Value:  "",
			Reason: "file path cannot be empty",
			Code:   "EMPTY_PATH",
		}
	}

	// Clean the path to resolve any .. or . components
	cleaned := filepath.Clean(filePath)

	// Check for path traversal attempts
	if strings.Contains(cleaned, "..") {
		return &ValidationError{
			Field:  "file_path",
			Value:  filePath,
			Reason: "path traversal detected (contains '..')",
			Code:   "PATH_TRAVERSAL",
		}
	}

	// Check for absolute paths (if not in allowlist)
	if filepath.IsAbs(cleaned) {
		allowed := false
		for _, prefix := range v.allowedPathPrefixes {
			if strings.HasPrefix(cleaned, prefix) {
				allowed = true
				break
			}
		}
		if !allowed {
			return &ValidationError{
				Field:  "file_path",
				Value:  filePath,
				Reason: "absolute path not in allowed prefixes",
				Code:   "INVALID_ABSOLUTE_PATH",
			}
		}
	}

	// Additional security: reject paths with null bytes or control characters
	if strings.ContainsAny(cleaned, "\x00\r\n") {
		return &ValidationError{
			Field:  "file_path",
			Value:  filePath,
			Reason: "path contains invalid characters",
			Code:   "INVALID_CHARACTERS",
		}
	}

	return nil
}

// ValidateKubernetesNamespace validates Kubernetes namespace name according to RFC 1123
// Kubernetes namespace names must be lowercase alphanumeric characters or '-', max 63 chars
var k8sNamespaceRegex = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

func (v *Validator) ValidateKubernetesNamespace(namespace string) error {
	if namespace == "" {
		// Empty namespace is valid (means all namespaces)
		return nil
	}

	if len(namespace) > 63 {
		return &ValidationError{
			Field:  "namespace",
			Value:  namespace,
			Reason: "namespace name exceeds 63 characters",
			Code:   "NAMESPACE_TOO_LONG",
		}
	}

	if !k8sNamespaceRegex.MatchString(namespace) {
		return &ValidationError{
			Field:  "namespace",
			Value:  namespace,
			Reason: "namespace name does not match Kubernetes naming requirements (RFC 1123)",
			Code:   "INVALID_NAMESPACE_FORMAT",
		}
	}

	return nil
}

// ValidateMultiple validates multiple fields at once
func (v *Validator) ValidateMultiple(fields map[string]interface{}) []error {
	var errors []error

	if benchmarkID, ok := fields["benchmark_id"].(string); ok {
		if err := v.ValidateBenchmarkID(benchmarkID); err != nil {
			errors = append(errors, err)
		}
	}

	if framework, ok := fields["framework"].(string); ok {
		if err := v.ValidateFramework(framework); err != nil {
			errors = append(errors, err)
		}
	}

	if format, ok := fields["output_format"].(string); ok {
		if err := v.ValidateOutputFormat(format); err != nil {
			errors = append(errors, err)
		}
	}

	if filePath, ok := fields["file_path"].(string); ok {
		if err := v.ValidateFilePath(filePath); err != nil {
			errors = append(errors, err)
		}
	}

	if namespace, ok := fields["namespace"].(string); ok {
		if err := v.ValidateKubernetesNamespace(namespace); err != nil {
			errors = append(errors, err)
		}
	}

	return errors
}
