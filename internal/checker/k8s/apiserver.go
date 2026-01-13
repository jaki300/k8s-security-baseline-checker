package k8s

import (
	"context"
	"fmt"
	"strings"

	"github.com/k8s-security-baseline-checker/internal/checker"
	"github.com/k8s-security-baseline-checker/pkg/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// checkAPIServerFlags validates API server command-line flags (CIS 1.2.1-1.2.12)
func (k *K8sChecker) checkAPIServerFlags(ctx context.Context, check types.Check, options *checker.ExecutionOptions) (*types.Result, error) {

	// Find API server pods
	pods, err := k.client.Clientset.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		LabelSelector: "component=kube-apiserver",
	})
	if err != nil {
		return k.CreateErrorResult(check, fmt.Errorf("failed to list API server pods: %w", err)), nil
	}

	if len(pods.Items) == 0 {
		return k.CreateWarnResult(check, []string{"No API server pods found"}, "No API server pods found in kube-system namespace"), nil
	}

	var violations []string
	var details []string

	// Required flags for CIS 1.2.x
	requiredFlags := map[string]struct {
		value       string
		description string
		severity    types.Severity
	}{
		"--anonymous-auth": {
			value:       "false",
			description: "Disable anonymous authentication",
			severity:    types.SeverityCritical,
		},
		"--authorization-mode": {
			value:       "Node,RBAC",
			description: "Enable Node and RBAC authorization",
			severity:    types.SeverityCritical,
		},
		"--audit-log-maxage": {
			value:       "30",
			description: "Retain audit logs for 30 days",
			severity:    types.SeverityHigh,
		},
		"--audit-log-maxbackup": {
			value:       "10",
			description: "Keep 10 audit log backups",
			severity:    types.SeverityHigh,
		},
		"--audit-log-maxsize": {
			value:       "100",
			description: "Maximum audit log file size (MB)",
			severity:    types.SeverityHigh,
		},
		"--request-timeout": {
			value:       "300s",
			description: "API request timeout",
			severity:    types.SeverityMedium,
		},
		"--service-account-lookup": {
			value:       "true",
			description: "Enable service account lookup",
			severity:    types.SeverityHigh,
		},
		"--enable-bootstrap-token-auth": {
			value:       "false",
			description: "Disable bootstrap token authentication",
			severity:    types.SeverityHigh,
		},
		"--tls-min-version": {
			value:       "VersionTLS12",
			description: "Minimum TLS version",
			severity:    types.SeverityHigh,
		},
	}

	// Dangerous flags that should be disabled
	dangerousFlags := map[string]string{
		"--insecure-port":         "Should be set to 0 or removed",
		"--insecure-bind-address": "Should be set to 0 or removed",
	}

	for _, pod := range pods.Items {
		container := findAPIServerContainer(pod.Spec.Containers)
		if container == nil {
			details = append(details, fmt.Sprintf("Pod %s/%s: No kube-apiserver container found", pod.Namespace, pod.Name))
			continue
		}

		flags := extractAPIServerFlags(container.Command)
		podName := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)

		// Check required flags
		for flag, config := range requiredFlags {
			actualValue, exists := flags[flag]
			if !exists {
				violations = append(violations, fmt.Sprintf("%s: Missing flag '%s' (%s)", podName, flag, config.description))
				details = append(details, fmt.Sprintf("%s: Missing required flag '%s'. Remediation: Add '%s=%s' to API server configuration", podName, flag, flag, config.value))
			} else if !validateAPIServerFlag(flag, actualValue, config.value) {
				violations = append(violations, fmt.Sprintf("%s: Invalid value for '%s' (got '%s', expected '%s')", podName, flag, actualValue, config.value))
				details = append(details, fmt.Sprintf("%s: Flag '%s' has invalid value '%s'. Expected '%s'. Remediation: Set '%s=%s' in API server configuration", podName, flag, actualValue, config.value, flag, config.value))
			}
		}

		// Check dangerous flags
		for dangerousFlag, reason := range dangerousFlags {
			if value, exists := flags[dangerousFlag]; exists && value != "0" && value != "" {
				violations = append(violations, fmt.Sprintf("%s: Dangerous flag '%s' is enabled (value: '%s')", podName, dangerousFlag, value))
				details = append(details, fmt.Sprintf("%s: Dangerous flag '%s' is enabled. %s. Remediation: Remove flag or set '%s=0'", podName, dangerousFlag, reason, dangerousFlag))
			}
		}
	}

	if len(violations) > 0 {
		return k.CreateFailResult(check, details, fmt.Sprintf("Found %d API server flag violation(s) across %d pod(s)", len(violations), len(pods.Items))), nil
	}

	return k.CreatePassResult(check, fmt.Sprintf("All API server flags are properly configured (%d pod(s) checked)", len(pods.Items))), nil
}

// checkEtcdEncryption validates etcd encryption at rest (CIS 1.1.20)
func (k *K8sChecker) checkEtcdEncryption(ctx context.Context, check types.Check, options *checker.ExecutionOptions) (*types.Result, error) {

	// Find API server pods
	pods, err := k.client.Clientset.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		LabelSelector: "component=kube-apiserver",
	})
	if err != nil {
		return k.CreateErrorResult(check, fmt.Errorf("failed to list API server pods: %w", err)), nil
	}

	if len(pods.Items) == 0 {
		return k.CreateWarnResult(check, []string{"No API server pods found"}, "No API server pods found in kube-system namespace"), nil
	}

	var violations []string
	var details []string
	encryptionEnabled := false

	for _, pod := range pods.Items {
		container := findAPIServerContainer(pod.Spec.Containers)
		if container == nil {
			continue
		}

		flags := extractAPIServerFlags(container.Command)
		podName := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)

		// Check for encryption provider config
		encryptionConfig, exists := flags["--encryption-provider-config"]
		if !exists || encryptionConfig == "" {
			violations = append(violations, fmt.Sprintf("%s: etcd encryption not configured", podName))
			details = append(details, fmt.Sprintf("%s: API server does not have --encryption-provider-config flag set. etcd data is stored in plaintext. Remediation: Configure encryption provider using --encryption-provider-config flag pointing to encryption configuration file. See: https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/", podName))
		} else {
			encryptionEnabled = true
			// Check encryption provider type (simplified - would need to read actual config file)
			if !strings.Contains(encryptionConfig, "aescbc") && !strings.Contains(encryptionConfig, "secretbox") {
				details = append(details, fmt.Sprintf("%s: Encryption provider configured but may be using weak provider. Prefer 'aescbc' or 'secretbox'. Remediation: Update encryption provider config to use aescbc or secretbox provider", podName))
			}
		}
	}

	if len(violations) > 0 {
		return k.CreateFailResult(check, details, fmt.Sprintf("etcd encryption not configured: %d violation(s) found", len(violations))), nil
	}

	if encryptionEnabled {
		return k.CreatePassResult(check, fmt.Sprintf("etcd encryption is properly configured (%d pod(s) checked)", len(pods.Items))), nil
	}

	return k.CreateWarnResult(check, details, "etcd encryption configuration needs review"), nil
}

// Helper functions

func findAPIServerContainer(containers []corev1.Container) *corev1.Container {
	for i := range containers {
		if containers[i].Name == "kube-apiserver" {
			return &containers[i]
		}
	}
	return nil
}

func extractAPIServerFlags(command []string) map[string]string {
	flags := make(map[string]string)
	for i, arg := range command {
		if strings.HasPrefix(arg, "--") {
			parts := strings.SplitN(arg, "=", 2)
			flagName := parts[0]
			if len(parts) == 2 {
				flags[flagName] = parts[1]
			} else {
				// Check if next argument is the value
				if i+1 < len(command) && !strings.HasPrefix(command[i+1], "--") {
					flags[flagName] = command[i+1]
				} else {
					flags[flagName] = "true" // Boolean flag
				}
			}
		}
	}
	return flags
}

func validateAPIServerFlag(flag, actual, expected string) bool {
	// Special handling for flags that can have multiple values
	if flag == "--authorization-mode" {
		modes := strings.Split(actual, ",")
		expectedModes := strings.Split(expected, ",")
		for _, expectedMode := range expectedModes {
			found := false
			for _, mode := range modes {
				if strings.TrimSpace(strings.ToLower(mode)) == strings.TrimSpace(strings.ToLower(expectedMode)) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	}

	return strings.EqualFold(actual, expected)
}
