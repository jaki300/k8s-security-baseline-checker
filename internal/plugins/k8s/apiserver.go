package k8s

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/k8s-security-baseline-checker/pkg/core"
	"github.com/k8s-security-baseline-checker/pkg/k8s"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// APIServerChecker checks API server configuration
type APIServerChecker struct {
	client *k8s.Client
}

// NewAPIServerChecker creates a new API server checker
func NewAPIServerChecker(client *k8s.Client) *APIServerChecker {
	return &APIServerChecker{client: client}
}

// CheckAPIServerFlags validates API server command-line flags (CIS 1.2.x)
func (c *APIServerChecker) CheckAPIServerFlags(ctx context.Context) (*core.CheckResult, error) {
	checkID := "cis-1.2.1"
	startTime := time.Now()

	// Find API server pods
	pods, err := c.client.Clientset.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		LabelSelector: "component=kube-apiserver",
	})
	if err != nil {
		return &core.CheckResult{
			CheckID:   checkID,
			Status:    core.StatusError,
			Message:   fmt.Sprintf("Failed to list API server pods: %v", err),
			Timestamp: time.Now(),
			Duration:  time.Since(startTime),
		}, nil
	}

	if len(pods.Items) == 0 {
		return &core.CheckResult{
			CheckID:   checkID,
			Status:    core.StatusWarn,
			Message:   "No API server pods found in kube-system namespace",
			Timestamp: time.Now(),
			Duration:  time.Since(startTime),
		}, nil
	}

	var findings []core.Finding
	var evidence []core.Evidence
	allCompliant := true

	// Required flags for CIS 1.2.x
	requiredFlags := map[string]string{
		"--anonymous-auth":                    "false",
		"--authorization-mode":                "Node,RBAC", // Should include Node and RBAC
		"--enable-admission-plugins":          "NodeRestriction,PodSecurityPolicy", // Or PodSecurity
		"--audit-log-maxage":                  "30",
		"--audit-log-maxbackup":               "10",
		"--audit-log-maxsize":                 "100",
		"--audit-log-path":                    "/var/log/audit.log",
		"--request-timeout":                   "300s",
		"--service-account-lookup":             "true",
		"--enable-bootstrap-token-auth":       "false",
		"--tls-cipher-suites":                  "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"--tls-min-version":                   "VersionTLS12",
	}

	for _, pod := range pods.Items {
		container := findContainerByName(pod.Spec.Containers, "kube-apiserver")
		if container == nil {
			continue
		}

		flags := extractFlags(container.Command)
		podEvidence := core.Evidence{
			Type:        core.EvidenceTypeConfig,
			Source:      fmt.Sprintf("pod/%s/%s", pod.Namespace, pod.Name),
			Description: "API server pod configuration",
			Content: map[string]interface{}{
				"pod":       pod.Name,
				"namespace": pod.Namespace,
				"flags":     flags,
			},
			Timestamp: time.Now(),
		}
		evidence = append(evidence, podEvidence)

		// Check each required flag
		for flag, expectedValue := range requiredFlags {
			actualValue, exists := flags[flag]
			if !exists {
				findings = append(findings, core.Finding{
					ID:          fmt.Sprintf("%s-%s-missing", pod.Name, flag),
					Title:       fmt.Sprintf("Missing required flag: %s", flag),
					Description: fmt.Sprintf("API server pod '%s' is missing required flag '%s'", pod.Name, flag),
					Severity:    core.SeverityCritical,
					Resource:    fmt.Sprintf("pod/kube-system/%s", pod.Name),
					Remediation: fmt.Sprintf("Add flag '%s=%s' to API server configuration", flag, expectedValue),
				})
				allCompliant = false
				continue
			}

			// Validate flag value
			if !validateFlagValue(flag, actualValue, expectedValue) {
				findings = append(findings, core.Finding{
					ID:          fmt.Sprintf("%s-%s-invalid", pod.Name, flag),
					Title:       fmt.Sprintf("Invalid flag value: %s", flag),
					Description: fmt.Sprintf("API server pod '%s' has invalid value for '%s': got '%s', expected '%s'", pod.Name, flag, actualValue, expectedValue),
					Severity:    core.SeverityCritical,
					Resource:    fmt.Sprintf("pod/kube-system/%s", pod.Name),
					Remediation: fmt.Sprintf("Set flag '%s=%s' in API server configuration", flag, expectedValue),
				})
				allCompliant = false
			}
		}

		// Check for dangerous flags
		dangerousFlags := []string{"--insecure-port", "--insecure-bind-address"}
		for _, dangerousFlag := range dangerousFlags {
			if value, exists := flags[dangerousFlag]; exists && value != "0" {
				findings = append(findings, core.Finding{
					ID:          fmt.Sprintf("%s-%s-dangerous", pod.Name, dangerousFlag),
					Title:       fmt.Sprintf("Dangerous flag enabled: %s", dangerousFlag),
					Description: fmt.Sprintf("API server pod '%s' has dangerous flag '%s' enabled with value '%s'", pod.Name, dangerousFlag, value),
					Severity:    core.SeverityCritical,
					Resource:    fmt.Sprintf("pod/kube-system/%s", pod.Name),
					Remediation: fmt.Sprintf("Remove or disable flag '%s' (set to 0)", dangerousFlag),
				})
				allCompliant = false
			}
		}
	}

	status := core.StatusPass
	severity := core.SeverityInfo
	if !allCompliant {
		status = core.StatusFail
		severity = core.SeverityCritical
	}

	return &core.CheckResult{
		CheckID:   checkID,
		Status:    status,
		Severity:  severity,
		Evidence:  evidence,
		Findings:  findings,
		Message:   fmt.Sprintf("Checked %d API server pod(s), found %d issue(s)", len(pods.Items), len(findings)),
		Timestamp: time.Now(),
		Duration:  time.Since(startTime),
	}, nil
}

// CheckEtcdEncryption validates etcd encryption at rest (CIS 1.1.20)
func (c *APIServerChecker) CheckEtcdEncryption(ctx context.Context) (*core.CheckResult, error) {
	checkID := "cis-1.1.20"
	startTime := time.Now()

	// Check for encryption configuration in API server
	pods, err := c.client.Clientset.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{
		LabelSelector: "component=kube-apiserver",
	})
	if err != nil {
		return &core.CheckResult{
			CheckID:   checkID,
			Status:    core.StatusError,
			Message:   fmt.Sprintf("Failed to list API server pods: %v", err),
			Timestamp: time.Now(),
			Duration:  time.Since(startTime),
		}, nil
	}

	var findings []core.Finding
	var evidence []core.Evidence
	encryptionEnabled := false

	for _, pod := range pods.Items {
		container := findContainerByName(pod.Spec.Containers, "kube-apiserver")
		if container == nil {
			continue
		}

		flags := extractFlags(container.Command)
		podEvidence := core.Evidence{
			Type:        core.EvidenceTypeConfig,
			Source:      fmt.Sprintf("pod/%s/%s", pod.Namespace, pod.Name),
			Description: "API server encryption configuration",
			Content: map[string]interface{}{
				"pod":       pod.Name,
				"namespace": pod.Namespace,
				"flags":     flags,
			},
			Timestamp: time.Now(),
		}
		evidence = append(evidence, podEvidence)

		// Check for encryption provider config
		if encryptionConfig, exists := flags["--encryption-provider-config"]; exists && encryptionConfig != "" {
			encryptionEnabled = true
		} else {
			findings = append(findings, core.Finding{
				ID:          fmt.Sprintf("%s-no-encryption", pod.Name),
				Title:       "etcd encryption not configured",
				Description: fmt.Sprintf("API server pod '%s' does not have encryption provider configured. etcd data is stored in plaintext.", pod.Name),
				Severity:    core.SeverityCritical,
				Resource:    fmt.Sprintf("pod/kube-system/%s", pod.Name),
				Remediation: "Configure encryption provider using --encryption-provider-config flag. See: https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/",
			})
		}

		// Check encryption provider type
		if encryptionConfig, exists := flags["--encryption-provider-config"]; exists {
			// Try to read the encryption config file from the pod
			// This is a simplified check - in production, you'd need to read the actual config file
			if !strings.Contains(encryptionConfig, "aescbc") && !strings.Contains(encryptionConfig, "secretbox") {
				findings = append(findings, core.Finding{
					ID:          fmt.Sprintf("%s-weak-encryption", pod.Name),
					Title:       "Weak encryption provider",
					Description: fmt.Sprintf("API server pod '%s' may be using weak encryption provider. Prefer aescbc or secretbox.", pod.Name),
					Severity:    core.SeverityHigh,
					Resource:    fmt.Sprintf("pod/kube-system/%s", pod.Name),
					Remediation: "Use aescbc or secretbox encryption provider. Avoid identity provider for production.",
				})
			}
		}
	}

	status := core.StatusPass
	severity := core.SeverityInfo
	if !encryptionEnabled {
		status = core.StatusFail
		severity = core.SeverityCritical
	} else if len(findings) > 0 {
		status = core.StatusWarn
		severity = core.SeverityHigh
	}

	return &core.CheckResult{
		CheckID:   checkID,
		Status:    status,
		Severity:  severity,
		Evidence:  evidence,
		Findings:  findings,
		Message:   fmt.Sprintf("etcd encryption: %v, found %d issue(s)", encryptionEnabled, len(findings)),
		Timestamp: time.Now(),
		Duration:  time.Since(startTime),
	}, nil
}

// Helper functions

func findContainerByName(containers []corev1.Container, name string) *corev1.Container {
	for i := range containers {
		if containers[i].Name == name {
			return &containers[i]
		}
	}
	return nil
}

func extractFlags(command []string) map[string]string {
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

func validateFlagValue(flag, actual, expected string) bool {
	// Special handling for flags that can have multiple values
	if flag == "--authorization-mode" {
		modes := strings.Split(actual, ",")
		expectedModes := strings.Split(expected, ",")
		for _, expectedMode := range expectedModes {
			found := false
			for _, mode := range modes {
				if strings.TrimSpace(mode) == strings.TrimSpace(expectedMode) {
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

	if flag == "--enable-admission-plugins" {
		plugins := strings.Split(actual, ",")
		expectedPlugins := strings.Split(expected, ",")
		for _, expectedPlugin := range expectedPlugins {
			found := false
			for _, plugin := range plugins {
				if strings.TrimSpace(plugin) == strings.TrimSpace(expectedPlugin) {
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

	return actual == expected
}
