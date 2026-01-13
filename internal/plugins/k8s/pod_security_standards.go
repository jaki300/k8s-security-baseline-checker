package k8s

import (
	"context"
	"fmt"
	"time"

	"github.com/k8s-security-baseline-checker/pkg/core"
	"github.com/k8s-security-baseline-checker/pkg/k8s"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PodSecurityStandardsChecker validates Pod Security Standards (CIS 5.x)
type PodSecurityStandardsChecker struct {
	client *k8s.Client
}

// NewPodSecurityStandardsChecker creates a new Pod Security Standards checker
func NewPodSecurityStandardsChecker(client *k8s.Client) *PodSecurityStandardsChecker {
	return &PodSecurityStandardsChecker{client: client}
}

// CheckPodSecurityStandards validates Pod Security Standards enforcement (CIS 5.2.1)
func (c *PodSecurityStandardsChecker) CheckPodSecurityStandards(ctx context.Context) (*core.CheckResult, error) {
	checkID := "cis-5.2.1"
	startTime := time.Now()

	namespaces, err := c.client.Clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return &core.CheckResult{
			CheckID:   checkID,
			Status:    core.StatusError,
			Message:   fmt.Sprintf("Failed to list namespaces: %v", err),
			Timestamp: time.Now(),
			Duration:  time.Since(startTime),
		}, nil
	}

	var findings []core.Finding
	var evidence []core.Evidence
	systemNamespaces := map[string]bool{
		"kube-system":     true,
		"kube-public":     true,
		"kube-node-lease": true,
	}

	for _, ns := range namespaces.Items {
		if systemNamespaces[ns.Name] {
			continue
		}

		nsEvidence := core.Evidence{
			Type:        core.EvidenceTypeResource,
			Source:      "k8s-api",
			Description: fmt.Sprintf("Namespace '%s' Pod Security Standards configuration", ns.Name),
			Content: map[string]interface{}{
				"name":        ns.Name,
				"labels":      ns.Labels,
				"annotations": ns.Annotations,
			},
			Timestamp: time.Now(),
		}
		evidence = append(evidence, nsEvidence)

		// Check for Pod Security Standards labels/annotations
		// Kubernetes 1.23+ uses labels, older versions use annotations
		pssEnforce := ns.Labels["pod-security.kubernetes.io/enforce"]
		if pssEnforce == "" {
			pssEnforce = ns.Annotations["pod-security.kubernetes.io/enforce"]
		}

		pssAudit := ns.Labels["pod-security.kubernetes.io/audit"]
		if pssAudit == "" {
			pssAudit = ns.Annotations["pod-security.kubernetes.io/audit"]
		}

		pssWarn := ns.Labels["pod-security.kubernetes.io/warn"]
		if pssWarn == "" {
			pssWarn = ns.Annotations["pod-security.kubernetes.io/warn"]
		}

		if pssEnforce == "" {
			findings = append(findings, core.Finding{
				ID:          fmt.Sprintf("namespace-%s-no-pss-enforce", ns.Name),
				Title:       fmt.Sprintf("Namespace '%s' does not enforce Pod Security Standards", ns.Name),
				Description: fmt.Sprintf("Namespace '%s' does not have Pod Security Standards enforcement configured. Pods can be created without security restrictions.", ns.Name),
				Severity:    core.SeverityHigh,
				Resource:    fmt.Sprintf("namespace/%s", ns.Name),
				Remediation: fmt.Sprintf("Add pod-security.kubernetes.io/enforce label to namespace '%s' with value 'restricted' or 'baseline'", ns.Name),
			})
		} else if pssEnforce != "restricted" && pssEnforce != "baseline" {
			findings = append(findings, core.Finding{
				ID:          fmt.Sprintf("namespace-%s-weak-pss", ns.Name),
				Title:       fmt.Sprintf("Namespace '%s' uses weak Pod Security Standards level", ns.Name),
				Description: fmt.Sprintf("Namespace '%s' has Pod Security Standards enforcement set to '%s'. Consider using 'restricted' for maximum security.", ns.Name, pssEnforce),
				Severity:    core.SeverityMedium,
				Resource:    fmt.Sprintf("namespace/%s", ns.Name),
				Remediation: fmt.Sprintf("Update pod-security.kubernetes.io/enforce label to 'restricted' for namespace '%s'", ns.Name),
			})
		}

		// Check if audit and warn are also configured
		if pssAudit == "" {
			findings = append(findings, core.Finding{
				ID:          fmt.Sprintf("namespace-%s-no-pss-audit", ns.Name),
				Title:       fmt.Sprintf("Namespace '%s' missing Pod Security Standards audit mode", ns.Name),
				Description: fmt.Sprintf("Namespace '%s' does not have Pod Security Standards audit mode configured. Consider adding audit mode for better visibility.", ns.Name),
				Severity:    core.SeverityLow,
				Resource:    fmt.Sprintf("namespace/%s", ns.Name),
				Remediation: fmt.Sprintf("Add pod-security.kubernetes.io/audit label to namespace '%s'", ns.Name),
			})
		}
	}

	status := core.StatusPass
	severity := core.SeverityInfo
	if len(findings) > 0 {
		status = core.StatusFail
		severity = core.SeverityHigh
	}

	return &core.CheckResult{
		CheckID:   checkID,
		Status:    status,
		Severity:  severity,
		Evidence:  evidence,
		Findings:  findings,
		Message:   fmt.Sprintf("Checked %d namespace(s) for Pod Security Standards, found %d issue(s)", len(namespaces.Items), len(findings)),
		Timestamp: time.Now(),
		Duration:  time.Since(startTime),
	}, nil
}

// CheckPodSecurityPolicy validates Pod Security Policy (PSP) or Pod Security Standards (CIS 5.2.2)
func (c *PodSecurityStandardsChecker) CheckPodSecurityPolicy(ctx context.Context) (*core.CheckResult, error) {
	checkID := "cis-5.2.2"
	startTime := time.Now()

	var findings []core.Finding
	var evidence []core.Evidence

	// Check for Pod Security Policies (deprecated in 1.21+, removed in 1.25)
	// For newer clusters, we check Pod Security Standards instead
	pods, err := c.client.Clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return &core.CheckResult{
			CheckID:   checkID,
			Status:    core.StatusError,
			Message:   fmt.Sprintf("Failed to list pods: %v", err),
			Timestamp: time.Now(),
			Duration:  time.Since(startTime),
		}, nil
	}

	systemNamespaces := map[string]bool{
		"kube-system":     true,
		"kube-public":     true,
		"kube-node-lease": true,
	}

	violations := 0
	for _, pod := range pods.Items {
		if systemNamespaces[pod.Namespace] {
			continue
		}

		// Check for security policy violations
		violationsFound := c.checkPodSecurityViolations(pod)
		if len(violationsFound) > 0 {
			violations++
			for _, violation := range violationsFound {
				findings = append(findings, core.Finding{
					ID:          fmt.Sprintf("pod-%s-%s-%s", pod.Namespace, pod.Name, violation.ID),
					Title:       violation.Title,
					Description: violation.Description,
					Severity:    violation.Severity,
					Resource:    fmt.Sprintf("pod/%s/%s", pod.Namespace, pod.Name),
					Remediation: violation.Remediation,
				})
			}
		}
	}

	status := core.StatusPass
	severity := core.SeverityInfo
	if violations > 0 {
		status = core.StatusFail
		severity = core.SeverityHigh
	}

	return &core.CheckResult{
		CheckID:   checkID,
		Status:    status,
		Severity:  severity,
		Evidence:  evidence,
		Findings:  findings,
		Message:   fmt.Sprintf("Checked %d pod(s) for security policy violations, found %d violation(s)", len(pods.Items), violations),
		Timestamp: time.Now(),
		Duration:  time.Since(startTime),
	}, nil
}

type securityViolation struct {
	ID          string
	Title       string
	Description string
	Severity    core.SeverityLevel
	Remediation string
}

func (c *PodSecurityStandardsChecker) checkPodSecurityViolations(pod corev1.Pod) []securityViolation {
	var violations []securityViolation

	// Check pod-level security context
	if pod.Spec.SecurityContext != nil {
		if pod.Spec.SecurityContext.RunAsUser != nil && *pod.Spec.SecurityContext.RunAsUser == 0 {
			violations = append(violations, securityViolation{
				ID:          "run-as-root",
				Title:       "Pod running as root",
				Description: fmt.Sprintf("Pod '%s/%s' is configured to run as root user (UID 0)", pod.Namespace, pod.Name),
				Severity:    core.SeverityCritical,
				Remediation: "Set securityContext.runAsNonRoot=true or securityContext.runAsUser to a non-zero value",
			})
		}
	}

	// Check container-level security contexts
	for _, container := range pod.Spec.Containers {
		if container.SecurityContext != nil {
			// Check for privileged containers
			if container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
				violations = append(violations, securityViolation{
					ID:          "privileged-container",
					Title:       "Privileged container",
					Description: fmt.Sprintf("Container '%s' in pod '%s/%s' is running in privileged mode", container.Name, pod.Namespace, pod.Name),
					Severity:    core.SeverityCritical,
					Remediation: "Set securityContext.privileged=false",
				})
			}

			// Check for allowPrivilegeEscalation
			if container.SecurityContext.AllowPrivilegeEscalation != nil && *container.SecurityContext.AllowPrivilegeEscalation {
				violations = append(violations, securityViolation{
					ID:          "privilege-escalation",
					Title:       "Privilege escalation allowed",
					Description: fmt.Sprintf("Container '%s' in pod '%s/%s' allows privilege escalation", container.Name, pod.Namespace, pod.Name),
					Severity:    core.SeverityHigh,
					Remediation: "Set securityContext.allowPrivilegeEscalation=false",
				})
			}

			// Check for read-only root filesystem
			if container.SecurityContext.ReadOnlyRootFilesystem == nil || !*container.SecurityContext.ReadOnlyRootFilesystem {
				violations = append(violations, securityViolation{
					ID:          "writable-root-fs",
					Title:       "Writable root filesystem",
					Description: fmt.Sprintf("Container '%s' in pod '%s/%s' has writable root filesystem", container.Name, pod.Namespace, pod.Name),
					Severity:    core.SeverityMedium,
					Remediation: "Set securityContext.readOnlyRootFilesystem=true",
				})
			}

			// Check capabilities
			if container.SecurityContext.Capabilities != nil {
				for _, cap := range container.SecurityContext.Capabilities.Add {
					if string(cap) == "ALL" {
						violations = append(violations, securityViolation{
							ID:          "all-capabilities",
							Title:       "All capabilities added",
							Description: fmt.Sprintf("Container '%s' in pod '%s/%s' has ALL capabilities added", container.Name, pod.Namespace, pod.Name),
							Severity:    core.SeverityCritical,
							Remediation: "Drop ALL capabilities and add only required ones",
						})
					}
				}
			}
		} else {
			// No security context at container level
			if pod.Spec.SecurityContext == nil {
				violations = append(violations, securityViolation{
					ID:          "no-security-context",
					Title:       "No security context",
					Description: fmt.Sprintf("Container '%s' in pod '%s/%s' has no security context configured", container.Name, pod.Namespace, pod.Name),
					Severity:    core.SeverityMedium,
					Remediation: "Configure securityContext for the container",
				})
			}
		}
	}

	return violations
}
