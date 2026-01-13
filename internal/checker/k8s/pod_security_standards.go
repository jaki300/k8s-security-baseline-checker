package k8s

import (
	"context"
	"fmt"

	"github.com/k8s-security-baseline-checker/internal/checker"
	"github.com/k8s-security-baseline-checker/pkg/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// checkPodSecurityStandards validates Pod Security Standards enforcement (CIS 5.2.1)
func (k *K8sChecker) checkPodSecurityStandards(ctx context.Context, check types.Check, options *checker.ExecutionOptions) (*types.Result, error) {

	namespaces, err := k.client.Clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return k.CreateErrorResult(check, fmt.Errorf("failed to list namespaces: %w", err)), nil
	}

	var violations []string
	var details []string
	systemNamespaces := map[string]bool{
		"kube-system":     true,
		"kube-public":     true,
		"kube-node-lease": true,
	}

	for _, ns := range namespaces.Items {
		if systemNamespaces[ns.Name] {
			continue
		}

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
			violations = append(violations, fmt.Sprintf("Namespace '%s' does not enforce Pod Security Standards", ns.Name))
			details = append(details, fmt.Sprintf("Namespace '%s' does not have Pod Security Standards enforcement configured. Pods can be created without security restrictions. Remediation: Add pod-security.kubernetes.io/enforce label to namespace '%s'. Example: kubectl label namespace %s pod-security.kubernetes.io/enforce=restricted --overwrite. Use 'restricted' for maximum security or 'baseline' for compatibility.", ns.Name, ns.Name, ns.Name))
		} else if pssEnforce != "restricted" && pssEnforce != "baseline" {
			violations = append(violations, fmt.Sprintf("Namespace '%s' uses weak Pod Security Standards level '%s'", ns.Name, pssEnforce))
			details = append(details, fmt.Sprintf("Namespace '%s' has Pod Security Standards enforcement set to '%s'. Consider using 'restricted' for maximum security. Remediation: Update pod-security.kubernetes.io/enforce label to 'restricted' for namespace '%s'. Example: kubectl label namespace %s pod-security.kubernetes.io/enforce=restricted --overwrite", ns.Name, pssEnforce, ns.Name, ns.Name))
		}

		// Check if audit and warn are also configured
		if pssAudit == "" {
			details = append(details, fmt.Sprintf("Namespace '%s' missing Pod Security Standards audit mode. Consider adding for better visibility. Remediation: kubectl label namespace %s pod-security.kubernetes.io/audit=restricted", ns.Name, ns.Name))
		}
	}

	if len(violations) > 0 {
		return k.CreateFailResult(check, details, fmt.Sprintf("Found %d Pod Security Standards issue(s) across %d namespace(s)", len(violations), len(namespaces.Items))), nil
	}

	return k.CreatePassResult(check, fmt.Sprintf("All namespaces have Pod Security Standards properly configured (%d namespace(s) checked)", len(namespaces.Items))), nil
}

// checkPodSecurityPolicyViolations validates Pod Security Policy violations (CIS 5.2.2)
func (k *K8sChecker) checkPodSecurityPolicyViolations(ctx context.Context, check types.Check, options *checker.ExecutionOptions) (*types.Result, error) {

	pods, err := k.client.Clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return k.CreateErrorResult(check, fmt.Errorf("failed to list pods: %w", err)), nil
	}

	var violations []string
	var details []string
	systemNamespaces := map[string]bool{
		"kube-system":     true,
		"kube-public":     true,
		"kube-node-lease": true,
	}

	for _, pod := range pods.Items {
		if systemNamespaces[pod.Namespace] {
			continue
		}

		// Check pod-level security context
		if pod.Spec.SecurityContext != nil {
			if pod.Spec.SecurityContext.RunAsUser != nil && *pod.Spec.SecurityContext.RunAsUser == 0 {
				violations = append(violations, fmt.Sprintf("Pod '%s/%s' is running as root", pod.Namespace, pod.Name))
				details = append(details, fmt.Sprintf("Pod '%s' in namespace '%s' is configured to run as root user (UID 0). Remediation: Set securityContext.runAsNonRoot=true or securityContext.runAsUser to a non-zero value in pod specification.", pod.Name, pod.Namespace))
			}
		}

		// Check container-level security contexts
		for _, container := range pod.Spec.Containers {
			if container.SecurityContext != nil {
				// Check for privileged containers
				if container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
					violations = append(violations, fmt.Sprintf("Container '%s' in pod '%s/%s' is privileged", container.Name, pod.Namespace, pod.Name))
					details = append(details, fmt.Sprintf("Container '%s' in pod '%s/%s' is running in privileged mode. Remediation: Set securityContext.privileged=false in container specification.", container.Name, pod.Namespace, pod.Name))
				}

				// Check for allowPrivilegeEscalation
				if container.SecurityContext.AllowPrivilegeEscalation != nil && *container.SecurityContext.AllowPrivilegeEscalation {
					violations = append(violations, fmt.Sprintf("Container '%s' in pod '%s/%s' allows privilege escalation", container.Name, pod.Namespace, pod.Name))
					details = append(details, fmt.Sprintf("Container '%s' in pod '%s/%s' allows privilege escalation. Remediation: Set securityContext.allowPrivilegeEscalation=false in container specification.", container.Name, pod.Namespace, pod.Name))
				}

				// Check for read-only root filesystem
				if container.SecurityContext.ReadOnlyRootFilesystem == nil || !*container.SecurityContext.ReadOnlyRootFilesystem {
					violations = append(violations, fmt.Sprintf("Container '%s' in pod '%s/%s' has writable root filesystem", container.Name, pod.Namespace, pod.Name))
					details = append(details, fmt.Sprintf("Container '%s' in pod '%s/%s' has writable root filesystem. Remediation: Set securityContext.readOnlyRootFilesystem=true in container specification. Ensure required volumes are mounted as tmpfs or emptyDir if write access is needed.", container.Name, pod.Namespace, pod.Name))
				}

				// Check capabilities
				if container.SecurityContext.Capabilities != nil {
					for _, cap := range container.SecurityContext.Capabilities.Add {
						if string(cap) == "ALL" {
							violations = append(violations, fmt.Sprintf("Container '%s' in pod '%s/%s' has ALL capabilities", container.Name, pod.Namespace, pod.Name))
							details = append(details, fmt.Sprintf("Container '%s' in pod '%s/%s' has ALL capabilities added. Remediation: Drop ALL capabilities and add only required ones. Example: securityContext.capabilities.drop=['ALL'], securityContext.capabilities.add=['NET_BIND_SERVICE']", container.Name, pod.Namespace, pod.Name))
						}
					}
				}
			} else {
				// No security context at container level
				if pod.Spec.SecurityContext == nil {
					violations = append(violations, fmt.Sprintf("Container '%s' in pod '%s/%s' has no security context", container.Name, pod.Namespace, pod.Name))
					details = append(details, fmt.Sprintf("Container '%s' in pod '%s/%s' has no security context configured. Remediation: Configure securityContext for the container with runAsNonRoot=true, allowPrivilegeEscalation=false, readOnlyRootFilesystem=true, and drop ALL capabilities.", container.Name, pod.Namespace, pod.Name))
				}
			}
		}
	}

	if len(violations) > 0 {
		return k.CreateFailResult(check, details, fmt.Sprintf("Found %d Pod Security Policy violation(s) across %d pod(s)", len(violations), len(pods.Items))), nil
	}

	return k.CreatePassResult(check, fmt.Sprintf("All pods comply with Pod Security Standards (%d pod(s) checked)", len(pods.Items))), nil
}
