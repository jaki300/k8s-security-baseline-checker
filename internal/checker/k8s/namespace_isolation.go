package k8s

import (
	"context"
	"fmt"

	"github.com/k8s-security-baseline-checker/internal/checker"
	"github.com/k8s-security-baseline-checker/pkg/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// checkNamespaceIsolationAdvanced validates namespace isolation controls (CIS 4.1.1, 4.2.1)
func (k *K8sChecker) checkNamespaceIsolationAdvanced(ctx context.Context, check types.Check, options *checker.ExecutionOptions) (*types.Result, error) {

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
		// Skip system namespaces
		if systemNamespaces[ns.Name] {
			continue
		}

		// Check 1: NetworkPolicies
		netpols, err := k.client.Clientset.NetworkingV1().NetworkPolicies(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		if len(netpols.Items) == 0 {
			violations = append(violations, fmt.Sprintf("Namespace '%s' has no NetworkPolicies", ns.Name))
			details = append(details, fmt.Sprintf("Namespace '%s' does not have any NetworkPolicies configured. This allows unrestricted network traffic between pods. Remediation: Create default-deny NetworkPolicy for namespace '%s'. Example: kubectl apply -f - <<EOF\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: default-deny\n  namespace: %s\nspec:\n  podSelector: {}\n  policyTypes:\n  - Ingress\n  - Egress\nEOF", ns.Name, ns.Name, ns.Name))
		} else {
			// Check if there's a default-deny policy
			hasDefaultDeny := false
			for _, netpol := range netpols.Items {
				if len(netpol.Spec.PodSelector.MatchLabels) == 0 && len(netpol.Spec.PolicyTypes) > 0 {
					hasDefaultDeny = true
					break
				}
			}

			if !hasDefaultDeny {
				violations = append(violations, fmt.Sprintf("Namespace '%s' lacks default-deny NetworkPolicy", ns.Name))
				details = append(details, fmt.Sprintf("Namespace '%s' has NetworkPolicies but no default-deny policy. All pods should be covered by network policies. Remediation: Create a default-deny NetworkPolicy for namespace '%s' that applies to all pods (empty podSelector).", ns.Name, ns.Name))
			}
		}

		// Check 2: ResourceQuotas
		quotas, err := k.client.Clientset.CoreV1().ResourceQuotas(ns.Name).List(ctx, metav1.ListOptions{})
		if err == nil && len(quotas.Items) == 0 {
			violations = append(violations, fmt.Sprintf("Namespace '%s' has no ResourceQuota", ns.Name))
			details = append(details, fmt.Sprintf("Namespace '%s' does not have ResourceQuota configured. This can lead to resource exhaustion. Remediation: Create ResourceQuota for namespace '%s' to limit resource consumption. Example: kubectl create quota %s-quota --hard=cpu=2,memory=4Gi --namespace=%s", ns.Name, ns.Name, ns.Name, ns.Name))
		}

		// Check 3: LimitRanges
		limits, err := k.client.Clientset.CoreV1().LimitRanges(ns.Name).List(ctx, metav1.ListOptions{})
		if err == nil && len(limits.Items) == 0 {
			violations = append(violations, fmt.Sprintf("Namespace '%s' has no LimitRange", ns.Name))
			details = append(details, fmt.Sprintf("Namespace '%s' does not have LimitRange configured. Containers can be created without resource limits. Remediation: Create LimitRange for namespace '%s' to enforce default resource limits. Example: kubectl create limitrange %s-limits --default-request=cpu=100m,memory=128Mi --default=cpu=500m,memory=512Mi --namespace=%s", ns.Name, ns.Name, ns.Name, ns.Name))
		}
	}

	if len(violations) > 0 {
		return k.CreateFailResult(check, details, fmt.Sprintf("Found %d namespace isolation issue(s) across %d namespace(s)", len(violations), len(namespaces.Items))), nil
	}

	return k.CreatePassResult(check, fmt.Sprintf("All namespaces have proper isolation controls configured (%d namespace(s) checked)", len(namespaces.Items))), nil
}

// checkNetworkPolicyCoverage checks if all pods are covered by NetworkPolicies (CIS 4.1.2)
func (k *K8sChecker) checkNetworkPolicyCoverage(ctx context.Context, check types.Check, options *checker.ExecutionOptions) (*types.Result, error) {

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

		// Get all pods in namespace
		pods, err := k.client.Clientset.CoreV1().Pods(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		// Get NetworkPolicies
		netpols, err := k.client.Clientset.NetworkingV1().NetworkPolicies(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		// Skip if no NetworkPolicies exist (handled by checkNamespaceIsolationAdvanced)
		if len(netpols.Items) == 0 {
			continue
		}

		// Check if each pod is covered by at least one NetworkPolicy
		for _, pod := range pods.Items {
			covered := false
			for _, netpol := range netpols.Items {
				if matchesNetworkPolicySelector(pod.Labels, netpol.Spec.PodSelector.MatchLabels) {
					covered = true
					break
				}
			}

			if !covered {
				violations = append(violations, fmt.Sprintf("Pod '%s/%s' is not covered by NetworkPolicy", ns.Name, pod.Name))
				details = append(details, fmt.Sprintf("Pod '%s' in namespace '%s' is not covered by any NetworkPolicy. Network traffic is unrestricted. Remediation: Create or update NetworkPolicy to cover pod '%s/%s'. Ensure NetworkPolicy podSelector matches pod labels.", pod.Name, ns.Name, ns.Name, pod.Name))
			}
		}
	}

	if len(violations) > 0 {
		return k.CreateFailResult(check, details, fmt.Sprintf("Found %d uncovered pod(s)", len(violations))), nil
	}

	return k.CreatePassResult(check, "All pods are covered by NetworkPolicies"), nil
}

func matchesNetworkPolicySelector(podLabels map[string]string, selector map[string]string) bool {
	if len(selector) == 0 {
		return true // Empty selector matches all
	}

	for key, value := range selector {
		if podValue, exists := podLabels[key]; !exists || podValue != value {
			return false
		}
	}
	return true
}
