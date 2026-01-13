package k8s

import (
	"context"
	"fmt"
	"time"

	"github.com/k8s-security-baseline-checker/pkg/core"
	"github.com/k8s-security-baseline-checker/pkg/k8s"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NamespaceIsolationChecker checks namespace isolation and security (CIS 4.x)
type NamespaceIsolationChecker struct {
	client *k8s.Client
}

// NewNamespaceIsolationChecker creates a new namespace isolation checker
func NewNamespaceIsolationChecker(client *k8s.Client) *NamespaceIsolationChecker {
	return &NamespaceIsolationChecker{client: client}
}

// CheckNamespaceIsolation validates namespace isolation controls (CIS 4.1.1, 4.2.1)
func (c *NamespaceIsolationChecker) CheckNamespaceIsolation(ctx context.Context) (*core.CheckResult, error) {
	checkID := "cis-4.1.1"
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
		// Skip system namespaces
		if systemNamespaces[ns.Name] {
			continue
		}

		nsEvidence := core.Evidence{
			Type:        core.EvidenceTypeResource,
			Source:      "k8s-api",
			Description: fmt.Sprintf("Namespace '%s' configuration", ns.Name),
			Content: map[string]interface{}{
				"name":      ns.Name,
				"labels":    ns.Labels,
				"annotations": ns.Annotations,
			},
			Timestamp: time.Now(),
		}
		evidence = append(evidence, nsEvidence)

		// Check 1: NetworkPolicies
		netpols, err := c.client.Clientset.NetworkingV1().NetworkPolicies(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		if len(netpols.Items) == 0 {
			findings = append(findings, core.Finding{
				ID:          fmt.Sprintf("namespace-%s-no-netpol", ns.Name),
				Title:       fmt.Sprintf("Namespace '%s' has no NetworkPolicies", ns.Name),
				Description: fmt.Sprintf("Namespace '%s' does not have any NetworkPolicies configured. This allows unrestricted network traffic between pods.", ns.Name),
				Severity:    core.SeverityHigh,
				Resource:    fmt.Sprintf("namespace/%s", ns.Name),
				Remediation: fmt.Sprintf("Create default-deny NetworkPolicy for namespace '%s' to enforce network segmentation", ns.Name),
			})
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
				findings = append(findings, core.Finding{
					ID:          fmt.Sprintf("namespace-%s-no-default-deny", ns.Name),
					Title:       fmt.Sprintf("Namespace '%s' lacks default-deny NetworkPolicy", ns.Name),
					Description: fmt.Sprintf("Namespace '%s' has NetworkPolicies but no default-deny policy. All pods should be covered by network policies.", ns.Name),
					Severity:    core.SeverityMedium,
					Resource:    fmt.Sprintf("namespace/%s", ns.Name),
					Remediation: fmt.Sprintf("Create a default-deny NetworkPolicy for namespace '%s' that applies to all pods", ns.Name),
				})
			}
		}

		// Check 2: ResourceQuotas
		quotas, err := c.client.Clientset.CoreV1().ResourceQuotas(ns.Name).List(ctx, metav1.ListOptions{})
		if err == nil && len(quotas.Items) == 0 {
			findings = append(findings, core.Finding{
				ID:          fmt.Sprintf("namespace-%s-no-quota", ns.Name),
				Title:       fmt.Sprintf("Namespace '%s' has no ResourceQuota", ns.Name),
				Description: fmt.Sprintf("Namespace '%s' does not have ResourceQuota configured. This can lead to resource exhaustion.", ns.Name),
				Severity:    core.SeverityMedium,
				Resource:    fmt.Sprintf("namespace/%s", ns.Name),
				Remediation: fmt.Sprintf("Create ResourceQuota for namespace '%s' to limit resource consumption", ns.Name),
			})
		}

		// Check 3: LimitRanges
		limits, err := c.client.Clientset.CoreV1().LimitRanges(ns.Name).List(ctx, metav1.ListOptions{})
		if err == nil && len(limits.Items) == 0 {
			findings = append(findings, core.Finding{
				ID:          fmt.Sprintf("namespace-%s-no-limitrange", ns.Name),
				Title:       fmt.Sprintf("Namespace '%s' has no LimitRange", ns.Name),
				Description: fmt.Sprintf("Namespace '%s' does not have LimitRange configured. Containers can be created without resource limits.", ns.Name),
				Severity:    core.SeverityMedium,
				Resource:    fmt.Sprintf("namespace/%s", ns.Name),
				Remediation: fmt.Sprintf("Create LimitRange for namespace '%s' to enforce default resource limits", ns.Name),
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
		Message:   fmt.Sprintf("Checked %d namespace(s), found %d isolation issue(s)", len(namespaces.Items), len(findings)),
		Timestamp: time.Now(),
		Duration:  time.Since(startTime),
	}, nil
}

// CheckNetworkPolicyCoverage checks if all pods are covered by NetworkPolicies (CIS 4.1.2)
func (c *NamespaceIsolationChecker) CheckNetworkPolicyCoverage(ctx context.Context) (*core.CheckResult, error) {
	checkID := "cis-4.1.2"
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

		// Get all pods in namespace
		pods, err := c.client.Clientset.CoreV1().Pods(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		// Get NetworkPolicies
		netpols, err := c.client.Clientset.NetworkingV1().NetworkPolicies(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		// Check if each pod is covered by at least one NetworkPolicy
		for _, pod := range pods.Items {
			covered := false
			for _, netpol := range netpols.Items {
				if matchesSelector(pod.Labels, netpol.Spec.PodSelector.MatchLabels) {
					covered = true
					break
				}
			}

			if !covered && len(netpols.Items) > 0 {
				findings = append(findings, core.Finding{
					ID:          fmt.Sprintf("pod-%s-%s-not-covered", ns.Name, pod.Name),
					Title:       fmt.Sprintf("Pod '%s/%s' is not covered by NetworkPolicy", ns.Name, pod.Name),
					Description: fmt.Sprintf("Pod '%s' in namespace '%s' is not covered by any NetworkPolicy. Network traffic is unrestricted.", pod.Name, ns.Name),
					Severity:    core.SeverityHigh,
					Resource:    fmt.Sprintf("pod/%s/%s", ns.Name, pod.Name),
					Remediation: fmt.Sprintf("Create or update NetworkPolicy to cover pod '%s/%s'", ns.Name, pod.Name),
				})
			}
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
		Message:   fmt.Sprintf("Checked NetworkPolicy coverage, found %d uncovered pod(s)", len(findings)),
		Timestamp: time.Now(),
		Duration:  time.Since(startTime),
	}, nil
}

func matchesSelector(podLabels map[string]string, selector map[string]string) bool {
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
