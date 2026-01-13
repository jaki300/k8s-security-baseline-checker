package k8s

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/k8s-security-baseline-checker/pkg/core"
	"github.com/k8s-security-baseline-checker/pkg/k8s"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RBACAdvancedChecker performs advanced RBAC security checks (CIS 1.1.x)
type RBACAdvancedChecker struct {
	client *k8s.Client
}

// NewRBACAdvancedChecker creates a new advanced RBAC checker
func NewRBACAdvancedChecker(client *k8s.Client) *RBACAdvancedChecker {
	return &RBACAdvancedChecker{client: client}
}

// CheckRBACMisconfigurations checks for common RBAC misconfigurations (CIS 1.1.1-1.1.8)
func (c *RBACAdvancedChecker) CheckRBACMisconfigurations(ctx context.Context) (*core.CheckResult, error) {
	checkID := "cis-1.1.1"
	startTime := time.Now()

	var findings []core.Finding
	var evidence []core.Evidence

	// Check 1: ClusterRoles with wildcard privileges
	clusterRoles, err := c.client.Clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return &core.CheckResult{
			CheckID:   checkID,
			Status:    core.StatusError,
			Message:   fmt.Sprintf("Failed to list ClusterRoles: %v", err),
			Timestamp: time.Now(),
			Duration:  time.Since(startTime),
		}, nil
	}

	for _, role := range clusterRoles.Items {
		// Skip system roles
		if strings.HasPrefix(role.Name, "system:") {
			continue
		}

		roleEvidence := core.Evidence{
			Type:        core.EvidenceTypeResource,
			Source:      "k8s-api",
			Description: fmt.Sprintf("ClusterRole '%s' configuration", role.Name),
			Content: map[string]interface{}{
				"name":      role.Name,
				"rules":     role.Rules,
				"namespace": "", // ClusterRole is cluster-scoped
			},
			Timestamp: time.Now(),
		}
		evidence = append(evidence, roleEvidence)

		for _, rule := range role.Rules {
			hasWildcard := false
			wildcardDetails := []string{}

			// Check for wildcard verbs
			for _, verb := range rule.Verbs {
				if verb == "*" {
					hasWildcard = true
					wildcardDetails = append(wildcardDetails, "verbs=*")
					break
				}
			}

			// Check for wildcard resources
			for _, resource := range rule.Resources {
				if resource == "*" {
					hasWildcard = true
					wildcardDetails = append(wildcardDetails, "resources=*")
					break
				}
			}

			// Check for wildcard API groups
			for _, apiGroup := range rule.APIGroups {
				if apiGroup == "*" {
					hasWildcard = true
					wildcardDetails = append(wildcardDetails, "apiGroups=*")
					break
				}
			}

			if hasWildcard {
				findings = append(findings, core.Finding{
					ID:          fmt.Sprintf("clusterrole-%s-wildcard", role.Name),
					Title:       fmt.Sprintf("ClusterRole '%s' has wildcard privileges", role.Name),
					Description: fmt.Sprintf("ClusterRole '%s' contains wildcard privileges: %s. This violates the principle of least privilege.", role.Name, strings.Join(wildcardDetails, ", ")),
					Severity:    core.SeverityCritical,
					Resource:    fmt.Sprintf("clusterrole/%s", role.Name),
					Remediation: fmt.Sprintf("Replace wildcard privileges in ClusterRole '%s' with specific verbs, resources, and API groups", role.Name),
				})
			}
		}
	}

	// Check 2: Excessive ClusterRoleBindings to cluster-admin
	clusterRoleBindings, err := c.client.Clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, binding := range clusterRoleBindings.Items {
			if binding.RoleRef.Name == "cluster-admin" && binding.RoleRef.Kind == "ClusterRole" {
				// Check if bound to non-system accounts
				hasNonSystemBinding := false
				for _, subject := range binding.Subjects {
					if subject.Kind != "ServiceAccount" || !strings.HasPrefix(subject.Name, "system:") {
						hasNonSystemBinding = true
						break
					}
				}

				if hasNonSystemBinding {
					findings = append(findings, core.Finding{
						ID:          fmt.Sprintf("clusterrolebinding-%s-cluster-admin", binding.Name),
						Title:       fmt.Sprintf("ClusterRoleBinding '%s' binds cluster-admin to non-system account", binding.Name),
						Description: fmt.Sprintf("ClusterRoleBinding '%s' grants cluster-admin privileges to non-system accounts. This is a critical security risk.", binding.Name),
						Severity:    core.SeverityCritical,
						Resource:    fmt.Sprintf("clusterrolebinding/%s", binding.Name),
						Remediation: fmt.Sprintf("Review and restrict ClusterRoleBinding '%s'. Use least privilege roles instead of cluster-admin.", binding.Name),
					})
				}
			}
		}
	}

	// Check 3: Roles with wildcard privileges in namespaces
	namespaces, err := c.client.Clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, ns := range namespaces.Items {
			roles, err := c.client.Clientset.RbacV1().Roles(ns.Name).List(ctx, metav1.ListOptions{})
			if err != nil {
				continue
			}

			for _, role := range roles.Items {
				for _, rule := range role.Rules {
					hasWildcard := false
					for _, verb := range rule.Verbs {
						if verb == "*" {
							hasWildcard = true
							break
						}
					}
					if !hasWildcard {
						for _, resource := range rule.Resources {
							if resource == "*" {
								hasWildcard = true
								break
							}
						}
					}

					if hasWildcard {
						findings = append(findings, core.Finding{
							ID:          fmt.Sprintf("role-%s-%s-wildcard", ns.Name, role.Name),
							Title:       fmt.Sprintf("Role '%s/%s' has wildcard privileges", ns.Name, role.Name),
							Description: fmt.Sprintf("Role '%s' in namespace '%s' contains wildcard privileges, violating least privilege.", role.Name, ns.Name),
							Severity:    core.SeverityHigh,
							Resource:    fmt.Sprintf("role/%s/%s", ns.Name, role.Name),
							Remediation: fmt.Sprintf("Replace wildcard privileges in Role '%s/%s' with specific permissions", ns.Name, role.Name),
						})
					}
				}
			}
		}
	}

	status := core.StatusPass
	severity := core.SeverityInfo
	if len(findings) > 0 {
		status = core.StatusFail
		severity = core.SeverityCritical
	}

	return &core.CheckResult{
		CheckID:   checkID,
		Status:    status,
		Severity:  severity,
		Evidence:  evidence,
		Findings:  findings,
		Message:   fmt.Sprintf("Checked RBAC configuration, found %d misconfiguration(s)", len(findings)),
		Timestamp: time.Now(),
		Duration:  time.Since(startTime),
	}, nil
}

// CheckServiceAccountPermissions checks for excessive ServiceAccount permissions (CIS 1.1.8)
func (c *RBACAdvancedChecker) CheckServiceAccountPermissions(ctx context.Context) (*core.CheckResult, error) {
	checkID := "cis-1.1.8"
	startTime := time.Now()

	var findings []core.Finding
	var evidence []core.Evidence

	// Get all ServiceAccounts
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

	for _, ns := range namespaces.Items {
		serviceAccounts, err := c.client.Clientset.CoreV1().ServiceAccounts(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, sa := range serviceAccounts.Items {
			// Skip system ServiceAccounts
			if strings.HasPrefix(sa.Name, "system:") || strings.HasPrefix(sa.Name, "default") {
				continue
			}

			// Check RoleBindings
			roleBindings, err := c.client.Clientset.RbacV1().RoleBindings(ns.Name).List(ctx, metav1.ListOptions{})
			if err == nil {
				for _, binding := range roleBindings.Items {
					for _, subject := range binding.Subjects {
						if subject.Kind == "ServiceAccount" && subject.Name == sa.Name {
							// Check if role has excessive permissions
							role, err := c.client.Clientset.RbacV1().Roles(ns.Name).Get(ctx, binding.RoleRef.Name, metav1.GetOptions{})
							if err == nil {
								for _, rule := range role.Rules {
									if hasExcessivePermissions(rule) {
										findings = append(findings, core.Finding{
											ID:          fmt.Sprintf("sa-%s-%s-excessive", ns.Name, sa.Name),
											Title:       fmt.Sprintf("ServiceAccount '%s/%s' has excessive permissions", ns.Name, sa.Name),
											Description: fmt.Sprintf("ServiceAccount '%s' in namespace '%s' is bound to Role '%s' with excessive permissions.", sa.Name, ns.Name, role.Name),
											Severity:    core.SeverityHigh,
											Resource:    fmt.Sprintf("serviceaccount/%s/%s", ns.Name, sa.Name),
											Remediation: fmt.Sprintf("Review and restrict permissions for ServiceAccount '%s/%s'. Apply principle of least privilege.", ns.Name, sa.Name),
										})
									}
								}
							}
						}
					}
				}
			}

			// Check ClusterRoleBindings
			clusterRoleBindings, err := c.client.Clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
			if err == nil {
				for _, binding := range clusterRoleBindings.Items {
					for _, subject := range binding.Subjects {
						if subject.Kind == "ServiceAccount" && subject.Name == sa.Name && subject.Namespace == ns.Name {
							if binding.RoleRef.Name == "cluster-admin" {
								findings = append(findings, core.Finding{
									ID:          fmt.Sprintf("sa-%s-%s-cluster-admin", ns.Name, sa.Name),
									Title:       fmt.Sprintf("ServiceAccount '%s/%s' has cluster-admin privileges", ns.Name, sa.Name),
									Description: fmt.Sprintf("ServiceAccount '%s' in namespace '%s' is bound to cluster-admin ClusterRole. This is a critical security risk.", sa.Name, ns.Name),
									Severity:    core.SeverityCritical,
									Resource:    fmt.Sprintf("serviceaccount/%s/%s", ns.Name, sa.Name),
									Remediation: fmt.Sprintf("Remove cluster-admin binding from ServiceAccount '%s/%s'. Use least privilege ClusterRole instead.", ns.Name, sa.Name),
								})
							}
						}
					}
				}
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
		Message:   fmt.Sprintf("Checked ServiceAccount permissions, found %d issue(s)", len(findings)),
		Timestamp: time.Now(),
		Duration:  time.Since(startTime),
	}, nil
}

func hasExcessivePermissions(rule rbacv1.PolicyRule) bool {
	// Check for wildcards
	for _, verb := range rule.Verbs {
		if verb == "*" {
			return true
		}
	}
	for _, resource := range rule.Resources {
		if resource == "*" {
			return true
		}
	}
	return false
}
