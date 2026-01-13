package k8s

import (
	"context"
	"fmt"
	"strings"

	"github.com/k8s-security-baseline-checker/internal/checker"
	"github.com/k8s-security-baseline-checker/pkg/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// checkClusterRoleWildcard checks if ClusterRoles have wildcard privileges
// Ported from: benchmarks.json (1.1.1)
func (k *K8sChecker) checkClusterRoleWildcard(ctx context.Context, check types.Check, options *checker.ExecutionOptions) (*types.Result, error) {
	clusterRoles, err := k.client.Clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return k.CreateErrorResult(check, fmt.Errorf("failed to list ClusterRoles: %w", err)), nil
	}

	var wildcardRoles []string

	for _, role := range clusterRoles.Items {
		// Skip system roles
		if strings.HasPrefix(role.Name, "system:") {
			continue
		}

		for _, rule := range role.Rules {
			// Check for wildcard verbs
			hasWildcardVerb := false
			for _, verb := range rule.Verbs {
				if verb == "*" {
					hasWildcardVerb = true
					break
				}
			}

			// Check for wildcard resources
			hasWildcardResource := false
			for _, resource := range rule.Resources {
				if resource == "*" {
					hasWildcardResource = true
					break
				}
			}

			// Check for wildcard API groups
			hasWildcardAPIGroup := false
			for _, apiGroup := range rule.APIGroups {
				if apiGroup == "*" {
					hasWildcardAPIGroup = true
					break
				}
			}

			if hasWildcardVerb || hasWildcardResource || hasWildcardAPIGroup {
				wildcardRoles = append(wildcardRoles, role.Name)
				break
			}
		}
	}

	if len(wildcardRoles) == 0 {
		return k.CreatePassResult(check, "No ClusterRoles with wildcard privileges found"), nil
	}

	return k.CreateFailResult(check, wildcardRoles, fmt.Sprintf("Found %d ClusterRole(s) with wildcard privileges", len(wildcardRoles))), nil
}

// checkRBAC performs general RBAC security checks
// This is a comprehensive RBAC check that validates multiple aspects
func (k *K8sChecker) checkRBAC(ctx context.Context, check types.Check, options *checker.ExecutionOptions) (*types.Result, error) {
	var issues []string

	// Check for ClusterRoles with wildcard privileges
	clusterRoles, err := k.client.Clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return k.CreateErrorResult(check, fmt.Errorf("failed to list ClusterRoles: %w", err)), nil
	}

	for _, role := range clusterRoles.Items {
		// Skip system roles
		if strings.HasPrefix(role.Name, "system:") {
			continue
		}

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
				issues = append(issues, fmt.Sprintf("ClusterRole %s has wildcard privileges", role.Name))
				break
			}
		}
	}

	// Check for Roles with wildcard privileges
	namespaces, err := k.getNamespaces(ctx, options)
	if err != nil {
		return k.CreateErrorResult(check, err), nil
	}

	for _, ns := range namespaces {
		roles, err := k.client.Clientset.RbacV1().Roles(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			k.Logger().Warnf("Failed to list Roles in namespace %s: %v", ns, err)
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
					issues = append(issues, fmt.Sprintf("Role %s/%s has wildcard privileges", ns, role.Name))
					break
				}
			}
		}
	}

	// Check for ClusterRoleBindings to cluster-admin
	clusterRoleBindings, err := k.client.Clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return k.CreateErrorResult(check, fmt.Errorf("failed to list ClusterRoleBindings: %w", err)), nil
	}

	for _, binding := range clusterRoleBindings.Items {
		if binding.RoleRef.Name == "cluster-admin" && binding.RoleRef.Kind == "ClusterRole" {
			// Check if it's bound to a service account (more secure) vs user/group
			hasNonSystemBinding := false
			for _, subject := range binding.Subjects {
				if subject.Kind != "ServiceAccount" || !strings.HasPrefix(subject.Name, "system:") {
					hasNonSystemBinding = true
					break
				}
			}
			if hasNonSystemBinding {
				issues = append(issues, fmt.Sprintf("ClusterRoleBinding %s binds cluster-admin to non-system account", binding.Name))
			}
		}
	}

	if len(issues) == 0 {
		return k.CreatePassResult(check, "RBAC configuration is secure"), nil
	}

	return k.CreateWarnResult(check, issues, fmt.Sprintf("Found %d RBAC security issue(s)", len(issues))), nil
}

