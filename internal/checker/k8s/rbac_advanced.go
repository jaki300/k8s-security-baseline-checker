package k8s

import (
	"context"
	"fmt"
	"strings"

	"github.com/k8s-security-baseline-checker/internal/checker"
	"github.com/k8s-security-baseline-checker/pkg/types"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// checkRBACAdvanced performs advanced RBAC security checks (CIS 1.1.1, 1.1.8)
func (k *K8sChecker) checkRBACAdvanced(ctx context.Context, check types.Check, options *checker.ExecutionOptions) (*types.Result, error) {

	var violations []string
	var details []string

	// Check 1: ClusterRoles with wildcard privileges
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
				violations = append(violations, fmt.Sprintf("ClusterRole '%s' has wildcard privileges", role.Name))
				details = append(details, fmt.Sprintf("ClusterRole '%s' contains wildcard privileges: %s. This violates the principle of least privilege. Remediation: Replace wildcard privileges with specific verbs, resources, and API groups. Example: Use ['get', 'list'] instead of ['*'], use ['pods', 'services'] instead of ['*']", role.Name, strings.Join(wildcardDetails, ", ")))
			}
		}
	}

	// Check 2: Excessive ClusterRoleBindings to cluster-admin
	clusterRoleBindings, err := k.client.Clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
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
					violations = append(violations, fmt.Sprintf("ClusterRoleBinding '%s' binds cluster-admin to non-system account", binding.Name))
					details = append(details, fmt.Sprintf("ClusterRoleBinding '%s' grants cluster-admin privileges to non-system accounts. This is a critical security risk. Remediation: Review and restrict ClusterRoleBinding '%s'. Use least privilege roles instead of cluster-admin. Consider creating custom ClusterRoles with only required permissions.", binding.Name, binding.Name))
				}
			}
		}
	}

	// Check 3: Roles with wildcard privileges in namespaces
	namespaces, err := k.client.Clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err == nil {
		for _, ns := range namespaces.Items {
			roles, err := k.client.Clientset.RbacV1().Roles(ns.Name).List(ctx, metav1.ListOptions{})
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
						violations = append(violations, fmt.Sprintf("Role '%s/%s' has wildcard privileges", ns.Name, role.Name))
						details = append(details, fmt.Sprintf("Role '%s' in namespace '%s' contains wildcard privileges, violating least privilege. Remediation: Replace wildcard privileges in Role '%s/%s' with specific permissions. Define exact verbs (e.g., ['get', 'list', 'watch']) and resources (e.g., ['pods', 'services']) needed.", role.Name, ns.Name, ns.Name, role.Name))
					}
				}
			}
		}
	}

	if len(violations) > 0 {
		return k.CreateFailResult(check, details, fmt.Sprintf("Found %d RBAC misconfiguration(s)", len(violations))), nil
	}

	return k.CreatePassResult(check, "RBAC configuration is secure - no wildcard privileges or excessive cluster-admin bindings found"), nil
}

// checkServiceAccountPermissions checks for excessive ServiceAccount permissions (CIS 1.1.8)
func (k *K8sChecker) checkServiceAccountPermissions(ctx context.Context, check types.Check, options *checker.ExecutionOptions) (*types.Result, error) {

	var violations []string
	var details []string

	// Get all ServiceAccounts
	namespaces, err := k.client.Clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return k.CreateErrorResult(check, fmt.Errorf("failed to list namespaces: %w", err)), nil
	}

	for _, ns := range namespaces.Items {
		serviceAccounts, err := k.client.Clientset.CoreV1().ServiceAccounts(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		for _, sa := range serviceAccounts.Items {
			// Skip system ServiceAccounts
			if strings.HasPrefix(sa.Name, "system:") || sa.Name == "default" {
				continue
			}

			// Check ClusterRoleBindings for cluster-admin
			clusterRoleBindings, err := k.client.Clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
			if err == nil {
				for _, binding := range clusterRoleBindings.Items {
					for _, subject := range binding.Subjects {
						if subject.Kind == "ServiceAccount" && subject.Name == sa.Name && subject.Namespace == ns.Name {
							if binding.RoleRef.Name == "cluster-admin" {
								violations = append(violations, fmt.Sprintf("ServiceAccount '%s/%s' has cluster-admin privileges", ns.Name, sa.Name))
								details = append(details, fmt.Sprintf("ServiceAccount '%s' in namespace '%s' is bound to cluster-admin ClusterRole via ClusterRoleBinding '%s'. This is a critical security risk. Remediation: Remove cluster-admin binding from ServiceAccount '%s/%s'. Create a custom ClusterRole with only required permissions and bind ServiceAccount to it.", sa.Name, ns.Name, binding.Name, ns.Name, sa.Name))
							}
						}
					}
				}
			}

			// Check RoleBindings for excessive permissions
			roleBindings, err := k.client.Clientset.RbacV1().RoleBindings(ns.Name).List(ctx, metav1.ListOptions{})
			if err == nil {
				for _, binding := range roleBindings.Items {
					for _, subject := range binding.Subjects {
						if subject.Kind == "ServiceAccount" && subject.Name == sa.Name {
							// Check if role has wildcard permissions
							role, err := k.client.Clientset.RbacV1().Roles(ns.Name).Get(ctx, binding.RoleRef.Name, metav1.GetOptions{})
							if err == nil {
								for _, rule := range role.Rules {
									if hasWildcardInRule(rule) {
										violations = append(violations, fmt.Sprintf("ServiceAccount '%s/%s' has excessive permissions via Role '%s'", ns.Name, sa.Name, role.Name))
										details = append(details, fmt.Sprintf("ServiceAccount '%s' in namespace '%s' is bound to Role '%s' with wildcard privileges. Remediation: Review and restrict permissions for ServiceAccount '%s/%s'. Apply principle of least privilege by replacing wildcard permissions with specific verbs and resources.", sa.Name, ns.Name, role.Name, ns.Name, sa.Name))
									}
								}
							}
						}
					}
				}
			}
		}
	}

	if len(violations) > 0 {
		return k.CreateFailResult(check, details, fmt.Sprintf("Found %d ServiceAccount permission issue(s)", len(violations))), nil
	}

	return k.CreatePassResult(check, "All ServiceAccounts have appropriate permissions configured"), nil
}

func hasWildcardInRule(rule rbacv1.PolicyRule) bool {
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
