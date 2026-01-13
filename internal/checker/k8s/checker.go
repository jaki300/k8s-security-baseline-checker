package k8s

import (
	"context"
	"fmt"

	"github.com/k8s-security-baseline-checker/internal/checker"
	"github.com/k8s-security-baseline-checker/pkg/k8s"
	"github.com/k8s-security-baseline-checker/pkg/types"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// K8sChecker implements the Checker interface for Kubernetes checks
type K8sChecker struct {
	*checker.BaseChecker
	client *k8s.Client
}

// NewK8sChecker creates a new Kubernetes checker instance
func NewK8sChecker(client *k8s.Client, logger *logrus.Logger) (*K8sChecker, error) {
	if client == nil {
		return nil, fmt.Errorf("k8s client cannot be nil")
	}

	base := checker.NewBaseChecker("k8s-checker", "k8s", logger)
	return &K8sChecker{
		BaseChecker: base,
		client:      client,
	}, nil
}

// Validate checks if this checker can handle the given check type
func (k *K8sChecker) Validate(check types.Check) bool {
	// Accept checks with type starting with "check_" (from benchmarks.json)
	// or checks with framework "k8s" or empty framework
	k8sCheckTypes := []string{
		"check_pods_nonroot",
		"check_pods_privileged",
		"check_pods_hostpath",
		"check_pods_resource_limits",
		"check_pods_default_sa",
		"check_namespaces_networkpolicy",
		"check_clusterrole_wildcard",
		"check_rbac",
		"check_image_pull_policy",
		"check_readonly_root_filesystem",
		"check_capabilities",
		"check_secrets_in_env",
		"check_allow_privilege_escalation",
		"check_liveness_probe",
		"check_readiness_probe",
		// CIS v1.8 checks
		"check_apiserver_flags",
		"check_etcd_encryption",
		"check_rbac_advanced",
		"check_serviceaccount_permissions",
		"check_namespace_isolation",
		"check_networkpolicy_coverage",
		"check_pod_security_standards",
		"check_pod_security_policy",
	}

	for _, checkType := range k8sCheckTypes {
		if check.Type == checkType {
			return true
		}
	}

	// Also accept if type is empty and framework is k8s or empty
	if check.Type == "" && (check.Framework == "k8s" || check.Framework == "") {
		return true
	}

	return false
}

// Execute runs the appropriate check based on the check type
func (k *K8sChecker) Execute(ctx context.Context, check types.Check, options *checker.ExecutionOptions) (*types.Result, error) {
	// Determine which check to run based on the check type
	switch check.Type {
	case "check_pods_nonroot", "2.1.1":
		return k.checkPodsNonRoot(ctx, check, options)
	case "check_pods_privileged", "2.1.2":
		return k.checkPrivilegedContainers(ctx, check, options)
	case "check_pods_hostpath", "2.1.3":
		return k.checkHostPathVolumes(ctx, check, options)
	case "check_pods_resource_limits", "2.2.1":
		return k.checkResourceLimits(ctx, check, options)
	case "check_pods_default_sa", "2.2.2":
		return k.checkDefaultServiceAccount(ctx, check, options)
	case "check_namespaces_networkpolicy", "4.1.1":
		return k.checkNetworkPolicies(ctx, check, options)
	case "check_clusterrole_wildcard", "1.1.1":
		return k.checkClusterRoleWildcard(ctx, check, options)
	case "check_rbac":
		return k.checkRBAC(ctx, check, options)
	case "check_image_pull_policy", "2.1.4":
		return k.checkImagePullPolicy(ctx, check, options)
	case "check_readonly_root_filesystem", "2.1.5":
		return k.checkReadOnlyRootFilesystem(ctx, check, options)
	case "check_capabilities", "2.1.6":
		return k.checkCapabilities(ctx, check, options)
	case "check_secrets_in_env", "2.1.7":
		return k.checkSecretsInEnv(ctx, check, options)
	case "check_allow_privilege_escalation", "2.1.8":
		return k.checkAllowPrivilegeEscalation(ctx, check, options)
	case "check_liveness_probe", "2.2.3":
		return k.checkLivenessProbe(ctx, check, options)
	case "check_readiness_probe", "2.2.4":
		return k.checkReadinessProbe(ctx, check, options)
	// CIS v1.8 checks
	case "check_apiserver_flags", "cis-1.2.1":
		return k.checkAPIServerFlags(ctx, check, options)
	case "check_etcd_encryption", "cis-1.1.20":
		return k.checkEtcdEncryption(ctx, check, options)
	case "check_rbac_advanced", "cis-1.1.1":
		return k.checkRBACAdvanced(ctx, check, options)
	case "check_serviceaccount_permissions", "cis-1.1.8":
		return k.checkServiceAccountPermissions(ctx, check, options)
	case "check_namespace_isolation", "cis-4.1.1":
		return k.checkNamespaceIsolationAdvanced(ctx, check, options)
	case "check_networkpolicy_coverage", "cis-4.1.2":
		return k.checkNetworkPolicyCoverage(ctx, check, options)
	case "check_pod_security_standards", "cis-5.2.1":
		return k.checkPodSecurityStandards(ctx, check, options)
	case "check_pod_security_policy", "cis-5.2.2":
		return k.checkPodSecurityPolicyViolations(ctx, check, options)
	default:
		return k.CreateErrorResult(check, fmt.Errorf("unknown check type: %s", check.Type)), nil
	}
}

// getNamespaces returns the list of namespaces to check
func (k *K8sChecker) getNamespaces(ctx context.Context, options *checker.ExecutionOptions) ([]string, error) {
	if options != nil && len(options.Namespaces) > 0 {
		return options.Namespaces, nil
	}

	// Get all namespaces
	namespaces, err := k.client.Clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	nsList := make([]string, 0, len(namespaces.Items))
	for _, ns := range namespaces.Items {
		nsList = append(nsList, ns.Name)
	}

	return nsList, nil
}

