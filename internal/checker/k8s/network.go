package k8s

import (
	"context"
	"fmt"

	"github.com/k8s-security-baseline-checker/internal/checker"
	"github.com/k8s-security-baseline-checker/pkg/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// checkNetworkPolicies checks if namespaces have NetworkPolicies defined
// Ported from: check-baseline.sh
func (k *K8sChecker) checkNetworkPolicies(ctx context.Context, check types.Check, options *checker.ExecutionOptions) (*types.Result, error) {
	namespaces, err := k.getNamespaces(ctx, options)
	if err != nil {
		return k.CreateErrorResult(check, err), nil
	}

	var noNetPolNamespaces []string

	for _, ns := range namespaces {
		// Skip system namespaces
		if ns == "kube-system" || ns == "kube-public" || ns == "kube-node-lease" {
			continue
		}

		netpols, err := k.client.Clientset.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			k.Logger().Warnf("Failed to list NetworkPolicies in namespace %s: %v", ns, err)
			continue
		}

		if len(netpols.Items) == 0 {
			noNetPolNamespaces = append(noNetPolNamespaces, ns)
		}
	}

	if len(noNetPolNamespaces) == 0 {
		return k.CreatePassResult(check, "All namespaces have NetworkPolicies"), nil
	}

	return k.CreateWarnResult(check, noNetPolNamespaces, fmt.Sprintf("Found %d namespace(s) without NetworkPolicies", len(noNetPolNamespaces))), nil
}

