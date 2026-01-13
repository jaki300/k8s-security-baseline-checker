package k8s

import (
	"context"
	"fmt"

	"github.com/k8s-security-baseline-checker/internal/checker"
	"github.com/k8s-security-baseline-checker/pkg/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// checkPodsNonRoot checks if any pods are running as root
// Ported from: check-baseline.sh and cis.sh
func (k *K8sChecker) checkPodsNonRoot(ctx context.Context, check types.Check, options *checker.ExecutionOptions) (*types.Result, error) {
	namespaces, err := k.getNamespaces(ctx, options)
	if err != nil {
		return k.CreateErrorResult(check, err), nil
	}

	var rootPods []string

	for _, ns := range namespaces {
		pods, err := k.client.Clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			k.Logger().Warnf("Failed to list pods in namespace %s: %v", ns, err)
			continue
		}

		for _, pod := range pods.Items {
			// Check pod-level security context
			if pod.Spec.SecurityContext != nil {
				if pod.Spec.SecurityContext.RunAsUser != nil && *pod.Spec.SecurityContext.RunAsUser == 0 {
					rootPods = append(rootPods, fmt.Sprintf("%s/%s", pod.Namespace, pod.Name))
					continue
				}
				if pod.Spec.SecurityContext.RunAsNonRoot != nil && !*pod.Spec.SecurityContext.RunAsNonRoot {
					rootPods = append(rootPods, fmt.Sprintf("%s/%s", pod.Namespace, pod.Name))
					continue
				}
			}

			// Check container-level security context
			for _, container := range pod.Spec.Containers {
				if container.SecurityContext != nil {
					if container.SecurityContext.RunAsUser != nil && *container.SecurityContext.RunAsUser == 0 {
						rootPods = append(rootPods, fmt.Sprintf("%s/%s", pod.Namespace, pod.Name))
						break
					}
					if container.SecurityContext.RunAsNonRoot != nil && !*container.SecurityContext.RunAsNonRoot {
						rootPods = append(rootPods, fmt.Sprintf("%s/%s", pod.Namespace, pod.Name))
						break
					}
				} else {
					// If no security context is set, it might run as root (depending on image defaults)
					// This is a warning case - we'll flag it if pod-level also doesn't have it
					if pod.Spec.SecurityContext == nil || 
						(pod.Spec.SecurityContext.RunAsNonRoot == nil && pod.Spec.SecurityContext.RunAsUser == nil) {
						rootPods = append(rootPods, fmt.Sprintf("%s/%s", pod.Namespace, pod.Name))
						break
					}
				}
			}

			// Check init containers
			for _, container := range pod.Spec.InitContainers {
				if container.SecurityContext != nil {
					if container.SecurityContext.RunAsUser != nil && *container.SecurityContext.RunAsUser == 0 {
						rootPods = append(rootPods, fmt.Sprintf("%s/%s", pod.Namespace, pod.Name))
						break
					}
					if container.SecurityContext.RunAsNonRoot != nil && !*container.SecurityContext.RunAsNonRoot {
						rootPods = append(rootPods, fmt.Sprintf("%s/%s", pod.Namespace, pod.Name))
						break
					}
				}
			}
		}
	}

	if len(rootPods) == 0 {
		return k.CreatePassResult(check, "All pods are configured to run as non-root"), nil
	}

	return k.CreateFailResult(check, rootPods, fmt.Sprintf("Found %d pod(s) running as root", len(rootPods))), nil
}

// checkPrivilegedContainers checks if any containers are running in privileged mode
// Ported from: check-baseline.sh and cis.sh
func (k *K8sChecker) checkPrivilegedContainers(ctx context.Context, check types.Check, options *checker.ExecutionOptions) (*types.Result, error) {
	namespaces, err := k.getNamespaces(ctx, options)
	if err != nil {
		return k.CreateErrorResult(check, err), nil
	}

	var privPods []string

	for _, ns := range namespaces {
		pods, err := k.client.Clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			k.Logger().Warnf("Failed to list pods in namespace %s: %v", ns, err)
			continue
		}

		for _, pod := range pods.Items {
			// Check container-level security context (Privileged is only at container level)
			for _, container := range pod.Spec.Containers {
				if container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
					privPods = append(privPods, fmt.Sprintf("%s/%s", pod.Namespace, pod.Name))
					break
				}
			}

			// Check init containers
			for _, container := range pod.Spec.InitContainers {
				if container.SecurityContext != nil && container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
					privPods = append(privPods, fmt.Sprintf("%s/%s", pod.Namespace, pod.Name))
					break
				}
			}
		}
	}

	if len(privPods) == 0 {
		return k.CreatePassResult(check, "No privileged containers found"), nil
	}

	return k.CreateFailResult(check, privPods, fmt.Sprintf("Found %d pod(s) with privileged containers", len(privPods))), nil
}

// checkHostPathVolumes checks if any pods are using hostPath volumes
// Ported from: cis.sh
func (k *K8sChecker) checkHostPathVolumes(ctx context.Context, check types.Check, options *checker.ExecutionOptions) (*types.Result, error) {
	namespaces, err := k.getNamespaces(ctx, options)
	if err != nil {
		return k.CreateErrorResult(check, err), nil
	}

	var hostPathPods []string

	for _, ns := range namespaces {
		pods, err := k.client.Clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			k.Logger().Warnf("Failed to list pods in namespace %s: %v", ns, err)
			continue
		}

		for _, pod := range pods.Items {
			for _, volume := range pod.Spec.Volumes {
				if volume.HostPath != nil {
					hostPathPods = append(hostPathPods, fmt.Sprintf("%s/%s", pod.Namespace, pod.Name))
					break
				}
			}
		}
	}

	if len(hostPathPods) == 0 {
		return k.CreatePassResult(check, "No hostPath volumes found"), nil
	}

	return k.CreateFailResult(check, hostPathPods, fmt.Sprintf("Found %d pod(s) using hostPath volumes", len(hostPathPods))), nil
}

// checkResourceLimits checks if pods have resource limits defined
// Ported from: check-baseline.sh
func (k *K8sChecker) checkResourceLimits(ctx context.Context, check types.Check, options *checker.ExecutionOptions) (*types.Result, error) {
	namespaces, err := k.getNamespaces(ctx, options)
	if err != nil {
		return k.CreateErrorResult(check, err), nil
	}

	var noLimitsPods []string

	for _, ns := range namespaces {
		pods, err := k.client.Clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			k.Logger().Warnf("Failed to list pods in namespace %s: %v", ns, err)
			continue
		}

		for _, pod := range pods.Items {
			hasLimits := false

			// Check containers
			for _, container := range pod.Spec.Containers {
				if container.Resources.Limits == nil || len(container.Resources.Limits) == 0 {
					hasLimits = false
					break
				}
				hasLimits = true
			}

			// Check init containers
			if hasLimits {
				for _, container := range pod.Spec.InitContainers {
					if container.Resources.Limits == nil || len(container.Resources.Limits) == 0 {
						hasLimits = false
						break
					}
				}
			}

			if !hasLimits {
				noLimitsPods = append(noLimitsPods, fmt.Sprintf("%s/%s", pod.Namespace, pod.Name))
			}
		}
	}

	if len(noLimitsPods) == 0 {
		return k.CreatePassResult(check, "All pods have resource limits defined"), nil
	}

	return k.CreateWarnResult(check, noLimitsPods, fmt.Sprintf("Found %d pod(s) without resource limits", len(noLimitsPods))), nil
}

// checkDefaultServiceAccount checks if pods are using the default ServiceAccount
// Ported from: check-baseline.sh
func (k *K8sChecker) checkDefaultServiceAccount(ctx context.Context, check types.Check, options *checker.ExecutionOptions) (*types.Result, error) {
	namespaces, err := k.getNamespaces(ctx, options)
	if err != nil {
		return k.CreateErrorResult(check, err), nil
	}

	var defaultSAPods []string

	for _, ns := range namespaces {
		pods, err := k.client.Clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			k.Logger().Warnf("Failed to list pods in namespace %s: %v", ns, err)
			continue
		}

		for _, pod := range pods.Items {
			// If serviceAccountName is empty or "default", it's using the default SA
			saName := pod.Spec.ServiceAccountName
			if saName == "" || saName == "default" {
				defaultSAPods = append(defaultSAPods, fmt.Sprintf("%s/%s", pod.Namespace, pod.Name))
			}
		}
	}

	if len(defaultSAPods) == 0 {
		return k.CreatePassResult(check, "No pods using default ServiceAccount"), nil
	}

	return k.CreateWarnResult(check, defaultSAPods, fmt.Sprintf("Found %d pod(s) using default ServiceAccount", len(defaultSAPods))), nil
}

// checkImagePullPolicy checks if containers have proper image pull policy set
func (k *K8sChecker) checkImagePullPolicy(ctx context.Context, check types.Check, options *checker.ExecutionOptions) (*types.Result, error) {
	namespaces, err := k.getNamespaces(ctx, options)
	if err != nil {
		return k.CreateErrorResult(check, err), nil
	}

	var noPullPolicyPods []string

	for _, ns := range namespaces {
		pods, err := k.client.Clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			k.Logger().Warnf("Failed to list pods in namespace %s: %v", ns, err)
			continue
		}

		for _, pod := range pods.Items {
			for _, container := range pod.Spec.Containers {
				if container.ImagePullPolicy == "" || container.ImagePullPolicy == "Always" {
					// "Always" is acceptable but "IfNotPresent" is preferred for security
					// Empty defaults to "IfNotPresent" for :latest tag, "Always" otherwise
					// We'll flag if it's explicitly "Always" as it can be a security concern
					if container.ImagePullPolicy == "Always" {
						noPullPolicyPods = append(noPullPolicyPods, fmt.Sprintf("%s/%s:%s", pod.Namespace, pod.Name, container.Name))
					}
				}
			}
		}
	}

	if len(noPullPolicyPods) == 0 {
		return k.CreatePassResult(check, "All containers have appropriate image pull policy"), nil
	}

	return k.CreateWarnResult(check, noPullPolicyPods, fmt.Sprintf("Found %d container(s) with Always image pull policy (consider IfNotPresent)", len(noPullPolicyPods))), nil
}

// checkReadOnlyRootFilesystem checks if containers have read-only root filesystem
func (k *K8sChecker) checkReadOnlyRootFilesystem(ctx context.Context, check types.Check, options *checker.ExecutionOptions) (*types.Result, error) {
	namespaces, err := k.getNamespaces(ctx, options)
	if err != nil {
		return k.CreateErrorResult(check, err), nil
	}

	var writableRootPods []string

	for _, ns := range namespaces {
		pods, err := k.client.Clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			k.Logger().Warnf("Failed to list pods in namespace %s: %v", ns, err)
			continue
		}

		for _, pod := range pods.Items {
			for _, container := range pod.Spec.Containers {
				if container.SecurityContext == nil || container.SecurityContext.ReadOnlyRootFilesystem == nil || !*container.SecurityContext.ReadOnlyRootFilesystem {
					writableRootPods = append(writableRootPods, fmt.Sprintf("%s/%s:%s", pod.Namespace, pod.Name, container.Name))
				}
			}
		}
	}

	if len(writableRootPods) == 0 {
		return k.CreatePassResult(check, "All containers have read-only root filesystem"), nil
	}

	return k.CreateWarnResult(check, writableRootPods, fmt.Sprintf("Found %d container(s) without read-only root filesystem", len(writableRootPods))), nil
}

// checkCapabilities checks if containers drop unnecessary capabilities
func (k *K8sChecker) checkCapabilities(ctx context.Context, check types.Check, options *checker.ExecutionOptions) (*types.Result, error) {
	namespaces, err := k.getNamespaces(ctx, options)
	if err != nil {
		return k.CreateErrorResult(check, err), nil
	}

	var insecureCapPods []string

	for _, ns := range namespaces {
		pods, err := k.client.Clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			k.Logger().Warnf("Failed to list pods in namespace %s: %v", ns, err)
			continue
		}

		for _, pod := range pods.Items {
			for _, container := range pod.Spec.Containers {
				if container.SecurityContext != nil && container.SecurityContext.Capabilities != nil {
					// Check if ALL capabilities are added (dangerous)
					if len(container.SecurityContext.Capabilities.Add) > 0 {
						hasAllCap := false
						for _, cap := range container.SecurityContext.Capabilities.Add {
							if cap == "ALL" {
								hasAllCap = true
								break
							}
						}
						if hasAllCap {
							insecureCapPods = append(insecureCapPods, fmt.Sprintf("%s/%s:%s", pod.Namespace, pod.Name, container.Name))
						}
					}
					// Check if dangerous capabilities are added
					dangerousCaps := []string{"SYS_ADMIN", "NET_ADMIN", "SYS_MODULE", "SYS_RAWIO", "SYS_PTRACE", "SYS_TIME"}
					for _, cap := range container.SecurityContext.Capabilities.Add {
						for _, dangerousCap := range dangerousCaps {
							if string(cap) == dangerousCap {
								insecureCapPods = append(insecureCapPods, fmt.Sprintf("%s/%s:%s (%s)", pod.Namespace, pod.Name, container.Name, cap))
								break
							}
						}
					}
				}
			}
		}
	}

	if len(insecureCapPods) == 0 {
		return k.CreatePassResult(check, "No containers with insecure capabilities found"), nil
	}

	return k.CreateWarnResult(check, insecureCapPods, fmt.Sprintf("Found %d container(s) with insecure capabilities", len(insecureCapPods))), nil
}

// checkSecretsInEnv checks if secrets are exposed via environment variables
func (k *K8sChecker) checkSecretsInEnv(ctx context.Context, check types.Check, options *checker.ExecutionOptions) (*types.Result, error) {
	namespaces, err := k.getNamespaces(ctx, options)
	if err != nil {
		return k.CreateErrorResult(check, err), nil
	}

	var secretsInEnvPods []string

	for _, ns := range namespaces {
		pods, err := k.client.Clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			k.Logger().Warnf("Failed to list pods in namespace %s: %v", ns, err)
			continue
		}

		for _, pod := range pods.Items {
			for _, container := range pod.Spec.Containers {
				for _, env := range container.Env {
					// Check if secret is referenced directly (not via secretKeyRef)
					if env.Value != "" && (env.Name == "PASSWORD" || env.Name == "SECRET" || env.Name == "API_KEY" || env.Name == "TOKEN") {
						secretsInEnvPods = append(secretsInEnvPods, fmt.Sprintf("%s/%s:%s (%s)", pod.Namespace, pod.Name, container.Name, env.Name))
					}
				}
			}
		}
	}

	if len(secretsInEnvPods) == 0 {
		return k.CreatePassResult(check, "No secrets found in environment variables"), nil
	}

	return k.CreateWarnResult(check, secretsInEnvPods, fmt.Sprintf("Found %d container(s) with potential secrets in environment variables", len(secretsInEnvPods))), nil
}

// checkAllowPrivilegeEscalation checks if containers allow privilege escalation
func (k *K8sChecker) checkAllowPrivilegeEscalation(ctx context.Context, check types.Check, options *checker.ExecutionOptions) (*types.Result, error) {
	namespaces, err := k.getNamespaces(ctx, options)
	if err != nil {
		return k.CreateErrorResult(check, err), nil
	}

	var privilegeEscalationPods []string

	for _, ns := range namespaces {
		pods, err := k.client.Clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			k.Logger().Warnf("Failed to list pods in namespace %s: %v", ns, err)
			continue
		}

		for _, pod := range pods.Items {
			for _, container := range pod.Spec.Containers {
				if container.SecurityContext != nil && container.SecurityContext.AllowPrivilegeEscalation != nil && *container.SecurityContext.AllowPrivilegeEscalation {
					privilegeEscalationPods = append(privilegeEscalationPods, fmt.Sprintf("%s/%s:%s", pod.Namespace, pod.Name, container.Name))
				}
			}
		}
	}

	if len(privilegeEscalationPods) == 0 {
		return k.CreatePassResult(check, "No containers allow privilege escalation"), nil
	}

	return k.CreateFailResult(check, privilegeEscalationPods, fmt.Sprintf("Found %d container(s) allowing privilege escalation", len(privilegeEscalationPods))), nil
}

// checkLivenessProbe checks if containers have liveness probes configured
func (k *K8sChecker) checkLivenessProbe(ctx context.Context, check types.Check, options *checker.ExecutionOptions) (*types.Result, error) {
	namespaces, err := k.getNamespaces(ctx, options)
	if err != nil {
		return k.CreateErrorResult(check, err), nil
	}

	var noLivenessProbePods []string

	for _, ns := range namespaces {
		pods, err := k.client.Clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			k.Logger().Warnf("Failed to list pods in namespace %s: %v", ns, err)
			continue
		}

		for _, pod := range pods.Items {
			for _, container := range pod.Spec.Containers {
				if container.LivenessProbe == nil {
					noLivenessProbePods = append(noLivenessProbePods, fmt.Sprintf("%s/%s:%s", pod.Namespace, pod.Name, container.Name))
				}
			}
		}
	}

	if len(noLivenessProbePods) == 0 {
		return k.CreatePassResult(check, "All containers have liveness probes configured"), nil
	}

	return k.CreateWarnResult(check, noLivenessProbePods, fmt.Sprintf("Found %d container(s) without liveness probes", len(noLivenessProbePods))), nil
}

// checkReadinessProbe checks if containers have readiness probes configured
func (k *K8sChecker) checkReadinessProbe(ctx context.Context, check types.Check, options *checker.ExecutionOptions) (*types.Result, error) {
	namespaces, err := k.getNamespaces(ctx, options)
	if err != nil {
		return k.CreateErrorResult(check, err), nil
	}

	var noReadinessProbePods []string

	for _, ns := range namespaces {
		pods, err := k.client.Clientset.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			k.Logger().Warnf("Failed to list pods in namespace %s: %v", ns, err)
			continue
		}

		for _, pod := range pods.Items {
			for _, container := range pod.Spec.Containers {
				if container.ReadinessProbe == nil {
					noReadinessProbePods = append(noReadinessProbePods, fmt.Sprintf("%s/%s:%s", pod.Namespace, pod.Name, container.Name))
				}
			}
		}
	}

	if len(noReadinessProbePods) == 0 {
		return k.CreatePassResult(check, "All containers have readiness probes configured"), nil
	}

	return k.CreateWarnResult(check, noReadinessProbePods, fmt.Sprintf("Found %d container(s) without readiness probes", len(noReadinessProbePods))), nil
}

