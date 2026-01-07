#!/bin/bash

NAMESPACES=$(kubectl get ns -o jsonpath='{.items[*].metadata.name}')

echo "Starting Kubernetes Security Baseline Checks..."

for ns in $NAMESPACES; do
    PODS=$(kubectl get pods -n $ns -o json)
    
    # Check 1: Pods running as root
    echo "$PODS" | jq -r '.items[] | select(.spec.containers[]?.securityContext.runAsNonRoot == false or .spec.containers[]?.securityContext.runAsUser == 0) | "[CRITICAL] Namespace '$ns': Pod \(.metadata.name) running as root"'
    
    # Check 2: Privileged containers
    echo "$PODS" | jq -r '.items[] | select(.spec.containers[]?.securityContext.privileged == true) | "[CRITICAL] Namespace '$ns': Pod \(.metadata.name) running privileged"'
    
    # Check 3: Missing NetworkPolicies
    NETPOL=$(kubectl get netpol -n $ns --no-headers 2>/dev/null | wc -l)
    if [ "$NETPOL" -eq 0 ]; then
        echo "[WARN] Namespace $ns: No NetworkPolicy found"
    fi
    
    # Check 4: Default ServiceAccount
    echo "$PODS" | jq -r '.items[] | select(.spec.serviceAccountName=="default") | "[WARN] Namespace '$ns': Pod \(.metadata.name) uses default SA"'
    
    # Check 5: Resource limits
    echo "$PODS" | jq -r '.items[] | select(.spec.containers[]?.resources.limits == null) | "[WARN] Namespace '$ns': Pod \(.metadata.name) has no resource limits"'
done
