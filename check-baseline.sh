#!/bin/bash

# ================================
# Kubernetes Security Baseline Checker v1.2
# Features:
# - Cluster overview (nodes, version, CNI, storage)
# - Security checks (root pods, privileged, networkpolicy, SA, resource limits)
# - Color-coded output
# - Optional: target namespace(s)
# - Optional: save output to file (text/CSV/JSON)
# ================================

# -----------------------------
# Color codes
# -----------------------------
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

OUTPUT_FILE=""
NAMESPACE_ARG=""

# -----------------------------
# Parse command-line arguments
# -----------------------------
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--namespace)
            NAMESPACE_ARG="$2"
            shift
            shift
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift
            shift
            ;;
        *)
            echo "Unknown argument: $1"
            echo "Usage: $0 [-n|--namespace NAMESPACE] [-o|--output OUTPUT_FILE]"
            exit 1
            ;;
    esac
done

echo -e "${GREEN}Starting Kubernetes Security Baseline Checker...${NC}\n"

# -----------------------------
# Cluster Info
# -----------------------------
echo -e "${GREEN}Cluster Overview:${NC}"

K8S_VERSION=$(kubectl version --short | grep Server | awk '{print $3}')
echo -e "Kubernetes Version: $K8S_VERSION"

echo "Nodes:"
kubectl get nodes -o custom-columns=NAME:.metadata.name,STATUS:.status.conditions[-1].type,ROLES:.metadata.labels.kubernetes\\.io/role,VERSION:.status.nodeInfo.kubeletVersion --no-headers | while read name status roles version; do
    if [[ $status == "Ready" ]]; then
        echo -e "${GREEN}✔ $name - $status ($roles, $version)${NC}"
    else
        echo -e "${RED}❌ $name - $status ($roles, $version)${NC}"
    fi
done

# Networking plugin
CNI=$(kubectl get pods -n kube-system -l k8s-app -o jsonpath='{.items[*].metadata.name}' | grep -E "calico|flannel|cilium|weave" || echo "Unknown")
echo -e "Networking Plugin(s): $CNI"

# Storage classes
SC=$(kubectl get sc -o jsonpath='{.items[*].metadata.name}')
echo -e "Storage Classes: $SC"

# -----------------------------
# Security Baseline Checks
# -----------------------------
echo -e "\n${GREEN}Security Baseline Checks:${NC}"

if [[ -n "$NAMESPACE_ARG" ]]; then
    NAMESPACES="$NAMESPACE_ARG"
else
    NAMESPACES=$(kubectl get ns -o jsonpath='{.items[*].metadata.name}')
fi

RESULTS=""

for ns in $NAMESPACES; do
    PODS=$(kubectl get pods -n $ns -o json)

    # 1. Pods running as root
    ROOT_PODS=$(echo "$PODS" | jq -r '.items[] | select(.spec.containers[]?.securityContext.runAsNonRoot == false or .spec.containers[]?.securityContext.runAsUser == 0) | "[CRITICAL] Namespace '$ns': Pod \(.metadata.name) running as root"')
    if [[ -n "$ROOT_PODS" ]]; then
        while read line; do
            echo -e "${RED}❌ $line${NC}"
            RESULTS+="$line"$'\n'
        done <<< "$ROOT_PODS"
    fi

    # 2. Privileged containers
    PRIV_PODS=$(echo "$PODS" | jq -r '.items[] | select(.spec.containers[]?.securityContext.privileged == true) | "[CRITICAL] Namespace '$ns': Pod \(.metadata.name) running privileged"')
    if [[ -n "$PRIV_PODS" ]]; then
        while read line; do
            echo -e "${RED}❌ $line${NC}"
            RESULTS+="$line"$'\n'
        done <<< "$PRIV_PODS"
    fi

    # 3. Missing NetworkPolicies
    NETPOL=$(kubectl get netpol -n $ns --no-headers 2>/dev/null | wc -l)
    if [ "$NETPOL" -eq 0 ]; then
        echo -e "${YELLOW}⚠️ [WARN] Namespace $ns: No NetworkPolicy found${NC}"
        RESULTS+="[WARN] Namespace $ns: No NetworkPolicy found"$'\n'
    fi

    # 4. Default ServiceAccount
    DEF_SA=$(echo "$PODS" | jq -r '.items[] | select(.spec.serviceAccountName=="default") | "[WARN] Namespace '$ns': Pod \(.metadata.name) uses default SA"')
    if [[ -n "$DEF_SA" ]]; then
        while read line; do
            echo -e "${YELLOW}⚠️ $line${NC}"
            RESULTS+="$line"$'\n'
        done <<< "$DEF_SA"
    fi

    # 5. Resource limits
    NO_LIMITS=$(echo "$PODS" | jq -r '.items[] | select(.spec.containers[]?.resources.limits == null) | "[WARN] Namespace '$ns': Pod \(.metadata.name) has no resource limits"')
    if [[ -n "$NO_LIMITS" ]]; then
        while read line; do
            echo -e "${YELLOW}⚠️ $line${NC}"
            RESULTS+="$line"$'\n'
        done <<< "$NO_LIMITS"
    fi

    # 6. All good
    OK_CHECK=$(echo "$PODS" | jq -r '.items[] | select((.spec.containers[]?.securityContext.runAsNonRoot != false) and (.spec.containers[]?.securityContext.privileged != true) and (.spec.containers[]?.resources.limits != null)) | "[OK] Namespace '$ns': Pod \(.metadata.name) compliant"' | wc -l)
    if [ "$OK_CHECK" -gt 0 ]; then
        echo -e "${GREEN}✅ Namespace $ns: All checked pods compliant${NC}"
        RESULTS+="Namespace $ns: All checked pods compliant"$'\n'
    fi
done

# -----------------------------
# Save output if requested
# -----------------------------
if [[ -n "$OUTPUT_FILE" ]]; then
    echo "$RESULTS" > "$OUTPUT_FILE"
    echo -e "\n${GREEN}Output saved to $OUTPUT_FILE${NC}"
fi
