#!/bin/bash

# ================================
# Kubernetes Security Baseline Checker v1.3
# Features:
# - Cluster overview (nodes, version, CNI, storage)
# - Cluster health summary (Ready nodes, Pending/CrashLoop pods)
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
OUTPUT_FORMAT="text"
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
        -f|--format)
            OUTPUT_FORMAT="$2"
            shift
            shift
            ;;
        *)
            echo "Unknown argument: $1"
            echo "Usage: $0 [-n|--namespace NAMESPACE] [-o|--output OUTPUT_FILE] [-f|--format text|csv|json]"
            exit 1
            ;;
    esac
done

echo -e "${GREEN}Starting Kubernetes Security Baseline Checker...${NC}\n"

# -----------------------------
# Cluster Info
# -----------------------------
echo -e "${GREEN}Cluster Overview:${NC}"

# Kubernetes version
K8S_VERSION=$(kubectl version -o json | jq -r '.serverVersion.gitVersion')
echo -e "Kubernetes Version: $K8S_VERSION"

# Nodes info
echo "Nodes:"
kubectl get nodes -o json | jq -r '.items[] |
    .metadata.name as $name |
    .status.conditions[] | select(.type=="Ready") |
    "\($name) - \(.status)"' | while read line; do
    if [[ $line == *"True"* ]]; then
        echo -e "${GREEN}✔ $line${NC}"
    else
        echo -e "${RED}❌ $line${NC}"
    fi
done

# Networking plugin (CNI)
CNI=$(kubectl get ds -n kube-system -o jsonpath='{.items[*].metadata.name}' | grep -E "calico|flannel|cilium|weave" || echo "Unknown")
echo -e "Networking Plugin(s): $CNI"

# Storage classes
SC=$(kubectl get sc -o jsonpath='{.items[*].metadata.name}')
echo -e "Storage Classes: $SC"

# -----------------------------
# Cluster Health Summary
# -----------------------------
TOTAL_NODES=$(kubectl get nodes --no-headers | wc -l)
READY_NODES=$(kubectl get nodes --no-headers | grep Ready | wc -l)
PENDING_PODS=$(kubectl get pods --all-namespaces --field-selector=status.phase=Pending --no-headers | wc -l)
CRASHLOOP_PODS=$(kubectl get pods --all-namespaces -o json | jq '[.items[] | select(.status.containerStatuses[]? | .state.waiting.reason=="CrashLoopBackOff")] | length')
echo -e "\n${GREEN}Cluster Health Summary:${NC}"
echo -e "Nodes Ready: $READY_NODES/$TOTAL_NODES"
echo -e "Pending Pods: $PENDING_PODS, CrashLoopBackOff Pods: $CRASHLOOP_PODS"

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
CSV_HEADER="Namespace,Pod,Check,Status,Message"
if [[ "$OUTPUT_FORMAT" == "csv" && -n "$OUTPUT_FILE" ]]; then
    echo "$CSV_HEADER" > "$OUTPUT_FILE"
fi

for ns in $NAMESPACES; do
    PODS=$(kubectl get pods -n $ns -o json)
    OK_FLAG=true

    # 1. Pods running as root
    ROOT_PODS=$(echo "$PODS" | jq -r '.items[] | select(.spec.containers[]?.securityContext.runAsNonRoot == false or .spec.containers[]?.securityContext.runAsUser == 0) | .metadata.name')
    for pod in $ROOT_PODS; do
        msg="[CRITICAL] Namespace $ns: Pod $pod running as root"
        echo -e "${RED}❌ $msg${NC}"
        OK_FLAG=false
        RESULTS+="$msg"$'\n'
        if [[ "$OUTPUT_FORMAT" == "csv" && -n "$OUTPUT_FILE" ]]; then
            echo "$ns,$pod,RunningAsRoot,CRITICAL,$msg" >> "$OUTPUT_FILE"
        fi
    done

    # 2. Privileged containers
    PRIV_PODS=$(echo "$PODS" | jq -r '.items[] | select(.spec.containers[]?.securityContext.privileged == true) | .metadata.name')
    for pod in $PRIV_PODS; do
        msg="[CRITICAL] Namespace $ns: Pod $pod running privileged"
        echo -e "${RED}❌ $msg${NC}"
        OK_FLAG=false
        RESULTS+="$msg"$'\n'
        [[ "$OUTPUT_FORMAT" == "csv" && -n "$OUTPUT_FILE" ]] && echo "$ns,$pod,Privileged,CRITICAL,$msg" >> "$OUTPUT_FILE"
    done

    # 3. Missing NetworkPolicies
    NETPOL=$(kubectl get netpol -n $ns --no-headers 2>/dev/null | wc -l)
    if [ "$NETPOL" -eq 0 ]; then
        msg="[WARN] Namespace $ns: No NetworkPolicy found"
        echo -e "${YELLOW}⚠️ $msg${NC}"
        OK_FLAG=false
        RESULTS+="$msg"$'\n'
        [[ "$OUTPUT_FORMAT" == "csv" && -n "$OUTPUT_FILE" ]] && echo "$ns,,NetworkPolicy,WARN,$msg" >> "$OUTPUT_FILE"
    fi

    # 4. Default ServiceAccount
    DEF_SA=$(echo "$PODS" | jq -r '.items[] | select(.spec.serviceAccountName=="default") | .metadata.name')
    for pod in $DEF_SA; do
        msg="[WARN] Namespace $ns: Pod $pod uses default SA"
        echo -e "${YELLOW}⚠️ $msg${NC}"
        OK_FLAG=false
        RESULTS+="$msg"$'\n'
        [[ "$OUTPUT_FORMAT" == "csv" && -n "$OUTPUT_FILE" ]] && echo "$ns,$pod,DefaultSA,WARN,$msg" >> "$OUTPUT_FILE"
    done

    # 5. Resource limits
    NO_LIMITS=$(echo "$PODS" | jq -r '.items[] | select(.spec.containers[]?.resources.limits == null) | .metadata.name')
    for pod in $NO_LIMITS; do
        msg="[WARN] Namespace $ns: Pod $pod has no resource limits"
        echo -e "${YELLOW}⚠️ $msg${NC}"
        OK_FLAG=false
        RESULTS+="$msg"$'\n'
        [[ "$OUTPUT_FORMAT" == "csv" && -n "$OUTPUT_FILE" ]] && echo "$ns,$pod,ResourceLimits,WARN,$msg" >> "$OUTPUT_FILE"
    done

    # ✅ All good
    if [ "$OK_FLAG" = true ]; then
        msg="Namespace $ns: All checked pods compliant"
        echo -e "${GREEN}✅ $msg${NC}"
        RESULTS+="$msg"$'\n'
        [[ "$OUTPUT_FORMAT" == "csv" && -n "$OUTPUT_FILE" ]] && echo "$ns,,Compliant,OK,$msg" >> "$OUTPUT_FILE"
    fi
done

# -----------------------------
# Save output to file
# -----------------------------
if [[ -n "$OUTPUT_FILE" && "$OUTPUT_FORMAT" != "csv" ]]; then
    echo "$RESULTS" > "$OUTPUT_FILE"
    echo -e "\n${GREEN}Output saved to $OUTPUT_FILE${NC}"
fi