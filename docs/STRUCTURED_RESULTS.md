# Structured Results with Severity and Remediation

## Overview

All production-ready CIS v1.8 checks return structured results with severity levels and detailed remediation guidance.

## Result Structure

```go
type Result struct {
    CheckID     string      // CIS control ID
    Status      CheckStatus // PASS, FAIL, WARN, ERROR, SKIP
    Severity    Severity    // CRITICAL, HIGH, MEDIUM, LOW, INFO
    Details     []string    // Detailed findings with remediation
    Remediation string      // General remediation guidance
    Weight      int         // Weight for scoring
    Message     string      // Human-readable summary
    Timestamp   time.Time   // Execution timestamp
    Duration    time.Duration // Execution duration
}
```

## Example: API Server Flags Check

### Input
```yaml
check:
  id: "cis-1.2.1"
  type: "check_apiserver_flags"
  severity: "CRITICAL"
  remediation: "Edit the API server pod specification file and set --anonymous-auth=false"
```

### Output (JSON)
```json
{
  "check_id": "cis-1.2.1",
  "status": "FAIL",
  "severity": "CRITICAL",
  "details": [
    "pod/kube-system/kube-apiserver-master-1: Missing required flag '--anonymous-auth' (Disable anonymous authentication). Remediation: Add '--anonymous-auth=false' to API server configuration",
    "pod/kube-system/kube-apiserver-master-1: Flag '--authorization-mode' has invalid value 'AlwaysAllow' (got 'AlwaysAllow', expected 'Node,RBAC'). Remediation: Set '--authorization-mode=Node,RBAC' in API server configuration",
    "pod/kube-system/kube-apiserver-master-1: Dangerous flag '--insecure-port' is enabled (value: '8080'). Should be set to 0 or removed. Remediation: Remove flag or set '--insecure-port=0'"
  ],
  "remediation": "Edit the API server pod specification file and set --anonymous-auth=false",
  "weight": 3,
  "message": "Found 3 API server flag violation(s) across 1 pod(s)",
  "timestamp": "2024-01-13T18:45:00Z",
  "duration": "125ms"
}
```

## Example: etcd Encryption Check

### Output (JSON)
```json
{
  "check_id": "cis-1.1.20",
  "status": "FAIL",
  "severity": "CRITICAL",
  "details": [
    "pod/kube-system/kube-apiserver-master-1: API server does not have --encryption-provider-config flag set. etcd data is stored in plaintext. Remediation: Configure encryption provider using --encryption-provider-config flag pointing to encryption configuration file. See: https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/"
  ],
  "remediation": "Configure etcd encryption at rest using --encryption-provider-config flag. See: https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/",
  "weight": 3,
  "message": "etcd encryption not configured: 1 violation(s) found",
  "timestamp": "2024-01-13T18:45:01Z",
  "duration": "98ms"
}
```

## Example: RBAC Advanced Check

### Output (JSON)
```json
{
  "check_id": "cis-1.1.1",
  "status": "FAIL",
  "severity": "CRITICAL",
  "details": [
    "ClusterRole 'admin-role' contains wildcard privileges: verbs=*, resources=*. This violates the principle of least privilege. Remediation: Replace wildcard privileges in ClusterRole 'admin-role' with specific verbs, resources, and API groups. Example: Use ['get', 'list'] instead of ['*'], use ['pods', 'services'] instead of ['*']",
    "ClusterRoleBinding 'admin-binding' grants cluster-admin privileges to non-system accounts. This is a critical security risk. Remediation: Review and restrict ClusterRoleBinding 'admin-binding'. Use least privilege roles instead of cluster-admin. Consider creating custom ClusterRoles with only required permissions."
  ],
  "remediation": "Avoid giving '*' verbs/resources to cluster-admin or any other roles. Review all ClusterRoles and Roles for wildcard privileges.",
  "weight": 2,
  "message": "Found 2 RBAC misconfiguration(s)",
  "timestamp": "2024-01-13T18:45:02Z",
  "duration": "234ms"
}
```

## Example: Namespace Isolation Check

### Output (JSON)
```json
{
  "check_id": "cis-4.1.1",
  "status": "FAIL",
  "severity": "HIGH",
  "details": [
    "Namespace 'production' does not have any NetworkPolicies configured. This allows unrestricted network traffic between pods. Remediation: Create default-deny NetworkPolicy for namespace 'production'. Example: kubectl apply -f - <<EOF\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: default-deny\n  namespace: production\nspec:\n  podSelector: {}\n  policyTypes:\n  - Ingress\n  - Egress\nEOF",
    "Namespace 'production' does not have ResourceQuota configured. This can lead to resource exhaustion. Remediation: Create ResourceQuota for namespace 'production' to limit resource consumption. Example: kubectl create quota production-quota --hard=cpu=2,memory=4Gi --namespace=production",
    "Namespace 'production' does not have LimitRange configured. Containers can be created without resource limits. Remediation: Create LimitRange for namespace 'production' to enforce default resource limits."
  ],
  "remediation": "Create default-deny NetworkPolicies for all namespaces. Also configure ResourceQuotas and LimitRanges for proper namespace isolation.",
  "weight": 2,
  "message": "Found 3 namespace isolation issue(s) across 5 namespace(s)",
  "timestamp": "2024-01-13T18:45:03Z",
  "duration": "456ms"
}
```

## Example: Pod Security Standards Check

### Output (JSON)
```json
{
  "check_id": "cis-5.2.1",
  "status": "FAIL",
  "severity": "HIGH",
  "details": [
    "Namespace 'production' does not have Pod Security Standards enforcement configured. Pods can be created without security restrictions. Remediation: Add pod-security.kubernetes.io/enforce label to namespace 'production'. Example: kubectl label namespace production pod-security.kubernetes.io/enforce=restricted --overwrite. Use 'restricted' for maximum security or 'baseline' for compatibility.",
    "Namespace 'staging' uses weak Pod Security Standards level 'privileged'. Consider using 'restricted' for maximum security. Remediation: Update pod-security.kubernetes.io/enforce label to 'restricted' for namespace 'staging'."
  ],
  "remediation": "Add pod-security.kubernetes.io/enforce label to namespaces with value 'restricted' or 'baseline'. Example: kubectl label namespace <namespace> pod-security.kubernetes.io/enforce=restricted",
  "weight": 2,
  "message": "Found 2 Pod Security Standards issue(s) across 5 namespace(s)",
  "timestamp": "2024-01-13T18:45:04Z",
  "duration": "189ms"
}
```

## Severity Mapping

| Severity | Description | Examples |
|----------|-------------|----------|
| **CRITICAL** | Immediate security risk | etcd not encrypted, anonymous auth enabled, cluster-admin bindings |
| **HIGH** | Significant security concern | Missing NetworkPolicies, wildcard RBAC, no PSS enforcement |
| **MEDIUM** | Moderate security issue | Missing ResourceQuotas, weak PSS level, missing audit mode |
| **LOW** | Minor security concern | Missing LimitRanges, informational findings |

## Remediation Format

Each detail entry follows this format:

```
<Resource>: <Issue Description>. Remediation: <Step-by-step fix instructions>
```

**Example**:
```
pod/kube-system/kube-apiserver-xxx: Missing required flag '--anonymous-auth' (Disable anonymous authentication). Remediation: Add '--anonymous-auth=false' to API server configuration
```

## Benefits

1. **Structured**: Consistent format across all checks
2. **Severity-Based**: Clear prioritization of issues
3. **Actionable**: Detailed remediation steps for each finding
4. **Traceable**: Resource identifiers for each issue
5. **Comprehensive**: Multiple findings per check when applicable

## Integration

Results integrate seamlessly with:
- Compliance mapping engine (maps to NIST, ISO27001, SOC2)
- Report generators (HTML, JSON, CSV)
- Scoring systems (weighted by severity)
- CI/CD pipelines (fail on CRITICAL findings)

---

**Status**: ✅ All Checks Return Structured Results with Severity and Remediation
