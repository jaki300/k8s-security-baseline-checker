# Kubernetes Security Baseline Checker

This tool checks your Kubernetes cluster against common security best practices.

## Features (v1)
- Detects pods running as root
- Detects privileged containers
- Detects missing NetworkPolicies
- Detects pods using default ServiceAccount
- Detects pods without resource limits

## Usage
```bash
git clone https://github.com/YOUR_USERNAME/k8s-security-baseline-checker.git
cd k8s-security-baseline-checker
bash check-baseline.sh



##
Usage Examples

Check all namespaces, default text output:

bash check-baseline.sh


Check specific namespace:

bash check-baseline.sh -n kube-system


Check namespace and save CSV report:

bash check-baseline.sh -n default -o report.csv -f csv


Check all namespaces and save text report:

bash check-baseline.sh -o report.txt
