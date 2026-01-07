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
