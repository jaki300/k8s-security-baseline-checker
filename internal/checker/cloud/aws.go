package cloud

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/k8s-security-baseline-checker/internal/checker"
	"github.com/k8s-security-baseline-checker/pkg/types"
	"github.com/sirupsen/logrus"
)

// AWSChecker implements checks for AWS cloud resources
type AWSChecker struct {
	*BaseCloudChecker
	config aws.Config
}

// NewAWSChecker creates a new AWS checker
func NewAWSChecker(logger *logrus.Logger) (*AWSChecker, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	base := NewBaseCloudChecker("aws-checker", "aws", logger)
	return &AWSChecker{
		BaseCloudChecker: base,
		config:           cfg,
	}, nil
}

// Validate checks if this checker can handle the given check
func (a *AWSChecker) Validate(check types.Check) bool {
	return check.Framework == "aws" || check.Framework == "cloud"
}

// Execute runs AWS-specific checks
func (a *AWSChecker) Execute(ctx context.Context, check types.Check, options *checker.ExecutionOptions) (*types.Result, error) {
	switch check.Type {
	case "check_eks_security":
		return a.checkEKSSecurity(ctx, check, options)
	case "check_iam_policies":
		return a.checkIAMPolicies(ctx, check, options)
	case "check_s3_buckets":
		return a.checkS3Buckets(ctx, check, options)
	default:
		return a.CreateErrorResult(check, fmt.Errorf("unknown AWS check type: %s", check.Type)), nil
	}
}

// checkEKSSecurity checks EKS cluster security
func (a *AWSChecker) checkEKSSecurity(ctx context.Context, check types.Check, options *checker.ExecutionOptions) (*types.Result, error) {
	client := eks.NewFromConfig(a.config)
	
	clusters, err := client.ListClusters(ctx, &eks.ListClustersInput{})
	if err != nil {
		return a.CreateErrorResult(check, err), nil
	}

	var issues []string
	for _, clusterName := range clusters.Clusters {
		cluster, err := client.DescribeCluster(ctx, &eks.DescribeClusterInput{
			Name: aws.String(clusterName),
		})
		if err != nil {
			continue
		}

		// Check if logging is enabled
		if cluster.Cluster.Logging == nil || len(cluster.Cluster.Logging.ClusterLogging) == 0 {
			issues = append(issues, fmt.Sprintf("EKS cluster %s: logging not enabled", clusterName))
		}

		// Check encryption
		if cluster.Cluster.EncryptionConfig == nil || len(cluster.Cluster.EncryptionConfig) == 0 {
			issues = append(issues, fmt.Sprintf("EKS cluster %s: encryption not configured", clusterName))
		}
	}

	if len(issues) > 0 {
		return a.CreateFailResult(check, issues, "EKS security issues found"), nil
	}

	return a.CreatePassResult(check, "All EKS clusters are secure"), nil
}

// checkIAMPolicies checks IAM policy security
func (a *AWSChecker) checkIAMPolicies(ctx context.Context, check types.Check, options *checker.ExecutionOptions) (*types.Result, error) {
	// TODO: Implement IAM policy checks
	return a.CreateWarnResult(check, []string{"IAM policy checks not yet implemented"}, "Check IAM policies manually"), nil
}

// checkS3Buckets checks S3 bucket security
func (a *AWSChecker) checkS3Buckets(ctx context.Context, check types.Check, options *checker.ExecutionOptions) (*types.Result, error) {
	// TODO: Implement S3 bucket checks
	return a.CreateWarnResult(check, []string{"S3 bucket checks not yet implemented"}, "Check S3 buckets manually"), nil
}

