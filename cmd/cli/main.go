package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/k8s-security-baseline-checker/internal/benchmark"
	"github.com/k8s-security-baseline-checker/internal/checker"
	k8schecker "github.com/k8s-security-baseline-checker/internal/checker/k8s"
	"github.com/k8s-security-baseline-checker/internal/reporter"
	"github.com/k8s-security-baseline-checker/pkg/errors"
	"github.com/k8s-security-baseline-checker/pkg/k8s"
	"github.com/k8s-security-baseline-checker/pkg/types"
	"github.com/k8s-security-baseline-checker/pkg/validation"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile      string
	outputPath   string
	outputFormat string
	benchmarkID  string
	namespace    string
	verbose      bool
	parallel     bool
)

var rootCmd = &cobra.Command{
	Use:   "k8s-checker",
	Short: "Kubernetes Security Baseline Checker",
	Long:  "Enterprise-grade security benchmarking tool for Kubernetes and cloud environments",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if verbose {
			logrus.SetLevel(logrus.DebugLevel)
		}
	},
}

var checkK8sCmd = &cobra.Command{
	Use:   "k8s",
	Short: "Check Kubernetes cluster security",
	Long:  "Run security checks against a Kubernetes cluster",
	RunE:  runK8sCheck,
}

var checkCloudCmd = &cobra.Command{
	Use:   "cloud",
	Short: "Check cloud provider security",
	Long:  "Run security checks against cloud provider resources (AWS, Azure, GCP)",
	RunE:  runCloudCheck,
}

var checkAllCmd = &cobra.Command{
	Use:   "all",
	Short: "Check both Kubernetes and cloud",
	Long:  "Run security checks against both Kubernetes cluster and cloud provider",
	RunE:  runAllChecks,
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.k8s-checker.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().StringVarP(&outputPath, "output", "o", "", "output file path")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "format", "f", "json", "output format (json, html, csv, pdf)")

	// Check command flags
	checkCmd := &cobra.Command{
		Use:   "check",
		Short: "Run security checks",
		Long:  "Execute security checks against Kubernetes or cloud environments",
	}
	checkCmd.PersistentFlags().StringVarP(&benchmarkID, "benchmark", "b", "", "benchmark ID to use (cis, nist, custom)")
	checkCmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", "", "namespace to check (empty for all)")
	checkCmd.PersistentFlags().BoolVar(&parallel, "parallel", true, "run checks in parallel")

	checkCmd.AddCommand(checkK8sCmd)
	checkCmd.AddCommand(checkCloudCmd)
	checkCmd.AddCommand(checkAllCmd)
	rootCmd.AddCommand(checkCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err == nil {
			viper.AddConfigPath(home)
		}
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".k8s-checker")
	}

	viper.AutomaticEnv()
	viper.ReadInConfig()
}

func runK8sCheck(cmd *cobra.Command, args []string) error {
	initConfig()

	logger := logrus.New()
	if verbose {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}

	// Enterprise requirement: Input validation for CLI
	validator := validation.NewValidator()

	// Validate benchmark ID if provided
	if benchmarkID != "" {
		if err := validator.ValidateBenchmarkID(benchmarkID); err != nil {
			return errors.NewValidationError("invalid benchmark ID", err.Error())
		}
	}

	// Validate output format
	if outputFormat != "" {
		if err := validator.ValidateOutputFormat(outputFormat); err != nil {
			return errors.NewValidationError("invalid output format", err.Error())
		}
	}

	// Validate namespace if provided
	if namespace != "" {
		if err := validator.ValidateKubernetesNamespace(namespace); err != nil {
			return errors.NewValidationError("invalid namespace", err.Error())
		}
	}

	// Validate output path if provided
	if outputPath != "" {
		if err := validator.ValidateFilePath(outputPath); err != nil {
			return errors.NewValidationError("invalid output path", err.Error())
		}
	}

	// Validate kubeconfig path if provided
	kubeconfig := viper.GetString("kubeconfig")
	if kubeconfig != "" {
		if err := validator.ValidateFilePath(kubeconfig); err != nil {
			return errors.NewValidationError("invalid kubeconfig path", err.Error())
		}
	}

	// Initialize Kubernetes client
	k8sClient, err := k8s.NewClient(kubeconfig)
	if err != nil {
		return errors.NewExecutionError("failed to create Kubernetes client", err)
	}

	// Get cluster info
	clusterInfo := &types.ClusterInfo{
		K8sVersion: k8sClient.Config.Host,
		Provider:   "unknown",
	}

	// Initialize benchmark registry
	benchmarkDir := viper.GetString("benchmark_dir")
	if benchmarkDir == "" {
		benchmarkDir = filepath.Join(".", "benchmarks")
	}
	registry := benchmark.NewRegistry(benchmarkDir)

	// Load benchmark with validation
	var bench *types.Benchmark
	if benchmarkID != "" {
		// Validate benchmark ID before loading
		if err := validator.ValidateBenchmarkID(benchmarkID); err != nil {
			return errors.NewValidationError("invalid benchmark ID", err.Error())
		}

		bench, err = registry.Get(benchmarkID)
		if err != nil {
			// Try loading by framework
			loadErr := registry.LoadFramework(benchmarkID)
			if loadErr == nil {
				benchmarks := registry.ListByFramework(benchmarkID)
				if len(benchmarks) > 0 {
					bench, err = registry.Get(benchmarks[0])
					if err == nil {
						// Successfully loaded benchmark by framework
						err = nil
					}
				} else {
					err = fmt.Errorf("no benchmarks found for framework '%s'", benchmarkID)
				}
			} else {
				// LoadFramework failed, combine errors
				err = fmt.Errorf("failed to load benchmark '%s' and failed to load framework: %w (original: %w)", benchmarkID, loadErr, err)
			}
		}
		if err != nil {
			return errors.NewExecutionError("failed to load benchmark", err)
		}
	} else {
		// Default to CIS
		if err := registry.LoadFramework("cis"); err != nil {
			return errors.NewExecutionError("failed to load CIS benchmark", err)
		}
		benchmarks := registry.ListByFramework("cis")
		if len(benchmarks) > 0 {
			bench, err = registry.Get(benchmarks[0])
			if err != nil {
				return errors.NewExecutionError("failed to get benchmark", err)
			}
		} else {
			return errors.NewExecutionError("no benchmarks found", fmt.Errorf("no CIS benchmarks available"))
		}
	}

	// Initialize checker engine
	engine := checker.NewEngine(logger)

	// Register Kubernetes checker
	k8sChecker, err := k8schecker.NewK8sChecker(k8sClient, logger)
	if err != nil {
		return fmt.Errorf("failed to create K8s checker: %w", err)
	}
	if err := engine.Register(k8sChecker); err != nil {
		return fmt.Errorf("failed to register K8s checker: %w", err)
	}

	// Prepare execution options
	options := &checker.ExecutionOptions{
		ClusterInfo: clusterInfo,
		Logger:      logger,
		Config:      make(map[string]interface{}),
	}
	if namespace != "" {
		options.Namespaces = []string{namespace}
	}

	// Execute benchmark
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	report, err := engine.ExecuteBenchmark(ctx, *bench, options, parallel)
	if err != nil {
		return errors.NewExecutionError("failed to execute benchmark", err)
	}

	// Generate report
	outputDir := viper.GetString("output_dir")
	if outputDir == "" {
		outputDir = "."
	}
	gen := reporter.NewGenerator(outputDir)

	if outputPath == "" {
		outputPath = filepath.Join(outputDir, fmt.Sprintf("report-%s.%s", report.ID, outputFormat))
	}

	// Validate output path before generating
	if err := validator.ValidateFilePath(outputPath); err != nil {
		return errors.NewValidationError("invalid output path", err.Error())
	}

	if err := gen.Generate(report, outputFormat, outputPath); err != nil {
		return errors.NewExecutionError("failed to generate report", err)
	}

	fmt.Printf("✓ Report generated: %s\n", outputPath)
	fmt.Printf("  Compliance Score: %d%% (Grade: %s)\n", report.ComplianceScore, report.Grade)
	fmt.Printf("  Total Checks: %d | Passed: %d | Failed: %d | Warnings: %d\n",
		report.TotalChecks, report.PassedChecks, report.FailedChecks, report.WarnedChecks)

	return nil
}

func runCloudCheck(cmd *cobra.Command, args []string) error {
	return fmt.Errorf("cloud checks not yet implemented")
}

func runAllChecks(cmd *cobra.Command, args []string) error {
	if err := runK8sCheck(cmd, args); err != nil {
		return err
	}
	// TODO: Add cloud checks
	return nil
}
