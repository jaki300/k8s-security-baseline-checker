package api

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/k8s-security-baseline-checker/internal/benchmark"
	"github.com/k8s-security-baseline-checker/internal/checker"
	k8schecker "github.com/k8s-security-baseline-checker/internal/checker/k8s"
	"github.com/k8s-security-baseline-checker/internal/reporter"
	"github.com/k8s-security-baseline-checker/pkg/errors"
	"github.com/k8s-security-baseline-checker/pkg/k8s"
	"github.com/k8s-security-baseline-checker/pkg/security/redaction"
	"github.com/k8s-security-baseline-checker/pkg/types"
	"github.com/k8s-security-baseline-checker/pkg/validation"
	"github.com/sirupsen/logrus"
)

// Handler handles API requests
type Handler struct {
	engine     *checker.Engine
	registry   *benchmark.Registry
	reporter   *reporter.Generator
	logger     *logrus.Logger
	reports    map[string]*types.Report
	validator  *validation.Validator
	redactor   *redaction.Redactor
}

// NewHandler creates a new API handler
func NewHandler(engine *checker.Engine, registry *benchmark.Registry, reporter *reporter.Generator, logger *logrus.Logger) *Handler {
	return &Handler{
		engine:    engine,
		registry:  registry,
		reporter:  reporter,
		logger:    logger,
		reports:   make(map[string]*types.Report),
		validator: validation.NewValidator(),
		redactor:  redaction.NewRedactor(),
	}
}

// ListBenchmarks lists all available benchmarks
func (h *Handler) ListBenchmarks(c *gin.Context) {
	benchmarks := h.registry.List()
	
	benchmarkList := make([]gin.H, 0, len(benchmarks))
	for _, id := range benchmarks {
		bench, err := h.registry.Get(id)
		if err != nil {
			continue
		}
		benchmarkList = append(benchmarkList, gin.H{
			"id":          bench.ID,
			"name":        bench.Name,
			"version":     bench.Version,
			"framework":   bench.Framework,
			"description": bench.Description,
			"checks_count": len(bench.Checks),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"benchmarks": benchmarkList,
		"count":      len(benchmarkList),
	})
}

// GetBenchmark retrieves a specific benchmark
func (h *Handler) GetBenchmark(c *gin.Context) {
	id := c.Param("id")
	
	// Validate benchmark ID
	if err := h.validator.ValidateBenchmarkID(id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": errors.NewValidationError("invalid benchmark ID", err.Error()).UserMessage(),
		})
		return
	}

	bench, err := h.registry.Get(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": errors.NewExecutionError("benchmark not found", err).UserMessage(),
		})
		return
	}

	c.JSON(http.StatusOK, bench)
}

// RunK8sChecksRequest represents a request to run K8s checks
type RunK8sChecksRequest struct {
	BenchmarkID string   `json:"benchmark_id,omitempty"`
	Namespace   string   `json:"namespace,omitempty"`
	Namespaces  []string `json:"namespaces,omitempty"`
	Kubeconfig  string   `json:"kubeconfig,omitempty"`
	Parallel    bool     `json:"parallel,omitempty"`
	Format      string   `json:"format,omitempty"`
}

// RunK8sChecks runs Kubernetes security checks
func (h *Handler) RunK8sChecks(c *gin.Context) {
	var req RunK8sChecksRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": errors.NewValidationError("invalid request body", err.Error()).UserMessage(),
		})
		return
	}

	// Validate input fields
	validationErrors := h.validator.ValidateMultiple(map[string]interface{}{
		"benchmark_id":  req.BenchmarkID,
		"output_format": req.Format,
		"namespace":     req.Namespace,
	})
	if len(validationErrors) > 0 {
		errorMessages := make([]string, len(validationErrors))
		for i, err := range validationErrors {
			errorMessages[i] = err.Error()
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error": errors.NewValidationError("validation failed", errorMessages[0]).UserMessage(),
			"details": errorMessages,
		})
		return
	}

	// Validate namespace if provided
	if req.Namespace != "" {
		if err := h.validator.ValidateKubernetesNamespace(req.Namespace); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": errors.NewValidationError("invalid namespace", err.Error()).UserMessage(),
			})
			return
		}
	}

	// Validate kubeconfig path if provided
	if req.Kubeconfig != "" {
		if err := h.validator.ValidateFilePath(req.Kubeconfig); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": errors.NewValidationError("invalid kubeconfig path", err.Error()).UserMessage(),
			})
			return
		}
	}

	// Redact kubeconfig from logs
	redactedKubeconfig := h.redactor.RedactKubeconfig(req.Kubeconfig)
	h.logger.WithField("kubeconfig", redactedKubeconfig).Debug("Initializing Kubernetes client")

	// Initialize Kubernetes client
	k8sClient, err := k8s.NewClient(req.Kubeconfig)
	if err != nil {
		// Redact error message to prevent leaking sensitive info
		redactedErr := h.redactor.Redact(err.Error())
		h.logger.WithField("redacted_error", redactedErr).Error("Failed to create Kubernetes client")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": errors.NewExecutionError("failed to create Kubernetes client", nil).UserMessage(),
		})
		return
	}

	// Get cluster info
	clusterInfo := &types.ClusterInfo{
		K8sVersion: k8sClient.Config.Host,
		Provider:   "unknown",
	}

	// Load benchmark
	benchmarkID := req.BenchmarkID
	if benchmarkID == "" {
		benchmarkID = "cis"
	}

	// Validate benchmark ID before loading
	if err := h.validator.ValidateBenchmarkID(benchmarkID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": errors.NewValidationError("invalid benchmark ID", err.Error()).UserMessage(),
		})
		return
	}

	bench, err := h.registry.Get(benchmarkID)
	if err != nil {
		// Try loading by framework
		if err := h.registry.LoadFramework(benchmarkID); err == nil {
			benchmarks := h.registry.ListByFramework(benchmarkID)
			if len(benchmarks) > 0 {
				bench, err = h.registry.Get(benchmarks[0])
			}
		}
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": errors.NewExecutionError("failed to load benchmark", err).UserMessage(),
			})
			return
		}
	}

	// Register K8s checker
	k8sChecker, err := k8schecker.NewK8sChecker(k8sClient, h.logger)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to create K8s checker",
		})
		return
	}
	if err := h.engine.Register(k8sChecker); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to register K8s checker",
		})
		return
	}

	// Prepare options
	options := &checker.ExecutionOptions{
		ClusterInfo: clusterInfo,
		Logger:      h.logger,
		Config:     make(map[string]interface{}),
	}
	if req.Namespace != "" {
		options.Namespaces = []string{req.Namespace}
	} else if len(req.Namespaces) > 0 {
		options.Namespaces = req.Namespaces
	}

	parallel := req.Parallel
	if !parallel {
		parallel = true // Default to parallel
	}

	// Execute benchmark
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	report, err := h.engine.ExecuteBenchmark(ctx, *bench, options, parallel)
	if err != nil {
		// Redact error message
		redactedErr := h.redactor.Redact(err.Error())
		h.logger.WithError(err).WithField("redacted_error", redactedErr).Error("Failed to execute benchmark")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": errors.NewExecutionError("failed to execute benchmark", nil).UserMessage(),
		})
		return
	}

	// Store report
	h.reports[report.ID] = report

	// Generate report file if format specified
	if req.Format != "" {
		if report.Metadata == nil {
			report.Metadata = make(map[string]interface{})
		}
		err := h.reporter.Generate(report, req.Format, "")
		if err == nil {
			report.Metadata["format"] = req.Format
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"report_id":        report.ID,
		"compliance_score": report.ComplianceScore,
		"grade":            report.Grade,
		"total_checks":     report.TotalChecks,
		"passed_checks":   report.PassedChecks,
		"failed_checks":   report.FailedChecks,
		"warned_checks":    report.WarnedChecks,
		"generated_at":     report.GeneratedAt,
		"duration":         report.Duration.String(),
	})
}

// RunCloudChecks runs cloud provider security checks
func (h *Handler) RunCloudChecks(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "cloud checks not yet implemented",
	})
}

// RunAllChecks runs both K8s and cloud checks
func (h *Handler) RunAllChecks(c *gin.Context) {
	// For now, just run K8s checks
	h.RunK8sChecks(c)
}

// GetReport retrieves a report by ID
func (h *Handler) GetReport(c *gin.Context) {
	id := c.Param("id")
	report, exists := h.reports[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "report not found",
		})
		return
	}

	c.JSON(http.StatusOK, report)
}

// ListReports lists all reports
func (h *Handler) ListReports(c *gin.Context) {
	reportList := make([]gin.H, 0, len(h.reports))
	for id, report := range h.reports {
		reportList = append(reportList, gin.H{
			"id":              id,
			"compliance_score": report.ComplianceScore,
			"grade":            report.Grade,
			"total_checks":     report.TotalChecks,
			"passed_checks":   report.PassedChecks,
			"failed_checks":   report.FailedChecks,
			"generated_at":     report.GeneratedAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"reports": reportList,
		"count":   len(reportList),
	})
}

