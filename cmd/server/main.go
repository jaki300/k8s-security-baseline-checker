package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/k8s-security-baseline-checker/internal/api"
	"github.com/k8s-security-baseline-checker/internal/auth"
	"github.com/k8s-security-baseline-checker/internal/benchmark"
	"github.com/k8s-security-baseline-checker/internal/checker"
	"github.com/k8s-security-baseline-checker/internal/middleware"
	"github.com/k8s-security-baseline-checker/internal/reporter"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	serverPort    int
	serverAddress string
	authEnabled   bool
	authType      string
)

var rootCmd = &cobra.Command{
	Use:   "k8s-checker-server",
	Short: "Kubernetes Security Checker API Server",
	Long:  "REST API server for Kubernetes security benchmarking",
	RunE:  runServer,
}

func init() {
	rootCmd.Flags().IntVarP(&serverPort, "port", "p", 8080, "server port")
	rootCmd.Flags().StringVar(&serverAddress, "address", "0.0.0.0", "server address")
	rootCmd.Flags().BoolVar(&authEnabled, "auth", false, "enable authentication")
	rootCmd.Flags().StringVar(&authType, "auth-type", "jwt", "authentication type (jwt, oidc, api-key)")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runServer(cmd *cobra.Command, args []string) error {
	// Initialize config
	initConfig()

	// Setup logger
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	if viper.GetBool("debug") {
		logger.SetLevel(logrus.DebugLevel)
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// Initialize components
	benchmarkDir := viper.GetString("benchmark_dir")
	if benchmarkDir == "" {
		benchmarkDir = filepath.Join(".", "benchmarks")
	}
	registry := benchmark.NewRegistry(benchmarkDir)
	if err := registry.LoadAll(); err != nil {
		logger.Warnf("Failed to load all benchmarks: %v", err)
	}

	// Enterprise requirement: Validate compliance mappings at startup
	// Note: This would require loading mapping engine - for now, log that validation should be done
	logger.Info("Compliance mapping validation should be performed after mappings are loaded")

	outputDir := viper.GetString("output_dir")
	if outputDir == "" {
		outputDir = "."
	}
	reporter := reporter.NewGenerator(outputDir)

	// Initialize checker engine
	engine := checker.NewEngine(logger)

	// Setup API handlers
	apiHandler := api.NewHandler(engine, registry, reporter, logger)

	// Initialize authentication (Enterprise requirement: API authentication)
	jwtSecret := viper.GetString("auth.jwt_secret")
	if jwtSecret == "" {
		jwtSecret = "change-me-in-production" // Default for development
		logger.Warn("Using default JWT secret - change in production!")
	}
	tokenExpiry := viper.GetDuration("auth.token_expiry")
	if tokenExpiry == 0 {
		tokenExpiry = 24 * time.Hour // Default 24 hours
	}
	authenticator := auth.NewAuthenticator(jwtSecret, tokenExpiry)

	// Register default API keys if configured (for testing/development)
	if apiKeys := viper.GetStringMapString("auth.api_keys"); len(apiKeys) > 0 {
		for key, userID := range apiKeys {
			roles := []auth.Role{auth.RoleOperator} // Default role
			if roleStr := viper.GetString(fmt.Sprintf("auth.api_key_roles.%s", key)); roleStr != "" {
				roles = []auth.Role{auth.Role(roleStr)}
			}
			authenticator.RegisterAPIKey(key, userID, roles, nil)
		}
	}

	// Initialize rate limiter (Enterprise requirement: API rate limiting)
	rateLimitRPS := viper.GetInt("rate_limit.rps")
	if rateLimitRPS == 0 {
		rateLimitRPS = 100 // Default 100 requests per second
	}
	rateLimitBurst := viper.GetInt("rate_limit.burst")
	if rateLimitBurst == 0 {
		rateLimitBurst = 200 // Default burst of 200
	}
	rateLimiter := middleware.NewRateLimiter(rateLimitRPS, rateLimitBurst, 5*time.Minute)

	// Setup router with enterprise middleware
	router := gin.New()
	
	// Enterprise requirement: Panic recovery for API
	router.Use(middleware.RecoveryMiddleware(logger))
	
	// Standard Gin middleware
	router.Use(gin.Logger())
	
	// Enterprise requirement: Rate limiting
	router.Use(middleware.RateLimitMiddleware(rateLimiter))

	// Health check (no auth required)
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "k8s-security-checker",
		})
	})

	// API routes with authentication
	v1 := router.Group("/api/v1")
	
	// Enterprise requirement: Ensure every API endpoint enforces auth
	if authEnabled {
		v1.Use(middleware.AuthMiddleware(authenticator))
		logger.Info("Authentication enabled for API endpoints")
	} else {
		logger.Warn("Authentication DISABLED - not recommended for production!")
	}

	{
		// Benchmark endpoints - require viewer permission
		benchmarks := v1.Group("/benchmarks")
		if authEnabled {
			benchmarks.Use(middleware.RequirePermission(authenticator, auth.PermissionViewBenchmarks))
		}
		{
			benchmarks.GET("", apiHandler.ListBenchmarks)
			benchmarks.GET("/:id", apiHandler.GetBenchmark)
		}

		// Check endpoints - require operator permission
		checks := v1.Group("/checks")
		if authEnabled {
			checks.Use(middleware.RequirePermission(authenticator, auth.PermissionExecuteChecks))
		}
		{
			checks.POST("/k8s", apiHandler.RunK8sChecks)
			checks.POST("/cloud", apiHandler.RunCloudChecks)
			checks.POST("/all", apiHandler.RunAllChecks)
		}

		// Report endpoints - require viewer permission
		reports := v1.Group("/reports")
		if authEnabled {
			reports.Use(middleware.RequirePermission(authenticator, auth.PermissionViewReports))
		}
		{
			reports.GET("/:id", apiHandler.GetReport)
			reports.GET("", apiHandler.ListReports)
		}
	}

	// Start server
	addr := fmt.Sprintf("%s:%d", serverAddress, serverPort)
	logger.Infof("Starting API server on %s", addr)
	return router.Run(addr)
}

func initConfig() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("/etc/k8s-checker")
	viper.AutomaticEnv()
	viper.ReadInConfig()
}
