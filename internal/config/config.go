package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

// Config represents the application configuration
type Config struct {
	Kubeconfig    string            `mapstructure:"kubeconfig"`
	BenchmarkDir  string            `mapstructure:"benchmark_dir"`
	OutputDir     string            `mapstructure:"output_dir"`
	Clusters      []ClusterConfig   `mapstructure:"clusters"`
	Cloud         CloudConfig       `mapstructure:"cloud"`
	Server        ServerConfig      `mapstructure:"server"`
	Database      DatabaseConfig     `mapstructure:"database"`
	Auth          AuthConfig         `mapstructure:"auth"`
	Alerting      AlertingConfig    `mapstructure:"alerting"`
	Schedule      ScheduleConfig    `mapstructure:"schedule"`
}

// ClusterConfig represents a Kubernetes cluster configuration
type ClusterConfig struct {
	Name       string            `mapstructure:"name"`
	Kubeconfig string            `mapstructure:"kubeconfig"`
	Context    string            `mapstructure:"context"`
	Metadata   map[string]string `mapstructure:"metadata"`
}

// CloudConfig represents cloud provider configuration
type CloudConfig struct {
	AWS   AWSConfig   `mapstructure:"aws"`
	Azure AzureConfig `mapstructure:"azure"`
	GCP   GCPConfig   `mapstructure:"gcp"`
}

// AWSConfig represents AWS configuration
type AWSConfig struct {
	Region  string `mapstructure:"region"`
	Profile string `mapstructure:"profile"`
}

// AzureConfig represents Azure configuration
type AzureConfig struct {
	SubscriptionID string `mapstructure:"subscription_id"`
	TenantID       string `mapstructure:"tenant_id"`
}

// GCPConfig represents GCP configuration
type GCPConfig struct {
	ProjectID string `mapstructure:"project_id"`
	Region    string `mapstructure:"region"`
}

// ServerConfig represents API server configuration
type ServerConfig struct {
	Port    int    `mapstructure:"port"`
	Address string `mapstructure:"address"`
	Debug   bool   `mapstructure:"debug"`
}

// DatabaseConfig represents database configuration
type DatabaseConfig struct {
	Type     string `mapstructure:"type"` // postgres, mysql, sqlite
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Database string `mapstructure:"database"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	DSN      string `mapstructure:"dsn"` // Direct connection string
}

// AuthConfig represents authentication configuration
type AuthConfig struct {
	Enabled bool      `mapstructure:"enabled"`
	Type    string    `mapstructure:"type"` // jwt, oidc, ldap, api-key
	JWT     JWTConfig `mapstructure:"jwt"`
	OIDC    OIDCConfig `mapstructure:"oidc"`
	LDAP    LDAPConfig `mapstructure:"ldap"`
}

// JWTConfig represents JWT configuration
type JWTConfig struct {
	Secret     string `mapstructure:"secret"`
	Expiration int    `mapstructure:"expiration"` // in hours
}

// OIDCConfig represents OIDC configuration
type OIDCConfig struct {
	Issuer       string `mapstructure:"issuer"`
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
}

// LDAPConfig represents LDAP configuration
type LDAPConfig struct {
	Server   string `mapstructure:"server"`
	BaseDN   string `mapstructure:"base_dn"`
	BindDN   string `mapstructure:"bind_dn"`
	BindPass string `mapstructure:"bind_password"`
}

// AlertingConfig represents alerting configuration
type AlertingConfig struct {
	Webhooks []WebhookConfig `mapstructure:"webhooks"`
	Email    EmailConfig     `mapstructure:"email"`
}

// WebhookConfig represents webhook configuration
type WebhookConfig struct {
	URL     string            `mapstructure:"url"`
	Headers map[string]string `mapstructure:"headers"`
}

// EmailConfig represents email configuration
type EmailConfig struct {
	Enabled  bool     `mapstructure:"enabled"`
	SMTPHost string   `mapstructure:"smtp_host"`
	SMTPPort int      `mapstructure:"smtp_port"`
	From     string   `mapstructure:"from"`
	To       []string `mapstructure:"to"`
}

// ScheduleConfig represents scheduling configuration
type ScheduleConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Cron    string `mapstructure:"cron"`
}

// Load loads configuration from file or environment
func Load(configPath string) (*Config, error) {
	viper.SetConfigType("yaml")
	
	if configPath != "" {
		viper.SetConfigFile(configPath)
	} else {
		// Default locations
		home, _ := os.UserHomeDir()
		viper.AddConfigPath(".")
		viper.AddConfigPath(home)
		viper.AddConfigPath("/etc/k8s-checker")
		viper.SetConfigName("config")
	}

	// Environment variables
	viper.SetEnvPrefix("K8S_CHECKER")
	viper.AutomaticEnv()

	// Defaults
	setDefaults()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config: %w", err)
		}
		// Config file not found is OK, use defaults
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Set defaults if not set
	if config.BenchmarkDir == "" {
		config.BenchmarkDir = filepath.Join(".", "benchmarks")
	}
	if config.OutputDir == "" {
		config.OutputDir = "."
	}

	return &config, nil
}

func setDefaults() {
	viper.SetDefault("benchmark_dir", "./benchmarks")
	viper.SetDefault("output_dir", ".")
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.address", "0.0.0.0")
	viper.SetDefault("server.debug", false)
	viper.SetDefault("database.type", "sqlite")
	viper.SetDefault("auth.enabled", false)
	viper.SetDefault("auth.type", "jwt")
	viper.SetDefault("schedule.enabled", false)
}

