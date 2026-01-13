package auth

import (
	"testing"
	"time"
)

func TestAuthenticator_GenerateToken(t *testing.T) {
	authenticator := NewAuthenticator("test-secret", 1*time.Hour)

	token, err := authenticator.GenerateToken("user123", "testuser", []Role{RoleOperator})
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	if token == "" {
		t.Error("GenerateToken() returned empty token")
	}
}

func TestAuthenticator_ValidateToken(t *testing.T) {
	authenticator := NewAuthenticator("test-secret", 1*time.Hour)

	// Generate token
	token, err := authenticator.GenerateToken("user123", "testuser", []Role{RoleOperator})
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	// Validate token
	claims, err := authenticator.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	if claims.UserID != "user123" {
		t.Errorf("ValidateToken() UserID = %v, want user123", claims.UserID)
	}

	if claims.Username != "testuser" {
		t.Errorf("ValidateToken() Username = %v, want testuser", claims.Username)
	}

	if len(claims.Roles) != 1 || claims.Roles[0] != RoleOperator {
		t.Errorf("ValidateToken() Roles = %v, want [operator]", claims.Roles)
	}
}

func TestAuthenticator_HasPermission(t *testing.T) {
	authenticator := NewAuthenticator("test-secret", 1*time.Hour)

	tests := []struct {
		name       string
		roles      []Role
		permission Permission
		want       bool
	}{
		{"viewer can view benchmarks", []Role{RoleViewer}, PermissionViewBenchmarks, true},
		{"viewer cannot execute checks", []Role{RoleViewer}, PermissionExecuteChecks, false},
		{"operator can execute checks", []Role{RoleOperator}, PermissionExecuteChecks, true},
		{"operator can view reports", []Role{RoleOperator}, PermissionViewReports, true},
		{"admin can manage config", []Role{RoleAdmin}, PermissionManageConfig, true},
		{"admin can manage users", []Role{RoleAdmin}, PermissionManageUsers, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := authenticator.HasPermission(tt.roles, tt.permission)
			if got != tt.want {
				t.Errorf("HasPermission() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthenticator_ValidateAPIKey(t *testing.T) {
	authenticator := NewAuthenticator("test-secret", 1*time.Hour)

	// Register API key
	apiKey := "test-api-key-123"
	authenticator.RegisterAPIKey(apiKey, "user456", []Role{RoleOperator}, nil)

	// Validate API key
	key, err := authenticator.ValidateAPIKey(apiKey)
	if err != nil {
		t.Fatalf("ValidateAPIKey() error = %v", err)
	}

	if key.UserID != "user456" {
		t.Errorf("ValidateAPIKey() UserID = %v, want user456", key.UserID)
	}

	// Test invalid API key
	_, err = authenticator.ValidateAPIKey("invalid-key")
	if err == nil {
		t.Error("ValidateAPIKey() should return error for invalid key")
	}
}
