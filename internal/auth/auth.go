package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Role represents a user role with specific permissions
type Role string

const (
	RoleViewer  Role = "viewer"  // Can view reports and benchmarks
	RoleOperator Role = "operator" // Can execute checks and view reports
	RoleAdmin   Role = "admin"   // Full access including configuration
)

// Permission represents a specific permission
type Permission string

const (
	PermissionViewBenchmarks  Permission = "benchmarks:view"
	PermissionExecuteChecks   Permission = "checks:execute"
	PermissionViewReports     Permission = "reports:view"
	PermissionManageConfig    Permission = "config:manage"
	PermissionManageUsers     Permission = "users:manage"
)

// RolePermissions maps roles to their permissions
var RolePermissions = map[Role][]Permission{
	RoleViewer: {
		PermissionViewBenchmarks,
		PermissionViewReports,
	},
	RoleOperator: {
		PermissionViewBenchmarks,
		PermissionExecuteChecks,
		PermissionViewReports,
	},
	RoleAdmin: {
		PermissionViewBenchmarks,
		PermissionExecuteChecks,
		PermissionViewReports,
		PermissionManageConfig,
		PermissionManageUsers,
	},
}

// Claims represents JWT claims
type Claims struct {
	UserID   string   `json:"user_id"`
	Username string   `json:"username"`
	Roles    []Role   `json:"roles"`
	jwt.RegisteredClaims
}

// Authenticator handles authentication and authorization
// Enterprise requirement: API authentication (JWT or API key) with role-based authorization
type Authenticator struct {
	jwtSecret     []byte
	apiKeys       map[string]*APIKey
	tokenExpiry   time.Duration
	issuer        string
}

// APIKey represents an API key with associated permissions
type APIKey struct {
	Key        string
	UserID     string
	Roles      []Role
	ExpiresAt  *time.Time
	CreatedAt  time.Time
}

// NewAuthenticator creates a new authenticator
func NewAuthenticator(jwtSecret string, tokenExpiry time.Duration) *Authenticator {
	return &Authenticator{
		jwtSecret:   []byte(jwtSecret),
		apiKeys:     make(map[string]*APIKey),
		tokenExpiry: tokenExpiry,
		issuer:      "k8s-security-checker",
	}
}

// GenerateToken generates a JWT token for a user
func (a *Authenticator) GenerateToken(userID, username string, roles []Role) (string, error) {
	now := time.Now()
	claims := &Claims{
		UserID:   userID,
		Username: username,
		Roles:    roles,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(a.tokenExpiry)),
			Issuer:    a.issuer,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(a.jwtSecret)
}

// ValidateToken validates a JWT token and returns claims
func (a *Authenticator) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return a.jwtSecret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	return claims, nil
}

// RegisterAPIKey registers a new API key
func (a *Authenticator) RegisterAPIKey(key string, userID string, roles []Role, expiresAt *time.Time) {
	a.apiKeys[key] = &APIKey{
		Key:       key,
		UserID:    userID,
		Roles:     roles,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}
}

// ValidateAPIKey validates an API key and returns associated user info
func (a *Authenticator) ValidateAPIKey(apiKey string) (*APIKey, error) {
	key, exists := a.apiKeys[apiKey]
	if !exists {
		return nil, errors.New("invalid API key")
	}

	if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
		return nil, errors.New("API key expired")
	}

	return key, nil
}

// HasPermission checks if a user has a specific permission
func (a *Authenticator) HasPermission(roles []Role, permission Permission) bool {
	for _, role := range roles {
		permissions, exists := RolePermissions[role]
		if !exists {
			continue
		}
		for _, p := range permissions {
			if p == permission {
				return true
			}
		}
	}
	return false
}

// RequirePermission checks if user has permission and returns error if not
func (a *Authenticator) RequirePermission(roles []Role, permission Permission) error {
	if !a.HasPermission(roles, permission) {
		return fmt.Errorf("permission denied: %s", permission)
	}
	return nil
}

// ExtractTokenFromHeader extracts token from Authorization header
func ExtractTokenFromHeader(authHeader string) (string, error) {
	if authHeader == "" {
		return "", errors.New("missing authorization header")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 {
		return "", errors.New("invalid authorization header format")
	}

	scheme := strings.ToLower(parts[0])
	token := parts[1]

	switch scheme {
	case "bearer":
		return token, nil
	case "apikey":
		return token, nil
	default:
		return "", fmt.Errorf("unsupported authorization scheme: %s", scheme)
	}
}

// ContextKey is a type for context keys
type ContextKey string

const (
	ContextKeyUserID   ContextKey = "user_id"
	ContextKeyUsername ContextKey = "username"
	ContextKeyRoles    ContextKey = "roles"
)

// GetUserFromContext extracts user information from context
func GetUserFromContext(ctx context.Context) (userID string, username string, roles []Role, ok bool) {
	userID, ok1 := ctx.Value(ContextKeyUserID).(string)
	username, ok2 := ctx.Value(ContextKeyUsername).(string)
	roles, ok3 := ctx.Value(ContextKeyRoles).([]Role)
	return userID, username, roles, ok1 && ok2 && ok3
}

// SetUserInContext sets user information in context
func SetUserInContext(ctx context.Context, userID, username string, roles []Role) context.Context {
	ctx = context.WithValue(ctx, ContextKeyUserID, userID)
	ctx = context.WithValue(ctx, ContextKeyUsername, username)
	ctx = context.WithValue(ctx, ContextKeyRoles, roles)
	return ctx
}
