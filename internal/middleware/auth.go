package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/k8s-security-baseline-checker/internal/auth"
	"github.com/k8s-security-baseline-checker/pkg/errors"
)

// AuthMiddleware creates authentication middleware for Gin
// Enterprise requirement: Ensure every API endpoint enforces auth
func AuthMiddleware(authenticator *auth.Authenticator) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": errors.NewAuthenticationError("authentication required").UserMessage(),
			})
			c.Abort()
			return
		}

		token, err := auth.ExtractTokenFromHeader(authHeader)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": errors.NewAuthenticationError("invalid authorization header").UserMessage(),
			})
			c.Abort()
			return
		}

		// Try JWT token first
		claims, jwtErr := authenticator.ValidateToken(token)
		if jwtErr == nil {
			c.Set("user_id", claims.UserID)
			c.Set("username", claims.Username)
			c.Set("roles", claims.Roles)
			c.Next()
			return
		}

		// Try API key
		apiKey, apiKeyErr := authenticator.ValidateAPIKey(token)
		if apiKeyErr == nil {
			c.Set("user_id", apiKey.UserID)
			c.Set("username", apiKey.UserID) // Use UserID as username for API keys
			c.Set("roles", apiKey.Roles)
			c.Next()
			return
		}

		// Both failed
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": errors.NewAuthenticationError("invalid or expired token").UserMessage(),
		})
		c.Abort()
	}
}

// RequirePermission creates authorization middleware that checks for specific permission
func RequirePermission(authenticator *auth.Authenticator, permission auth.Permission) gin.HandlerFunc {
	return func(c *gin.Context) {
		rolesInterface, exists := c.Get("roles")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{
				"error": errors.NewAuthorizationError("roles not found in context").UserMessage(),
			})
			c.Abort()
			return
		}

		roles, ok := rolesInterface.([]auth.Role)
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{
				"error": errors.NewAuthorizationError("invalid roles in context").UserMessage(),
			})
			c.Abort()
			return
		}

		if err := authenticator.RequirePermission(roles, permission); err != nil {
			c.JSON(http.StatusForbidden, gin.H{
				"error": errors.NewAuthorizationError(err.Error()).UserMessage(),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireRole creates authorization middleware that checks for specific role
func RequireRole(authenticator *auth.Authenticator, requiredRole auth.Role) gin.HandlerFunc {
	return func(c *gin.Context) {
		rolesInterface, exists := c.Get("roles")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{
				"error": errors.NewAuthorizationError("roles not found in context").UserMessage(),
			})
			c.Abort()
			return
		}

		roles, ok := rolesInterface.([]auth.Role)
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{
				"error": errors.NewAuthorizationError("invalid roles in context").UserMessage(),
			})
			c.Abort()
			return
		}

		hasRole := false
		for _, role := range roles {
			if role == requiredRole {
				hasRole = true
				break
			}
		}

		if !hasRole {
			c.JSON(http.StatusForbidden, gin.H{
				"error": errors.NewAuthorizationError("insufficient permissions").UserMessage(),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// GetUserRoles extracts user roles from context
func GetUserRoles(c *gin.Context) []auth.Role {
	rolesInterface, exists := c.Get("roles")
	if !exists {
		return nil
	}

	roles, ok := rolesInterface.([]auth.Role)
	if !ok {
		return nil
	}

	return roles
}

// GetUserID extracts user ID from context
func GetUserID(c *gin.Context) string {
	userID, exists := c.Get("user_id")
	if !exists {
		return ""
	}

	id, ok := userID.(string)
	if !ok {
		return ""
	}

	return id
}
