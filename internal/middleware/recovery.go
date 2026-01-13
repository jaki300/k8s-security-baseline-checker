package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/k8s-security-baseline-checker/pkg/errors"
	"github.com/sirupsen/logrus"
)

// RecoveryMiddleware provides panic recovery for API endpoints
// Enterprise requirement: Add panic recovery for API and execution engine
func RecoveryMiddleware(logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				// Convert panic to AppError
				appErr := errors.RecoverPanic(r)

				// Log the error with stack trace
				logger.WithFields(logrus.Fields{
					"error_code":    appErr.Code,
					"severity":      appErr.Severity,
					"internal_msg":  appErr.InternalDetails(),
					"stack_trace":   appErr.StackTrace,
					"path":          c.Request.URL.Path,
					"method":        c.Request.Method,
				}).Error("Panic recovered")

				// Return user-safe error message
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": appErr.UserMessage(),
				})
				c.Abort()
			}
		}()

		c.Next()
	}
}
