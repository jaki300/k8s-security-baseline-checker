package errors

import (
	"fmt"
	"runtime"
)

// ErrorCode represents a standardized error code for error classification
type ErrorCode string

const (
	// ErrorCodeValidation indicates input validation failure
	ErrorCodeValidation ErrorCode = "VALIDATION_ERROR"
	// ErrorCodeAuthentication indicates authentication failure
	ErrorCodeAuthentication ErrorCode = "AUTHENTICATION_ERROR"
	// ErrorCodeAuthorization indicates authorization failure
	ErrorCodeAuthorization ErrorCode = "AUTHORIZATION_ERROR"
	// ErrorCodeExecution indicates check execution failure
	ErrorCodeExecution ErrorCode = "EXECUTION_ERROR"
	// ErrorCodeConfiguration indicates configuration error
	ErrorCodeConfiguration ErrorCode = "CONFIGURATION_ERROR"
	// ErrorCodeInternal indicates internal system error
	ErrorCodeInternal ErrorCode = "INTERNAL_ERROR"
	// ErrorCodeTimeout indicates operation timeout
	ErrorCodeTimeout ErrorCode = "TIMEOUT_ERROR"
	// ErrorCodeRateLimit indicates rate limit exceeded
	ErrorCodeRateLimit ErrorCode = "RATE_LIMIT_ERROR"
)

// ErrorSeverity represents the severity level of an error
type ErrorSeverity string

const (
	SeverityLow      ErrorSeverity = "LOW"
	SeverityMedium   ErrorSeverity = "MEDIUM"
	SeverityHigh     ErrorSeverity = "HIGH"
	SeverityCritical ErrorSeverity = "CRITICAL"
)

// AppError represents a standardized application error with enterprise features
// Enterprise requirement: Centralized error model with code, severity, and user-safe messages
type AppError struct {
	// Code is a standardized error code for programmatic handling
	Code ErrorCode

	// Severity indicates the severity level
	Severity ErrorSeverity

	// Message is a user-safe message that can be exposed to end users
	Message string

	// InternalMessage contains detailed internal information (not exposed to users)
	InternalMessage string

	// Cause is the underlying error (if any)
	Cause error

	// Stack trace for debugging (only in debug mode)
	StackTrace string
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.InternalMessage != "" {
		return fmt.Sprintf("[%s] %s: %s", e.Code, e.Message, e.InternalMessage)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Unwrap returns the underlying error for error unwrapping
func (e *AppError) Unwrap() error {
	return e.Cause
}

// NewAppError creates a new application error
func NewAppError(code ErrorCode, severity ErrorSeverity, message string, internalMessage string) *AppError {
	return &AppError{
		Code:            code,
		Severity:        severity,
		Message:         message,
		InternalMessage: internalMessage,
	}
}

// NewAppErrorWithCause creates a new application error with a cause
func NewAppErrorWithCause(code ErrorCode, severity ErrorSeverity, message string, cause error) *AppError {
	return &AppError{
		Code:     code,
		Severity: severity,
		Message:  message,
		Cause:    cause,
	}
}

// WithStackTrace adds stack trace to the error (for debugging)
func (e *AppError) WithStackTrace() *AppError {
	buf := make([]byte, 4096)
	n := runtime.Stack(buf, false)
	e.StackTrace = string(buf[:n])
	return e
}

// UserMessage returns a user-safe error message
func (e *AppError) UserMessage() string {
	return e.Message
}

// InternalDetails returns internal error details (for logging)
func (e *AppError) InternalDetails() string {
	if e.InternalMessage != "" {
		return e.InternalMessage
	}
	if e.Cause != nil {
		return e.Cause.Error()
	}
	return ""
}

// Helper functions for common error types

// NewValidationError creates a validation error
func NewValidationError(message string, internalMessage string) *AppError {
	return NewAppError(ErrorCodeValidation, SeverityMedium, message, internalMessage)
}

// NewAuthenticationError creates an authentication error
func NewAuthenticationError(message string) *AppError {
	return NewAppError(ErrorCodeAuthentication, SeverityHigh, message, "")
}

// NewAuthorizationError creates an authorization error
func NewAuthorizationError(message string) *AppError {
	return NewAppError(ErrorCodeAuthorization, SeverityHigh, message, "")
}

// NewExecutionError creates an execution error
func NewExecutionError(message string, cause error) *AppError {
	return NewAppErrorWithCause(ErrorCodeExecution, SeverityHigh, message, cause)
}

// NewConfigurationError creates a configuration error
func NewConfigurationError(message string, internalMessage string) *AppError {
	return NewAppError(ErrorCodeConfiguration, SeverityMedium, message, internalMessage)
}

// NewInternalError creates an internal error
func NewInternalError(message string, cause error) *AppError {
	return NewAppErrorWithCause(ErrorCodeInternal, SeverityCritical, message, cause)
}

// NewTimeoutError creates a timeout error
func NewTimeoutError(message string) *AppError {
	return NewAppError(ErrorCodeTimeout, SeverityHigh, message, "")
}

// NewRateLimitError creates a rate limit error
func NewRateLimitError(message string) *AppError {
	return NewAppError(ErrorCodeRateLimit, SeverityMedium, message, "")
}

// RecoverPanic recovers from a panic and converts it to an AppError
// Enterprise requirement: Panic recovery for API and execution engine
func RecoverPanic(r interface{}) *AppError {
	if r == nil {
		return nil
	}

	var err error
	switch v := r.(type) {
	case error:
		err = v
	case string:
		err = fmt.Errorf("panic: %s", v)
	default:
		err = fmt.Errorf("panic: %v", v)
	}

	return NewInternalError("An unexpected error occurred", err).WithStackTrace()
}
