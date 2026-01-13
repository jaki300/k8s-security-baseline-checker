package core

import (
	"context"
	"time"
)

// Checker is the core interface that all security checks must implement
// This enables a plugin-based architecture where checks can be added dynamically
type Checker interface {
	// ID returns the unique identifier for this checker
	ID() string

	// Name returns the human-readable name of the check
	Name() string

	// Description returns a detailed description of what the check does
	Description() string

	// Execute runs the check and returns evidence-based results
	Execute(ctx context.Context, target CheckTarget) (*CheckResult, error)

	// Validate checks if this checker can handle the given target
	Validate(target CheckTarget) bool

	// Metadata returns additional metadata about the check
	Metadata() CheckMetadata
}

// CheckTarget represents what is being checked (pod, namespace, cluster, etc.)
type CheckTarget interface {
	// Type returns the type of target (pod, namespace, cluster, etc.)
	Type() string

	// ID returns a unique identifier for this target
	ID() string

	// Data returns the raw data for the target (for evidence collection)
	Data() map[string]interface{}
}

// CheckResult represents the result of executing a check with evidence
type CheckResult struct {
	// CheckID is the identifier of the check that was executed
	CheckID string

	// Status is the overall status (PASS, FAIL, WARN, ERROR, SKIP)
	Status CheckStatus

	// Severity indicates the severity level if the check failed
	Severity SeverityLevel

	// Evidence contains detailed evidence supporting the result
	Evidence []Evidence

	// Findings contains specific issues found (if any)
	Findings []Finding

	// Message provides a human-readable summary
	Message string

	// Timestamp when the check was executed
	Timestamp time.Time

	// Duration how long the check took to execute
	Duration time.Duration

	// Metadata contains additional context
	Metadata map[string]interface{}
}

// Evidence represents concrete evidence supporting a check result
type Evidence struct {
	// Type is the type of evidence (resource, config, log, etc.)
	Type EvidenceType

	// Source identifies where the evidence came from
	Source string

	// Content contains the actual evidence data
	Content map[string]interface{}

	// Description explains what this evidence shows
	Description string

	// Timestamp when the evidence was collected
	Timestamp time.Time
}

// Finding represents a specific security issue found
type Finding struct {
	// ID is a unique identifier for this finding
	ID string

	// Title is a short title describing the issue
	Title string

	// Description provides detailed information about the finding
	Description string

	// Severity indicates how severe this finding is
	Severity SeverityLevel

	// Resource identifies the resource where the issue was found
	Resource string

	// Remediation provides guidance on how to fix the issue
	Remediation string

	// Evidence references evidence supporting this finding
	Evidence []Evidence
}

// CheckMetadata contains metadata about a check
type CheckMetadata struct {
	// Category is the security category (e.g., "Pod Security", "RBAC")
	Category string

	// Tags are additional tags for categorization
	Tags []string

	// References contains links to relevant documentation
	References []string

	// CISControl is the CIS control ID if applicable
	CISControl string

	// Version is the version of the check definition
	Version string
}

// ComplianceMapper maps check results to compliance framework controls
type ComplianceMapper interface {
	// Framework returns the compliance framework name (NIST, ISO27001, SOC2, etc.)
	Framework() string

	// Version returns the framework version
	Version() string

	// Map maps a check result to compliance controls
	Map(result *CheckResult) []ComplianceControl

	// GetControls returns all controls for this framework
	GetControls() []ComplianceControl
}

// ComplianceControl represents a control from a compliance framework
type ComplianceControl struct {
	// ID is the control identifier (e.g., "AC-3" for NIST, "A.9.2.1" for ISO27001)
	ID string

	// Name is the control name
	Name string

	// Description provides details about the control
	Description string

	// Category is the control category
	Category string

	// CheckResults contains the check results that map to this control
	CheckResults []*CheckResult

	// Status is the compliance status for this control
	Status ComplianceStatus

	// Evidence contains evidence supporting the compliance status
	Evidence []Evidence
}

// ReportGenerator generates compliance reports
type ReportGenerator interface {
	// Generate creates a report from check results and compliance mappings
	Generate(ctx context.Context, results []*CheckResult, mappings map[string][]ComplianceControl, format ReportFormat) ([]byte, error)

	// SupportedFormats returns the formats this generator supports
	SupportedFormats() []ReportFormat
}

// PluginRegistry manages registered checkers and compliance mappers
type PluginRegistry interface {
	// RegisterChecker registers a new checker plugin
	RegisterChecker(checker Checker) error

	// RegisterComplianceMapper registers a new compliance mapper
	RegisterComplianceMapper(mapper ComplianceMapper) error

	// GetChecker retrieves a checker by ID
	GetChecker(id string) (Checker, error)

	// GetComplianceMapper retrieves a compliance mapper by framework
	GetComplianceMapper(framework string) (ComplianceMapper, error)

	// ListCheckers returns all registered checkers
	ListCheckers() []Checker

	// ListComplianceMappers returns all registered compliance mappers
	ListComplianceMappers() []ComplianceMapper
}

// Types and Enums

type CheckStatus string

const (
	StatusPass  CheckStatus = "PASS"
	StatusFail  CheckStatus = "FAIL"
	StatusWarn  CheckStatus = "WARN"
	StatusError CheckStatus = "ERROR"
	StatusSkip  CheckStatus = "SKIP"
)

type SeverityLevel string

const (
	SeverityCritical SeverityLevel = "CRITICAL"
	SeverityHigh     SeverityLevel = "HIGH"
	SeverityMedium   SeverityLevel = "MEDIUM"
	SeverityLow      SeverityLevel = "LOW"
	SeverityInfo     SeverityLevel = "INFO"
)

type EvidenceType string

const (
	EvidenceTypeResource EvidenceType = "resource"
	EvidenceTypeConfig   EvidenceType = "config"
	EvidenceTypeLog      EvidenceType = "log"
	EvidenceTypeQuery    EvidenceType = "query"
	EvidenceTypeScan     EvidenceType = "scan"
)

type ComplianceStatus string

const (
	ComplianceStatusCompliant    ComplianceStatus = "COMPLIANT"
	ComplianceStatusNonCompliant ComplianceStatus = "NON_COMPLIANT"
	ComplianceStatusPartial      ComplianceStatus = "PARTIAL"
	ComplianceStatusNotApplicable ComplianceStatus = "NOT_APPLICABLE"
)

type ReportFormat string

const (
	ReportFormatJSON ReportFormat = "json"
	ReportFormatHTML ReportFormat = "html"
	ReportFormatPDF  ReportFormat = "pdf"
	ReportFormatCSV  ReportFormat = "csv"
	ReportFormatXLSX ReportFormat = "xlsx"
)
