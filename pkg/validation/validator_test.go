package validation

import (
	"testing"
)

func TestValidateBenchmarkID(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid CIS", "cis", false},
		{"valid NIST", "nist", false},
		{"valid ISO", "iso-27001", false},
		{"valid SOC2", "soc2", false},
		{"empty", "", true},
		{"invalid", "invalid-benchmark", true},
		{"case insensitive", "CIS", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateBenchmarkID(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateBenchmarkID(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateFramework(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid CIS", "cis", false},
		{"valid NIST", "nist", false},
		{"empty", "", true},
		{"invalid", "invalid-framework", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateFramework(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFramework(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateOutputFormat(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid JSON", "json", false},
		{"valid HTML", "html", false},
		{"valid CSV", "csv", false},
		{"valid PDF", "pdf", false},
		{"empty", "", true},
		{"invalid", "invalid-format", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateOutputFormat(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateOutputFormat(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateFilePath(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid relative", "./report.json", false},
		{"valid relative 2", "report.json", false},
		{"path traversal", "../../etc/passwd", true},
		{"path traversal 2", "../secret", true},
		{"null byte", "file\x00name", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateFilePath(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFilePath(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateKubernetesNamespace(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid namespace", "production", false},
		{"valid with dash", "my-namespace", false},
		{"valid with numbers", "ns123", false},
		{"empty (valid)", "", false},
		{"too long", "a1234567890123456789012345678901234567890123456789012345678901234", true},
		{"invalid uppercase", "Production", true},
		{"invalid underscore", "my_namespace", true},
		{"invalid start", "-namespace", true},
		{"invalid end", "namespace-", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateKubernetesNamespace(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateKubernetesNamespace(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}
