package redaction

import (
	"testing"
)

func TestRedact(t *testing.T) {
	redactor := NewRedactor()

	tests := []struct {
		name     string
		input    string
		contains []string // Strings that should NOT be in output
	}{
		{
			name:     "JWT token",
			input:    "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			contains: []string{"REDACTED_JWT"},
		},
		{
			name:     "API key",
			input:    "api_key: sk_live_1234567890abcdef",
			contains: []string{"REDACTED_API_KEY"},
		},
		{
			name:     "Secret",
			input:    "password: mySecretPassword123",
			contains: []string{"REDACTED_SECRET"},
		},
		{
			name:     "Certificate",
			input:    "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END CERTIFICATE-----",
			contains: []string{"REDACTED_CERTIFICATE"},
		},
		{
			name:     "AWS access key",
			input:    "AKIAIOSFODNN7EXAMPLE",
			contains: []string{"REDACTED_AWS_KEY"},
		},
		{
			name:     "Private IP",
			input:    "Server at 192.168.1.1",
			contains: []string{"REDACTED_IP"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := redactor.Redact(tt.input)
			
			// Check that sensitive data is redacted
			for _, sensitive := range tt.contains {
				if !contains(result, sensitive) {
					t.Errorf("Redact() should contain %s, got: %s", sensitive, result)
				}
			}

			// Check that original sensitive data is NOT in output
			if contains(result, tt.input) && len(tt.input) > 20 {
				t.Errorf("Redact() should not contain original input")
			}
		})
	}
}

func TestRedactKubeconfig(t *testing.T) {
	redactor := NewRedactor()

	kubeconfig := `
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTi...
    server: https://kubernetes.example.com
  name: my-cluster
users:
- name: my-user
  user:
    client-certificate-data: LS0tLS1CRUdJTi...
    client-key-data: LS0tLS1CRUdJTi...
    token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
`

	result := redactor.RedactKubeconfig(kubeconfig)

	// Should redact certificate data and tokens
	if contains(result, "certificate-authority-data: LS0t") {
		t.Error("RedactKubeconfig() should redact certificate-authority-data")
	}
	if contains(result, "client-certificate-data: LS0t") {
		t.Error("RedactKubeconfig() should redact client-certificate-data")
	}
	if contains(result, "token: eyJ") {
		t.Error("RedactKubeconfig() should redact token")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || 
		(len(s) > len(substr) && (s[:len(substr)] == substr || 
		s[len(s)-len(substr):] == substr || 
		containsHelper(s, substr))))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
