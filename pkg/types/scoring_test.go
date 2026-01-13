package types

import (
	"testing"
)

// TestCalculateComplianceScore tests the deterministic scoring logic
// Enterprise requirement: Make scoring deterministic and handle PASS/FAIL/WARN/NOT_APPLICABLE explicitly
func TestCalculateComplianceScore(t *testing.T) {
	tests := []struct {
		name     string
		results  []Result
		expected int
	}{
		{
			name:     "empty results",
			results:  []Result{},
			expected: 0,
		},
		{
			name: "all pass",
			results: []Result{
				{Status: StatusPass, Weight: 1},
				{Status: StatusPass, Weight: 1},
				{Status: StatusPass, Weight: 1},
			},
			expected: 100,
		},
		{
			name: "all fail",
			results: []Result{
				{Status: StatusFail, Weight: 1},
				{Status: StatusFail, Weight: 1},
			},
			expected: 0,
		},
		{
			name: "half pass half fail",
			results: []Result{
				{Status: StatusPass, Weight: 1},
				{Status: StatusFail, Weight: 1},
			},
			expected: 50,
		},
		{
			name: "warn counts as half",
			results: []Result{
				{Status: StatusPass, Weight: 1},
				{Status: StatusWarn, Weight: 1},
				{Status: StatusFail, Weight: 1},
			},
			expected: 50, // (1 + 0.5) / 3 * 100 = 50
		},
		{
			name: "skip excluded",
			results: []Result{
				{Status: StatusPass, Weight: 1},
				{Status: StatusSkip, Weight: 1}, // Should be excluded
				{Status: StatusFail, Weight: 1},
			},
			expected: 50, // 1 / 2 * 100 = 50
		},
		{
			name: "error treated as fail",
			results: []Result{
				{Status: StatusPass, Weight: 1},
				{Status: StatusError, Weight: 1},
			},
			expected: 50,
		},
		{
			name: "weighted scoring",
			results: []Result{
				{Status: StatusPass, Weight: 2},
				{Status: StatusFail, Weight: 1},
			},
			expected: 66, // (2) / 3 * 100 = 66
		},
		{
			name: "zero weight defaults to 1",
			results: []Result{
				{Status: StatusPass, Weight: 0}, // Should default to 1
				{Status: StatusFail, Weight: 0}, // Should default to 1
			},
			expected: 50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := CalculateComplianceScore(tt.results)
			if score != tt.expected {
				t.Errorf("CalculateComplianceScore() = %d, want %d", score, tt.expected)
			}
		})
	}
}

func TestCalculateGrade(t *testing.T) {
	tests := []struct {
		score    int
		expected string
	}{
		{100, "A+"},
		{95, "A+"},
		{90, "A+"},
		{89, "A"},
		{85, "A"},
		{80, "A"},
		{79, "B"},
		{75, "B"},
		{70, "B"},
		{69, "C"},
		{65, "C"},
		{60, "C"},
		{59, "D"},
		{50, "D"},
		{49, "F"},
		{0, "F"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			grade := CalculateGrade(tt.score)
			if grade != tt.expected {
				t.Errorf("CalculateGrade(%d) = %s, want %s", tt.score, grade, tt.expected)
			}
		})
	}
}
