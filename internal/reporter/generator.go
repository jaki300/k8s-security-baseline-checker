package reporter

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/k8s-security-baseline-checker/pkg/types"
)

// Generator handles report generation in various formats
type Generator struct {
	outputDir string
}

// NewGenerator creates a new report generator
func NewGenerator(outputDir string) *Generator {
	return &Generator{
		outputDir: outputDir,
	}
}

// Generate generates a report in the specified format
func (g *Generator) Generate(report *types.Report, format string, outputPath string) error {
	switch strings.ToLower(format) {
	case "json":
		return g.GenerateJSON(report, outputPath)
	case "html":
		return g.GenerateHTML(report, outputPath)
	case "pdf":
		return g.GeneratePDF(report, outputPath)
	case "csv":
		return g.GenerateCSV(report, outputPath)
	default:
		return fmt.Errorf("unsupported format: %s (supported: json, html, pdf, csv)", format)
	}
}

// GenerateJSON generates a JSON report
func (g *Generator) GenerateJSON(report *types.Report, outputPath string) error {
	if outputPath == "" {
		outputPath = filepath.Join(g.outputDir, fmt.Sprintf("report-%s.json", report.ID))
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write JSON report: %w", err)
	}

	return nil
}

// GenerateHTML generates an HTML report with modern UI
func (g *Generator) GenerateHTML(report *types.Report, outputPath string) error {
	if outputPath == "" {
		outputPath = filepath.Join(g.outputDir, fmt.Sprintf("report-%s.html", report.ID))
	}

	htmlTemplate := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kubernetes Security Compliance Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            padding: 30px;
        }
        h1 {
            color: #2c3e50;
            margin-bottom: 10px;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            flex-wrap: wrap;
        }
        .score-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            min-width: 200px;
        }
        .score-value {
            font-size: 48px;
            font-weight: bold;
            margin: 10px 0;
        }
        .grade {
            font-size: 24px;
            opacity: 0.9;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        .summary-item {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
            border-left: 4px solid #3498db;
        }
        .summary-item.passed { border-left-color: #27ae60; }
        .summary-item.failed { border-left-color: #e74c3c; }
        .summary-item.warned { border-left-color: #f39c12; }
        .summary-label {
            font-size: 12px;
            color: #7f8c8d;
            text-transform: uppercase;
            margin-bottom: 5px;
        }
        .summary-value {
            font-size: 24px;
            font-weight: bold;
            color: #2c3e50;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th {
            background: #34495e;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }
        td {
            padding: 12px;
            border-bottom: 1px solid #ecf0f1;
        }
        tr:hover {
            background: #f8f9fa;
        }
        .status {
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
            display: inline-block;
        }
        .status.pass { background: #d4edda; color: #155724; }
        .status.fail { background: #f8d7da; color: #721c24; }
        .status.warn { background: #fff3cd; color: #856404; }
        .status.error { background: #f5c6cb; color: #721c24; }
        .severity {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
        }
        .severity.critical { background: #fee; color: #c00; }
        .severity.high { background: #ffe6e6; color: #d00; }
        .severity.medium { background: #fff4e6; color: #d60; }
        .severity.low { background: #e6f3ff; color: #006; }
        .details {
            font-size: 12px;
            color: #7f8c8d;
            margin-top: 5px;
        }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ecf0f1;
            text-align: center;
            color: #7f8c8d;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Kubernetes Security Compliance Report</h1>
        <div class="header">
            <div>
                <p><strong>Cluster:</strong> {{.Cluster.Name}}</p>
                <p><strong>K8s Version:</strong> {{.Cluster.K8sVersion}}</p>
                <p><strong>Benchmark:</strong> {{.Benchmark}} {{.BenchmarkVersion}}</p>
                <p><strong>Generated:</strong> {{.GeneratedAt.Format "2006-01-02 15:04:05"}}</p>
            </div>
            <div class="score-card">
                <div class="score-value">{{.ComplianceScore}}%</div>
                <div class="grade">Grade: {{.Grade}}</div>
            </div>
        </div>
        
        <div class="summary">
            <div class="summary-item">
                <div class="summary-label">Total Checks</div>
                <div class="summary-value">{{.TotalChecks}}</div>
            </div>
            <div class="summary-item passed">
                <div class="summary-label">Passed</div>
                <div class="summary-value">{{.PassedChecks}}</div>
            </div>
            <div class="summary-item failed">
                <div class="summary-label">Failed</div>
                <div class="summary-value">{{.FailedChecks}}</div>
            </div>
            <div class="summary-item warned">
                <div class="summary-label">Warnings</div>
                <div class="summary-value">{{.WarnedChecks}}</div>
            </div>
        </div>

        <h2>Check Results</h2>
        <table>
            <thead>
                <tr>
                    <th>Check ID</th>
                    <th>Status</th>
                    <th>Severity</th>
                    <th>Details</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>
                {{range .Results}}
                <tr>
                    <td><strong>{{.CheckID}}</strong></td>
                    <td><span class="status {{.Status | lower}}">{{.Status}}</span></td>
                    <td><span class="severity {{.Severity | lower}}">{{.Severity}}</span></td>
                    <td>
                        {{if .Details}}
                            {{range $i, $detail := .Details}}
                                {{if $i}}<br>{{end}}
                                <span class="details">{{$detail}}</span>
                            {{end}}
                        {{else}}
                            <span class="details">No issues found</span>
                        {{end}}
                    </td>
                    <td>{{.Remediation}}</td>
                </tr>
                {{end}}
            </tbody>
        </table>

        <div class="footer">
            <p>Report generated by Kubernetes Security Baseline Checker</p>
            <p>Duration: {{formatDuration .Duration}}</p>
        </div>
    </div>
</body>
</html>`

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"lower": func(v interface{}) string {
			return strings.ToLower(fmt.Sprintf("%v", v))
		},
		"formatDuration": func(d time.Duration) string {
			return d.Round(time.Millisecond).String()
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse HTML template: %w", err)
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create HTML file: %w", err)
	}
	defer file.Close()

	if err := tmpl.Execute(file, report); err != nil {
		return fmt.Errorf("failed to execute HTML template: %w", err)
	}

	return nil
}

// GeneratePDF generates a PDF report
// Note: PDF generation requires gofpdf library. For now, we generate a text-based report.
func (g *Generator) GeneratePDF(report *types.Report, outputPath string) error {
	if outputPath == "" {
		outputPath = filepath.Join(g.outputDir, fmt.Sprintf("report-%s.pdf", report.ID))
	}

	// For now, generate a text report as PDF support requires additional dependencies
	// TODO: Add gofpdf or similar library for proper PDF generation
	textPath := strings.TrimSuffix(outputPath, ".pdf") + ".txt"
	
	var sb strings.Builder
	sb.WriteString("Kubernetes Security Compliance Report\n")
	sb.WriteString("=====================================\n\n")
	sb.WriteString(fmt.Sprintf("Cluster: %s\n", report.Cluster.Name))
	sb.WriteString(fmt.Sprintf("K8s Version: %s\n", report.Cluster.K8sVersion))
	sb.WriteString(fmt.Sprintf("Benchmark: %s %s\n", report.Benchmark, report.BenchmarkVersion))
	sb.WriteString(fmt.Sprintf("Generated: %s\n\n", report.GeneratedAt.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("Compliance Score: %d%% (Grade: %s)\n\n", report.ComplianceScore, report.Grade))
	sb.WriteString("Summary:\n")
	sb.WriteString(fmt.Sprintf("  Total Checks: %d\n", report.TotalChecks))
	sb.WriteString(fmt.Sprintf("  Passed: %d\n", report.PassedChecks))
	sb.WriteString(fmt.Sprintf("  Failed: %d\n", report.FailedChecks))
	sb.WriteString(fmt.Sprintf("  Warnings: %d\n\n", report.WarnedChecks))
	sb.WriteString("Check Results:\n")
	sb.WriteString("==============\n\n")
	
	for _, result := range report.Results {
		sb.WriteString(fmt.Sprintf("Check ID: %s\n", result.CheckID))
		sb.WriteString(fmt.Sprintf("  Status: %s\n", result.Status))
		sb.WriteString(fmt.Sprintf("  Severity: %s\n", result.Severity))
		if len(result.Details) > 0 {
			sb.WriteString(fmt.Sprintf("  Details: %s\n", strings.Join(result.Details, ", ")))
		}
		sb.WriteString(fmt.Sprintf("  Remediation: %s\n\n", result.Remediation))
	}

	if err := os.WriteFile(textPath, []byte(sb.String()), 0644); err != nil {
		return fmt.Errorf("failed to write text report: %w", err)
	}

	return fmt.Errorf("PDF generation not yet implemented. Text report saved to: %s", textPath)
}

// GenerateCSV generates a CSV report
func (g *Generator) GenerateCSV(report *types.Report, outputPath string) error {
	if outputPath == "" {
		outputPath = filepath.Join(g.outputDir, fmt.Sprintf("report-%s.csv", report.ID))
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{
		"Check ID", "Status", "Severity", "Weight", "Details", "Remediation", "Timestamp",
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write rows
	for _, result := range report.Results {
		row := []string{
			result.CheckID,
			string(result.Status),
			string(result.Severity),
			fmt.Sprintf("%d", result.Weight),
			strings.Join(result.Details, "; "),
			result.Remediation,
			result.Timestamp.Format(time.RFC3339),
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	return nil
}

