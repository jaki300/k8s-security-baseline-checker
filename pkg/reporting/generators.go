package reporting

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ReportGenerator generates enterprise compliance reports
type ReportGenerator struct {
	outputDir string
}

// NewReportGenerator creates a new report generator
func NewReportGenerator(outputDir string) *ReportGenerator {
	return &ReportGenerator{
		outputDir: outputDir,
	}
}

// GenerateComplianceReport generates a comprehensive compliance report
func (g *ReportGenerator) GenerateComplianceReport(
	report *ComplianceReport,
	format string,
	outputPath string,
) error {
	switch strings.ToLower(format) {
	case "json":
		return g.GenerateJSON(report, outputPath)
	case "html":
		return g.GenerateHTML(report, outputPath)
	case "csv":
		return g.GenerateCSV(report, outputPath)
	default:
		return fmt.Errorf("unsupported format: %s (supported: json, html, csv)", format)
	}
}

// GenerateJSON generates a machine-readable JSON report
func (g *ReportGenerator) GenerateJSON(report *ComplianceReport, outputPath string) error {
	if outputPath == "" {
		outputPath = filepath.Join(g.outputDir, fmt.Sprintf("compliance-report-%s.json", report.ID))
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

// GenerateHTML generates an executive dashboard HTML report
func (g *ReportGenerator) GenerateHTML(report *ComplianceReport, outputPath string) error {
	if outputPath == "" {
		outputPath = filepath.Join(g.outputDir, fmt.Sprintf("compliance-report-%s.html", report.ID))
	}

	htmlTemplate := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Compliance Report - {{.Cluster.Name}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #2c3e50;
            background: #f5f7fa;
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            padding: 40px;
        }
        .header {
            border-bottom: 3px solid #3498db;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        h1 {
            color: #2c3e50;
            font-size: 32px;
            margin-bottom: 10px;
        }
        .header-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-top: 20px;
            font-size: 14px;
        }
        .header-info-item {
            color: #7f8c8d;
        }
        .header-info-item strong {
            color: #2c3e50;
        }
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        .dashboard-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 12px;
            text-align: center;
        }
        .dashboard-card.risk {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }
        .dashboard-card.compliance {
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        }
        .dashboard-card.frameworks {
            background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);
        }
        .card-value {
            font-size: 48px;
            font-weight: bold;
            margin: 10px 0;
        }
        .card-label {
            font-size: 14px;
            opacity: 0.9;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .card-subvalue {
            font-size: 18px;
            margin-top: 10px;
            opacity: 0.9;
        }
        .section {
            margin-bottom: 40px;
        }
        .section-title {
            font-size: 24px;
            color: #2c3e50;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #ecf0f1;
        }
        .framework-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        .framework-card {
            background: #f8f9fa;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            padding: 20px;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .framework-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        .framework-card.compliant {
            border-color: #27ae60;
        }
        .framework-card.non-compliant {
            border-color: #e74c3c;
        }
        .framework-card.partial {
            border-color: #f39c12;
        }
        .framework-name {
            font-size: 18px;
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 10px;
        }
        .framework-score {
            font-size: 32px;
            font-weight: bold;
            color: #3498db;
            margin: 10px 0;
        }
        .framework-stats {
            display: flex;
            justify-content: space-between;
            font-size: 12px;
            color: #7f8c8d;
            margin-top: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: white;
        }
        th {
            background: #34495e;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            font-size: 14px;
        }
        td {
            padding: 15px;
            border-bottom: 1px solid #ecf0f1;
            font-size: 14px;
        }
        tr:hover {
            background: #f8f9fa;
        }
        .status-badge {
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            display: inline-block;
        }
        .status-badge.pass { background: #d4edda; color: #155724; }
        .status-badge.fail { background: #f8d7da; color: #721c24; }
        .status-badge.warn { background: #fff3cd; color: #856404; }
        .status-badge.error { background: #f5c6cb; color: #721c24; }
        .severity-badge {
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
        }
        .severity-badge.critical { background: #fee; color: #c00; }
        .severity-badge.high { background: #ffe6e6; color: #d00; }
        .severity-badge.medium { background: #fff4e6; color: #d60; }
        .severity-badge.low { background: #e6f3ff; color: #006; }
        .evidence-section {
            background: #f8f9fa;
            border-left: 4px solid #3498db;
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
        }
        .evidence-title {
            font-weight: 600;
            color: #2c3e50;
            margin-bottom: 8px;
        }
        .evidence-content {
            font-size: 12px;
            color: #7f8c8d;
            font-family: 'Courier New', monospace;
            background: white;
            padding: 10px;
            border-radius: 4px;
            margin-top: 5px;
        }
        .remediation-section {
            background: #fff9e6;
            border-left: 4px solid #f39c12;
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
        }
        .remediation-title {
            font-weight: 600;
            color: #856404;
            margin-bottom: 10px;
        }
        .remediation-steps {
            list-style: none;
            padding-left: 0;
        }
        .remediation-steps li {
            padding: 8px 0;
            padding-left: 25px;
            position: relative;
        }
        .remediation-steps li:before {
            content: "→";
            position: absolute;
            left: 0;
            color: #f39c12;
            font-weight: bold;
        }
        .risk-indicator {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 14px;
        }
        .risk-indicator.critical { background: #fee; color: #c00; }
        .risk-indicator.high { background: #ffe6e6; color: #d00; }
        .risk-indicator.medium { background: #fff4e6; color: #d60; }
        .risk-indicator.low { background: #e6f3ff; color: #006; }
        .risk-indicator.minimal { background: #d4edda; color: #155724; }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #ecf0f1;
            text-align: center;
            color: #7f8c8d;
            font-size: 12px;
        }
        .expandable {
            cursor: pointer;
        }
        .expandable-content {
            display: none;
            margin-top: 10px;
        }
        .expandable.expanded .expandable-content {
            display: block;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Enterprise Compliance Report</h1>
            <div class="header-info">
                <div class="header-info-item">
                    <strong>Cluster:</strong> {{.Cluster.Name}}
                </div>
                <div class="header-info-item">
                    <strong>K8s Version:</strong> {{.Cluster.K8sVersion}}
                </div>
                <div class="header-info-item">
                    <strong>Provider:</strong> {{.Cluster.Provider}}
                </div>
                <div class="header-info-item">
                    <strong>Benchmark:</strong> {{.Benchmark.Name}} {{.Benchmark.Version}}
                </div>
                <div class="header-info-item">
                    <strong>Generated:</strong> {{.GeneratedAt.Format "2006-01-02 15:04:05 MST"}}
                </div>
                <div class="header-info-item">
                    <strong>Duration:</strong> {{.Duration.Round time.Millisecond}}
                </div>
            </div>
        </div>

        <!-- Executive Dashboard -->
        <div class="dashboard">
            <div class="dashboard-card compliance">
                <div class="card-label">Compliance Score</div>
                <div class="card-value">{{printf "%.1f" .OverallCompliance.ComplianceScore}}%</div>
                <div class="card-subvalue">Grade: {{.OverallCompliance.Grade}}</div>
            </div>
            <div class="dashboard-card risk">
                <div class="card-label">Risk Score</div>
                <div class="card-value">{{printf "%.1f" .RiskScore.OverallScore}}</div>
                <div class="card-subvalue">
                    <span class="risk-indicator {{.RiskScore.RiskLevel | lower}}">{{.RiskScore.RiskLevel}}</span>
                </div>
            </div>
            <div class="dashboard-card">
                <div class="card-label">Total Checks</div>
                <div class="card-value">{{.OverallCompliance.TotalChecks}}</div>
                <div class="card-subvalue">
                    ✓ {{.OverallCompliance.PassedChecks}} | 
                    ✗ {{.OverallCompliance.FailedChecks}} | 
                    ⚠ {{.OverallCompliance.WarnedChecks}}
                </div>
            </div>
            <div class="dashboard-card frameworks">
                <div class="card-label">Frameworks</div>
                <div class="card-value">{{len .FrameworkMappings}}</div>
                <div class="card-subvalue">Mapped</div>
            </div>
        </div>

        <!-- Framework Compliance Overview -->
        <div class="section">
            <h2 class="section-title">Framework Compliance</h2>
            <div class="framework-grid">
                {{range $framework, $compliance := .FrameworkMappings}}
                <div class="framework-card {{$compliance.ComplianceScore | complianceClass}}">
                    <div class="framework-name">{{$compliance.Framework}} {{$compliance.Version}}</div>
                    <div class="framework-score">{{printf "%.1f" $compliance.ComplianceScore}}%</div>
                    <div style="margin: 10px 0;">
                        <span class="status-badge {{if $compliance.Compliant}}pass{{else}}fail{{end}}">
                            {{if $compliance.Compliant}}COMPLIANT{{else}}NON-COMPLIANT{{end}}
                        </span>
                    </div>
                    <div class="framework-stats">
                        <span>✓ {{$compliance.CompliantControls}}</span>
                        <span>✗ {{$compliance.NonCompliantControls}}</span>
                        <span>⚠ {{$compliance.PartialControls}}</span>
                    </div>
                </div>
                {{end}}
            </div>
        </div>

        <!-- Risk Breakdown -->
        <div class="section">
            <h2 class="section-title">Risk Assessment</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Count</th>
                        <th>Risk Contribution</th>
                    </tr>
                </thead>
                <tbody>
                    {{range $severity, $count := .RiskScore.SeverityBreakdown}}
                    <tr>
                        <td><span class="severity-badge {{$severity | lower}}">{{$severity}}</span></td>
                        <td>{{$count}}</td>
                        <td>{{printf "%.1f" (index $.RiskScore.CategoryRisks $severity)}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>

        <!-- Check Results with Evidence -->
        <div class="section">
            <h2 class="section-title">Detailed Check Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>Check ID</th>
                        <th>Status</th>
                        <th>Severity</th>
                        <th>Category</th>
                        <th>Risk Score</th>
                        <th>Framework Controls</th>
                        <th>Evidence</th>
                        <th>Remediation</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .CheckResults}}
                    <tr>
                        <td><strong>{{.CheckID}}</strong><br><small>{{.CheckName}}</small></td>
                        <td><span class="status-badge {{.Status | lower}}">{{.Status}}</span></td>
                        <td><span class="severity-badge {{.Severity | lower}}">{{.Severity}}</span></td>
                        <td>{{.Category}}</td>
                        <td>{{printf "%.1f" .RiskScore}}</td>
                        <td>
                            {{if .FrameworkControls}}
                                {{range .FrameworkControls}}
                                    <div style="font-size: 11px; margin: 2px 0;">
                                        <strong>{{.Framework}}:</strong> {{.ControlID}}<br>
                                        <span class="status-badge {{.Status | lower}}">{{.Status}}</span>
                                    </div>
                                {{end}}
                            {{else}}
                                <span style="color: #7f8c8d;">N/A</span>
                            {{end}}
                        </td>
                        <td>
                            {{if .Evidence}}
                                <div class="expandable" onclick="this.classList.toggle('expanded')">
                                    <span style="color: #3498db; cursor: pointer;">View Evidence ({{len .Evidence}})</span>
                                    <div class="expandable-content">
                                        {{range .Evidence}}
                                        <div class="evidence-section">
                                            <div class="evidence-title">{{.Type | title}} - {{.Source}}</div>
                                            <div class="evidence-content">{{.Description}}</div>
                                        </div>
                                        {{end}}
                                    </div>
                                </div>
                            {{else}}
                                <span style="color: #7f8c8d;">No evidence</span>
                            {{end}}
                        </td>
                        <td>
                            <div class="remediation-section">
                                <div class="remediation-title">Priority: {{.Remediation.Priority}}</div>
                                <ul class="remediation-steps">
                                    {{range .Remediation.Steps}}
                                    <li>{{.}}</li>
                                    {{end}}
                                </ul>
                                {{if .Remediation.Commands}}
                                <div style="margin-top: 10px;">
                                    <strong>Commands:</strong>
                                    {{range .Remediation.Commands}}
                                    <div class="evidence-content" style="margin-top: 5px;">{{.}}</div>
                                    {{end}}
                                </div>
                                {{end}}
                            </div>
                        </td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>

        <div class="footer">
            <p>Report generated by Kubernetes Security Baseline Checker</p>
            <p>This report contains sensitive security information - handle with care</p>
        </div>
    </div>
</body>
</html>`

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"lower": strings.ToLower,
		"title": strings.Title,
		"complianceClass": func(score float64) string {
			if score >= 80 {
				return "compliant"
			} else if score >= 60 {
				return "partial"
			}
			return "non-compliant"
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

// GenerateCSV generates an auditor-friendly CSV report
func (g *ReportGenerator) GenerateCSV(report *ComplianceReport, outputPath string) error {
	if outputPath == "" {
		outputPath = filepath.Join(g.outputDir, fmt.Sprintf("compliance-report-%s.csv", report.ID))
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
		"Check ID",
		"Check Name",
		"Category",
		"Status",
		"Severity",
		"Risk Score",
		"Framework",
		"Control ID",
		"Control Name",
		"Control Status",
		"Evidence Type",
		"Evidence Source",
		"Evidence Description",
		"Finding ID",
		"Finding Title",
		"Finding Resource",
		"Remediation Priority",
		"Remediation Summary",
		"Remediation Steps",
		"Remediation Commands",
		"Timestamp",
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write rows - one row per check with framework mappings
	for _, result := range report.CheckResults {
		// If no framework mappings, write one row
		if len(result.FrameworkControls) == 0 {
			row := buildCSVRow(result, "", "", "", "", "")
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("failed to write CSV row: %w", err)
			}
		} else {
			// Write one row per framework control mapping
			for _, control := range result.FrameworkControls {
				row := buildCSVRow(result, control.Framework, control.ControlID, control.ControlName, string(control.Status), "")
				if err := writer.Write(row); err != nil {
					return fmt.Errorf("failed to write CSV row: %w", err)
				}
			}
		}
	}

	// Write framework summary section
	if err := writer.Write([]string{}); err != nil {
		return err
	}
	if err := writer.Write([]string{"FRAMEWORK COMPLIANCE SUMMARY"}); err != nil {
		return err
	}
	frameworkHeader := []string{
		"Framework",
		"Version",
		"Total Controls",
		"Compliant",
		"Non-Compliant",
		"Partial",
		"Compliance Score",
		"Grade",
		"Compliant Status",
	}
	if err := writer.Write(frameworkHeader); err != nil {
		return err
	}

	// Sort frameworks for consistent output
	var frameworks []string
	for fw := range report.FrameworkMappings {
		frameworks = append(frameworks, fw)
	}
	sort.Strings(frameworks)

	for _, fw := range frameworks {
		compliance := report.FrameworkMappings[fw]
		compliantStatus := "NON-COMPLIANT"
		if compliance.Compliant {
			compliantStatus = "COMPLIANT"
		}
		row := []string{
			compliance.Framework,
			compliance.Version,
			fmt.Sprintf("%d", compliance.TotalControls),
			fmt.Sprintf("%d", compliance.CompliantControls),
			fmt.Sprintf("%d", compliance.NonCompliantControls),
			fmt.Sprintf("%d", compliance.PartialControls),
			fmt.Sprintf("%.2f", compliance.ComplianceScore),
			compliance.Grade,
			compliantStatus,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

func buildCSVRow(result CheckResultWithEvidence, framework, controlID, controlName, controlStatus, evidenceDetail string) []string {
	// Build evidence summary
	evidenceTypes := []string{}
	evidenceSources := []string{}
	evidenceDescriptions := []string{}
	for _, ev := range result.Evidence {
		evidenceTypes = append(evidenceTypes, ev.Type)
		evidenceSources = append(evidenceSources, ev.Source)
		evidenceDescriptions = append(evidenceDescriptions, ev.Description)
	}

	// Build findings summary
	findingIDs := []string{}
	findingTitles := []string{}
	findingResources := []string{}
	for _, finding := range result.Findings {
		findingIDs = append(findingIDs, finding.ID)
		findingTitles = append(findingTitles, finding.Title)
		findingResources = append(findingResources, finding.Resource)
	}

	return []string{
		result.CheckID,
		result.CheckName,
		result.Category,
		result.Status,
		result.Severity,
		fmt.Sprintf("%.2f", result.RiskScore),
		framework,
		controlID,
		controlName,
		controlStatus,
		strings.Join(evidenceTypes, "; "),
		strings.Join(evidenceSources, "; "),
		strings.Join(evidenceDescriptions, "; "),
		strings.Join(findingIDs, "; "),
		strings.Join(findingTitles, "; "),
		strings.Join(findingResources, "; "),
		result.Remediation.Priority,
		result.Remediation.Summary,
		strings.Join(result.Remediation.Steps, " | "),
		strings.Join(result.Remediation.Commands, " | "),
		result.Timestamp.Format(time.RFC3339),
	}
}


