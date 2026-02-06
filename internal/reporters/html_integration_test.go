package reporters_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/WritingPanda/ghas-reporting-engine-action/internal/analyzer"
	"github.com/WritingPanda/ghas-reporting-engine-action/internal/config"
	"github.com/WritingPanda/ghas-reporting-engine-action/internal/mapping"
	"github.com/WritingPanda/ghas-reporting-engine-action/internal/models"
	"github.com/WritingPanda/ghas-reporting-engine-action/internal/reporters"
)

// TestGenerateHTMLReportsForAllFrameworks builds realistic alerts covering
// three frameworks (OWASP, SANS, MITRE). Each alert uses the
// external/cwe/* tag convention so CWEs() returns valid values.
func TestGenerateHTMLReportsForAllFrameworks(t *testing.T) {
	// Alerts that map to at least one category in every framework.
	alerts := []models.Alert{
		{
			Number:    1,
			CreatedAt: time.Now().Add(-24 * time.Hour),
			UpdatedAt: time.Now(),
			State:     "open",
			HTMLURL:   "https://github.com/org/repo/security/code-scanning/1",
			Rule: models.Rule{
				ID:                    "go/sql-injection",
				Severity:              "error",
				SecuritySeverityLevel: "critical",
				Tags:                  []string{"security", "external/cwe/cwe-089"},
				Description:           "SQL injection vulnerability",
				Name:                  "SQL Injection",
			},
			Repository: models.Repository{FullName: "org/repo"},
		},
		{
			Number:    2,
			CreatedAt: time.Now().Add(-48 * time.Hour),
			UpdatedAt: time.Now(),
			State:     "open",
			HTMLURL:   "https://github.com/org/repo/security/code-scanning/2",
			Rule: models.Rule{
				ID:                    "go/xss",
				Severity:              "warning",
				SecuritySeverityLevel: "high",
				Tags:                  []string{"security", "external/cwe/cwe-079"},
				Description:           "Cross-site scripting",
				Name:                  "Reflected XSS",
			},
			Repository: models.Repository{FullName: "org/repo"},
		},
		{
			Number:    3,
			CreatedAt: time.Now().Add(-72 * time.Hour),
			UpdatedAt: time.Now(),
			State:     "open",
			HTMLURL:   "https://github.com/org/repo2/security/code-scanning/3",
			Rule: models.Rule{
				ID:                    "go/hardcoded-credentials",
				Severity:              "error",
				SecuritySeverityLevel: "high",
				Tags:                  []string{"security", "external/cwe/cwe-798"},
				Description:           "Hard-coded credentials",
				Name:                  "Hard-coded Credentials",
			},
			Repository: models.Repository{FullName: "org/repo2"},
		},
		{
			Number:    4,
			CreatedAt: time.Now().Add(-96 * time.Hour),
			UpdatedAt: time.Now(),
			State:     "dismissed",
			HTMLURL:   "https://github.com/org/repo/security/code-scanning/4",
			Rule: models.Rule{
				ID:                    "go/path-traversal",
				Severity:              "warning",
				SecuritySeverityLevel: "medium",
				Tags:                  []string{"security", "external/cwe/cwe-022"},
				Description:           "Path traversal vulnerability",
				Name:                  "Path Traversal",
			},
			Repository: models.Repository{FullName: "org/repo"},
		},
		{
			Number:    5,
			CreatedAt: time.Now().Add(-120 * time.Hour),
			UpdatedAt: time.Now(),
			State:     "open",
			HTMLURL:   "https://github.com/org/repo3/security/code-scanning/5",
			Rule: models.Rule{
				ID:                    "go/missing-error-check",
				Severity:              "warning",
				SecuritySeverityLevel: "medium",
				Tags:                  []string{"security", "external/cwe/cwe-252"},
				Description:           "Unchecked return value",
				Name:                  "Missing Error Check",
			},
			Repository: models.Repository{FullName: "org/repo3"},
		},
	}

	mapper, err := mapping.NewMapper("")
	if err != nil {
		t.Fatalf("NewMapper: %v", err)
	}

	frameworks := []string{"owasp", "sans", "mitre"}

	for _, fw := range frameworks {
		t.Run(fw, func(t *testing.T) {
			cfg := config.Config{
				ReportTypes:    []string{fw},
				DaysBack:       90,
				OutputDir:      t.TempDir(),
				IncludeDismissed: true,
			}

			a := analyzer.New(cfg, mapper)
			result := a.Analyze(alerts)

			metadata := mapper.FrameworkSummaries()[fw]
			if metadata == nil {
				t.Fatalf("no metadata for framework %s", fw)
			}

			outPath := filepath.Join(cfg.OutputDir, "ghas_"+fw+"_report.html")
			err := reporters.WriteHTML(result, fw, alerts, metadata, outPath, reporters.ReportTemplate)
			if err != nil {
				t.Fatalf("WriteHTML(%s): %v", fw, err)
			}

			info, err := os.Stat(outPath)
			if err != nil {
				t.Fatalf("stat report: %v", err)
			}
			if info.Size() == 0 {
				t.Fatal("report file is empty")
			}
			t.Logf("generated %s report: %s (%d bytes)", fw, outPath, info.Size())
		})
	}
}

// TestHTMLReportWithNoAlerts verifies that an empty alert list produces a
// valid (non-crashing) HTML report for every framework.
func TestHTMLReportWithNoAlerts(t *testing.T) {
	mapper, err := mapping.NewMapper("")
	if err != nil {
		t.Fatalf("NewMapper: %v", err)
	}

	frameworks := []string{"owasp", "sans", "mitre"}

	for _, fw := range frameworks {
		t.Run("empty_"+fw, func(t *testing.T) {
			cfg := config.Config{
				ReportTypes: []string{fw},
				DaysBack:    90,
				OutputDir:   t.TempDir(),
			}

			a := analyzer.New(cfg, mapper)
			result := a.Analyze([]models.Alert{})

			metadata := mapper.FrameworkSummaries()[fw]

			outPath := filepath.Join(cfg.OutputDir, "empty_"+fw+".html")
			err := reporters.WriteHTML(result, fw, []models.Alert{}, metadata, outPath, reporters.ReportTemplate)
			if err != nil {
				t.Fatalf("WriteHTML empty (%s): %v", fw, err)
			}

			info, err := os.Stat(outPath)
			if err != nil {
				t.Fatalf("stat: %v", err)
			}
			if info.Size() == 0 {
				t.Fatal("empty report file is empty")
			}
			t.Logf("generated empty %s report: %s (%d bytes)", fw, outPath, info.Size())
		})
	}
}
