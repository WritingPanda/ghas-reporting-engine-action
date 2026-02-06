package reporters

import (
	"fmt"
	"html/template"
	"os"
	"sort"
	"strings"

	"github.com/WritingPanda/ghas-reporting-engine-action/internal/analyzer"
	"github.com/WritingPanda/ghas-reporting-engine-action/internal/models"
)

type alertLink struct {
	Number   int
	Repo     string
	URL      string
	State    string
	Severity string
	RuleID   string
	RuleName string
}

type cweGroup struct {
	CWE    string
	Count  int
	Alerts []alertLink
}

// WriteHTML renders a simple HTML report using the embedded template.
func WriteHTML(result analyzer.AnalysisResult, framework string, alerts []models.Alert, metadata map[string]any, path string, templateText string) error {
	funcMap := template.FuncMap{"upper": func(v any) string {
		return strings.ToUpper(fmt.Sprint(v))
	}}
	tpl, err := template.New("report").Funcs(funcMap).Parse(templateText)
	if err != nil {
		return err
	}

	// Build Metadata with the keys the template expects (title-cased).
	meta := map[string]any{
		"Framework": metadata["framework"],
		"Target":    metadata["version"],
	}
	// Copy any remaining keys so callers can add extra metadata.
	for k, v := range metadata {
		if k != "framework" && k != "version" {
			meta[k] = v
		}
	}

	ctx := map[string]any{
		"Metadata":        meta,
		"Summary":         result.Summary,
		"Framework":       result.FrameworkMappings[framework],
		"CWEAnalysis":     result.CWEAnalysis,
		"Recommendations": result.Recommendations,
		"CWEGroups":       buildCWEGroups(alerts),
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return tpl.Execute(f, ctx)
}

func buildCWEGroups(alerts []models.Alert) []cweGroup {
	groups := map[string][]alertLink{}
	for _, alert := range alerts {
		cwes := alert.CWEs()
		if len(cwes) == 0 {
			cwes = []string{"CWE-UNKNOWN"}
		}
		for _, cwe := range cwes {
			groups[cwe] = append(groups[cwe], alertLink{
				Number:   alert.Number,
				Repo:     alert.Repository.FullName,
				URL:      alert.HTMLURL,
				State:    alert.State,
				Severity: alert.Severity(),
				RuleID:   alert.Rule.ID,
				RuleName: alert.Rule.Name,
			})
		}
	}

	out := make([]cweGroup, 0, len(groups))
	for cwe, items := range groups {
		out = append(out, cweGroup{CWE: cwe, Count: len(items), Alerts: items})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].CWE < out[j].CWE
		}
		return out[i].Count > out[j].Count
	})
	return out
}
