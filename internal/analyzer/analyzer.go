package analyzer

import (
	"sort"

	"github.com/WritingPanda/ghas-reporting-engine-action/internal/config"
	"github.com/WritingPanda/ghas-reporting-engine-action/internal/mapping"
	"github.com/WritingPanda/ghas-reporting-engine-action/internal/models"
)

// AnalysisResult mirrors the Python tool's output at a high level.
type AnalysisResult struct {
	Summary            map[string]int            `json:"summary"`
	FrameworkMappings  map[string]map[string]any `json:"framework_mappings"`
	CWEAnalysis        map[string]any            `json:"cwe_analysis"`
	RepositoryAnalysis map[string]any            `json:"repository_analysis"`
	SeverityAnalysis   map[string]any            `json:"severity_analysis"`
	Recommendations    []string                  `json:"recommendations"`
}

// Analyzer holds mapping utilities.
type Analyzer struct {
	cfg    config.Config
	mapper *mapping.Mapper
}

// New builds an Analyzer.
func New(cfg config.Config, mapper *mapping.Mapper) *Analyzer {
	return &Analyzer{cfg: cfg, mapper: mapper}
}

// Analyze processes fetched alerts into aggregated structures.
func (a *Analyzer) Analyze(alerts []models.Alert) AnalysisResult {
	res := AnalysisResult{
		Summary:            map[string]int{},
		FrameworkMappings:  map[string]map[string]any{},
		CWEAnalysis:        map[string]any{},
		RepositoryAnalysis: map[string]any{},
		SeverityAnalysis:   map[string]any{},
		Recommendations:    []string{},
	}
	if len(alerts) == 0 {
		return res
	}

	res.Summary = a.buildSummary(alerts)

	allCWEs := collectCWEs(alerts)

	for _, fw := range a.cfg.ReportTypes {
		switch fw {
		case "owasp":
			res.FrameworkMappings["owasp"] = a.analyzeOWASP(alerts, allCWEs)
		case "sans":
			res.FrameworkMappings["sans"] = a.analyzeSANS(alerts, allCWEs)
		case "mitre":
			res.FrameworkMappings["mitre"] = a.analyzeMITRE(alerts, allCWEs)
		}
	}

	res.CWEAnalysis = a.analyzeCWEs(alerts, allCWEs)
	res.RepositoryAnalysis = a.analyzeRepositories(alerts)
	res.SeverityAnalysis = a.analyzeSeverities(alerts)
	res.Recommendations = a.recommend(res)

	return res
}

func (a *Analyzer) buildSummary(alerts []models.Alert) map[string]int {
	summary := map[string]int{"total_alerts": len(alerts), "open_alerts": 0, "dismissed_alerts": 0, "fixed_alerts": 0}
	for _, al := range alerts {
		if al.IsOpen() {
			summary["open_alerts"]++
		}
		if al.IsDismissed() {
			summary["dismissed_alerts"]++
		}
		if al.IsFixed() {
			summary["fixed_alerts"]++
		}
	}
	return summary
}

func collectCWEs(alerts []models.Alert) []string {
	set := map[string]struct{}{}
	out := []string{}
	for _, a := range alerts {
		for _, c := range a.CWEs() {
			if _, ok := set[c]; !ok {
				set[c] = struct{}{}
				out = append(out, c)
			}
		}
	}
	return out
}

func (a *Analyzer) analyzeOWASP(alerts []models.Alert, allCWEs []string) map[string]any {
	categoryMap := a.mapper.OWASPCategoryMap(allCWEs)
	counts := map[string]int{}
	for _, al := range alerts {
		cwes := al.CWEs()
		for cat, mapped := range categoryMap {
			if intersects(cwes, mapped) {
				counts[cat]++
			}
		}
	}
	return map[string]any{
		"summary":             a.mapper.FrameworkSummaries()["owasp"],
		"category_alerts":     counts,
		"total_mapped_alerts": sumInt(counts),
	}
}

func (a *Analyzer) analyzeSANS(alerts []models.Alert, allCWEs []string) map[string]any {
	match := a.mapper.SANSMatches(allCWEs)
	cweCounts := map[string]int{}
	for _, al := range alerts {
		for _, c := range al.CWEs() {
			if _, ok := match[c]; ok {
				cweCounts[c]++
			}
		}
	}
	// sort top 5
	type pair struct {
		cwe   string
		count int
	}
	pairs := []pair{}
	for c, n := range cweCounts {
		pairs = append(pairs, pair{c, n})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].count > pairs[j].count })
	top := map[string]int{}
	for i := 0; i < len(pairs) && i < 5; i++ {
		top[pairs[i].cwe] = pairs[i].count
	}
	return map[string]any{
		"summary":             a.mapper.FrameworkSummaries()["sans"],
		"mappings":            match,
		"cwe_counts":          cweCounts,
		"top_5_cwes":          top,
		"total_mapped_alerts": sumInt(cweCounts),
	}
}

func (a *Analyzer) analyzeMITRE(alerts []models.Alert, allCWEs []string) map[string]any {
	match := a.mapper.KEVMatches(allCWEs)
	cweCounts := map[string]int{}
	for _, al := range alerts {
		for _, c := range al.CWEs() {
			if _, ok := match[c]; ok {
				cweCounts[c]++
			}
		}
	}
	return map[string]any{
		"summary":             a.mapper.FrameworkSummaries()["mitre"],
		"mappings":            match,
		"cwe_counts":          cweCounts,
		"total_mapped_alerts": sumInt(cweCounts),
	}
}

func (a *Analyzer) analyzeCWEs(alerts []models.Alert, allCWEs []string) map[string]any {
	counts := map[string]int{}
	for _, al := range alerts {
		for _, c := range al.CWEs() {
			counts[c]++
		}
	}
	// top 10
	type pair struct {
		c string
		n int
	}
	pairs := []pair{}
	for c, n := range counts {
		pairs = append(pairs, pair{c, n})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].n > pairs[j].n })
	top := map[string]int{}
	for i := 0; i < len(pairs) && i < 10; i++ {
		top[pairs[i].c] = pairs[i].n
	}
	return map[string]any{
		"total_unique_cwes": len(allCWEs),
		"top_cwes":          top,
	}
}

func (a *Analyzer) analyzeRepositories(alerts []models.Alert) map[string]any {
	repoCounts := map[string]int{}
	for _, al := range alerts {
		repoCounts[al.Repository.FullName]++
	}
	return map[string]any{
		"total_repositories":         len(repoCounts),
		"top_repositories_by_alerts": repoCounts,
	}
}

func (a *Analyzer) analyzeSeverities(alerts []models.Alert) map[string]any {
	counts := map[string]int{}
	for _, al := range alerts {
		counts[al.Severity()]++
	}
	return map[string]any{"severity_counts": counts}
}

func (a *Analyzer) recommend(res AnalysisResult) []string {
	recs := []string{}
	if res.Summary["total_alerts"] > 100 {
		recs = append(recs, "High alert volume detected; consider automated triage.")
	}
	if res.Summary["open_alerts"] > 0 {
		recs = append(recs, "Prioritize open alerts with critical/high severity.")
	}
	if mapped, ok := res.FrameworkMappings["mitre"]; ok {
		if val, ok2 := mapped["total_mapped_alerts"].(int); ok2 && val > 0 {
			recs = append(recs, "Known exploited vulnerabilities present; patch immediately.")
		}
	}
	return recs
}

func intersects(a, b []string) bool {
	set := map[string]struct{}{}
	for _, v := range a {
		set[v] = struct{}{}
	}
	for _, v := range b {
		if _, ok := set[v]; ok {
			return true
		}
	}
	return false
}

func sumInt(m map[string]int) int {
	s := 0
	for _, v := range m {
		s += v
	}
	return s
}
