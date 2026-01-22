package mapping

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

//go:embed assets/owasp_top10.json
//go:embed assets/sans_top25.json
//go:embed assets/mitre_kev.json
var embeddedFS embed.FS

// OWASPData mirrors owasp_top10.json layout.
type OWASPData struct {
	Framework  string                   `json:"framework"`
	Version    string                   `json:"version"`
	Categories map[string]OWASPCategory `json:"categories"`
}

// OWASPCategory describes a single OWASP entry.
type OWASPCategory struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	CWEs        []string `json:"cwes"`
}

// SANSData mirrors sans_top25.json.
type SANSData struct {
	Framework string        `json:"framework"`
	Version   string        `json:"version"`
	Rankings  []SANSRanking `json:"rankings"`
}

// SANSRanking represents a ranked CWE.
type SANSRanking struct {
	Rank int    `json:"rank"`
	CWE  string `json:"cwe"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

// KEVData mirrors mitre_kev.json.
type KEVData struct {
	Framework string    `json:"framework"`
	Version   string    `json:"version"`
	Top10     []KEVItem `json:"top_10_kev"`
}

// KEVItem holds rank info.
type KEVItem struct {
	Rank     int    `json:"rank"`
	CWE      string `json:"cwe"`
	Name     string `json:"name"`
	CVECount int    `json:"cve_count"`
}

// Mapper loads framework mappings from embedded assets or an optional data directory.
type Mapper struct {
	owasp OWASPData
	sans  SANSData
	kev   KEVData
}

// NewMapper builds a mapper, preferring dataDir when provided.
func NewMapper(dataDir string) (*Mapper, error) {
	loader := func(path string, target any) error {
		if dataDir != "" {
			if err := loadJSON(filepath.Join(dataDir, filepath.Base(path)), target); err == nil {
				return nil
			}
		}
		return loadEmbedded(path, target)
	}

	m := &Mapper{}
	if err := loader("assets/owasp_top10.json", &m.owasp); err != nil {
		return nil, fmt.Errorf("load owasp mappings: %w", err)
	}
	if err := loader("assets/sans_top25.json", &m.sans); err != nil {
		return nil, fmt.Errorf("load sans mappings: %w", err)
	}
	if err := loader("assets/mitre_kev.json", &m.kev); err != nil {
		return nil, fmt.Errorf("load mitre kev mappings: %w", err)
	}
	return m, nil
}

func loadJSON(path string, target any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewDecoder(f).Decode(target)
}

func loadEmbedded(path string, target any) error {
	data, err := fs.ReadFile(embeddedFS, path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}

// OWASPCategoryMap returns category -> matched CWEs for supplied list.
func (m *Mapper) OWASPCategoryMap(cwes []string) map[string][]string {
	set := make(map[string]struct{}, len(cwes))
	for _, c := range cwes {
		set[strings.ToUpper(c)] = struct{}{}
	}
	out := map[string][]string{}
	for id, cat := range m.owasp.Categories {
		matched := []string{}
		for _, cwe := range cat.CWEs {
			if _, ok := set[strings.ToUpper(cwe)]; ok {
				matched = append(matched, strings.ToUpper(cwe))
			}
		}
		if len(matched) > 0 {
			out[fmt.Sprintf("%s: %s", id, cat.Name)] = matched
		}
	}
	return out
}

// SANSMatches returns CWE -> rank details for supplied CWEs.
func (m *Mapper) SANSMatches(cwes []string) map[string]SANSRanking {
	set := make(map[string]struct{}, len(cwes))
	for _, c := range cwes {
		set[strings.ToUpper(c)] = struct{}{}
	}
	out := map[string]SANSRanking{}
	for _, r := range m.sans.Rankings {
		if _, ok := set[strings.ToUpper(r.CWE)]; ok {
			out[strings.ToUpper(r.CWE)] = r
		}
	}
	return out
}

// KEVMatches returns CWE -> KEV entry for supplied CWEs.
func (m *Mapper) KEVMatches(cwes []string) map[string]KEVItem {
	set := make(map[string]struct{}, len(cwes))
	for _, c := range cwes {
		set[strings.ToUpper(c)] = struct{}{}
	}
	out := map[string]KEVItem{}
	for _, k := range m.kev.Top10 {
		if _, ok := set[strings.ToUpper(k.CWE)]; ok {
			out[strings.ToUpper(k.CWE)] = k
		}
	}
	return out
}

// FrameworkSummaries returns metadata used by reporters.
func (m *Mapper) FrameworkSummaries() map[string]map[string]any {
	return map[string]map[string]any{
		"owasp": {
			"framework":        m.owasp.Framework,
			"version":          m.owasp.Version,
			"total_categories": len(m.owasp.Categories),
		},
		"sans": {
			"framework":    m.sans.Framework,
			"version":      m.sans.Version,
			"total_ranked": len(m.sans.Rankings),
		},
		"mitre": {
			"framework":    m.kev.Framework,
			"version":      m.kev.Version,
			"total_ranked": len(m.kev.Top10),
		},
	}
}
