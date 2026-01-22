package models

import (
	"strings"
	"time"
)

// Alert models the GitHub Code Scanning alert payload (subset used by the tool).
type Alert struct {
	Number     int        `json:"number"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	State      string     `json:"state"`
	HTMLURL    string     `json:"html_url"`
	Rule       Rule       `json:"rule"`
	Repository Repository `json:"repository"`
}

// Rule contains rule metadata.
type Rule struct {
	ID                    string   `json:"id"`
	Severity              string   `json:"severity"`
	SecuritySeverityLevel string   `json:"security_severity_level"`
	Tags                  []string `json:"tags"`
	Description           string   `json:"description"`
	Name                  string   `json:"name"`
}

// Repository represents the owning repo.
type Repository struct {
	FullName string `json:"full_name"`
}

// CWEs extracts normalized CWE IDs from rule tags.
func (a Alert) CWEs() []string {
	out := []string{}
	for _, tag := range a.Rule.Tags {
		if len(tag) < 12 {
			continue
		}
		if tag[:12] == "external/cwe" {
			cwe := tag[len("external/cwe/"):]
			if cwe != "" {
				if cwe[:4] != "CWE-" {
					cwe = "CWE-" + cwe
				}
				out = append(out, strings.ToUpper(cwe))
			}
		}
	}
	return out
}

// Severity returns normalized severity string.
func (a Alert) Severity() string {
	if a.Rule.SecuritySeverityLevel != "" {
		return strings.ToLower(a.Rule.SecuritySeverityLevel)
	}
	return strings.ToLower(a.Rule.Severity)
}

// IsOpen returns true when the alert is open.
func (a Alert) IsOpen() bool { return a.State == "open" }

// IsDismissed returns true when the alert is dismissed.
func (a Alert) IsDismissed() bool { return a.State == "dismissed" }

// IsFixed returns true when the alert is fixed.
func (a Alert) IsFixed() bool { return a.State == "fixed" }
