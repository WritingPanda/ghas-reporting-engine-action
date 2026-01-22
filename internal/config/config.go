package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	validReportTypes = map[string]bool{"owasp": true, "sans": true, "mitre": true}
	validSeverities  = map[string]bool{"critical": true, "high": true, "medium": true, "low": true}
)

// Config holds runtime settings parsed from flags/env.
type Config struct {
	GitHubToken      string
	Organization     string
	Enterprise       string
	ReportTypes      []string
	DaysBack         int
	OutputDir        string
	LogLevel         string
	IncludeDismissed bool
	IncludeFixed     bool
	SeverityFilters  []string
	APIBaseURL       string
	MaxRetries       int
	RequestTimeout   time.Duration
	DataDir          string
}

// DefaultConfig returns baseline values.
func DefaultConfig() Config {
	return Config{
		ReportTypes:      []string{"owasp", "sans", "mitre"},
		DaysBack:         90,
		OutputDir:        "./reports",
		LogLevel:         "INFO",
		IncludeDismissed: false,
		IncludeFixed:     false,
		APIBaseURL:       "https://api.github.com",
		MaxRetries:       3,
		RequestTimeout:   30 * time.Second,
	}
}

// Validate enforces flag invariants.
func (c *Config) Validate() error {
	if c.GitHubToken == "" {
		return errors.New("GitHub token is required (use --token or GITHUB_TOKEN)")
	}
	if c.Organization == "" && c.Enterprise == "" {
		return errors.New("either --organization or --enterprise must be specified")
	}
	if c.Organization != "" && c.Enterprise != "" {
		return errors.New("--organization and --enterprise are mutually exclusive")
	}
	if c.DaysBack < 1 || c.DaysBack > 365 {
		return errors.New("--days-back must be between 1 and 365")
	}
	for _, t := range c.ReportTypes {
		if !validReportTypes[t] {
			return fmt.Errorf("invalid report type: %s", t)
		}
	}
	for _, s := range c.SeverityFilters {
		if !validSeverities[s] {
			return fmt.Errorf("invalid severity filter: %s", s)
		}
	}
	return nil
}

// TargetName returns the org or enterprise identifier.
func (c *Config) TargetName() string {
	if c.Organization != "" {
		return c.Organization
	}
	if c.Enterprise != "" {
		return c.Enterprise
	}
	return "unknown"
}

// TargetType returns the target type string.
func (c *Config) TargetType() string {
	if c.Organization != "" {
		return "organization"
	}
	if c.Enterprise != "" {
		return "enterprise"
	}
	return "unknown"
}

// SinceDate computes the earliest alert date to fetch.
func (c *Config) SinceDate() time.Time {
	return time.Now().UTC().AddDate(0, 0, -c.DaysBack)
}

// UntilDate returns now in UTC.
func (c *Config) UntilDate() time.Time {
	return time.Now().UTC()
}

// ReportFilename produces a deterministic report file name.
func (c *Config) ReportFilename(reportType string) string {
	timestamp := time.Now().UTC().Format("20060102_150405")
	return fmt.Sprintf("ghas_%s_%s_%s.html", reportType, c.TargetName(), timestamp)
}

// ReportPath joins OutputDir with the report filename.
func (c *Config) ReportPath(reportType string) string {
	return filepath.Join(c.OutputDir, c.ReportFilename(reportType))
}

// ResolveDataDir tries to locate the cwe_mappings folder when running as binary or checkout.
func (c *Config) ResolveDataDir() string {
	if c.DataDir != "" {
		return c.DataDir
	}
	if exePath, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exePath), "data", "cwe_mappings")
		if dirExists(candidate) {
			return candidate
		}
	}
	candidate := filepath.Join("data", "cwe_mappings")
	if dirExists(candidate) {
		return candidate
	}
	return ""
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// ParseCSVList splits comma separated strings into lowercase values.
func ParseCSVList(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(strings.ToLower(part))
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
