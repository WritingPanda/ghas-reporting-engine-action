package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/WritingPanda/ghas-reporting-engine-action/internal/config"
	"github.com/WritingPanda/ghas-reporting-engine-action/internal/logging"
	"github.com/WritingPanda/ghas-reporting-engine-action/internal/runtime"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	cfg := config.DefaultConfig()

	cmd := &cobra.Command{
		Use:   "ghas-report",
		Short: "Generate GHAS compliance reports (OWASP, SANS, MITRE)",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := logging.Setup(cfg.LogLevel)
			if err := cfg.Validate(); err != nil {
				return err
			}
			return runtime.Execute(cmd.Context(), cfg, logger)
		},
	}

	cmd.Flags().StringVar(&cfg.GitHubToken, "token", os.Getenv("GITHUB_TOKEN"), "GitHub token (env: GITHUB_TOKEN)")
	cmd.Flags().StringVar(&cfg.Organization, "organization", "", "GitHub organization name")
	cmd.Flags().StringVar(&cfg.Enterprise, "enterprise", "", "GitHub enterprise name")
	cmd.Flags().StringSliceVar(&cfg.ReportTypes, "report-types", cfg.ReportTypes, "Comma separated report types: owasp,sans,mitre")
	cmd.Flags().IntVar(&cfg.DaysBack, "days-back", cfg.DaysBack, "Number of days to look back for alerts")
	cmd.Flags().StringVar(&cfg.OutputDir, "output-dir", cfg.OutputDir, "Directory for report output")
	cmd.Flags().StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "Log level (DEBUG, INFO, WARN, ERROR)")
	cmd.Flags().BoolVar(&cfg.IncludeDismissed, "include-dismissed", cfg.IncludeDismissed, "Include dismissed alerts")
	cmd.Flags().BoolVar(&cfg.IncludeFixed, "include-fixed", cfg.IncludeFixed, "Include fixed alerts")
	cmd.Flags().StringSliceVar(&cfg.SeverityFilters, "severity-filter", cfg.SeverityFilters, "Filter severities: critical,high,medium,low")
	cmd.Flags().StringVar(&cfg.APIBaseURL, "api-base-url", cfg.APIBaseURL, "Override GitHub API base URL")
	cmd.Flags().IntVar(&cfg.MaxRetries, "max-retries", cfg.MaxRetries, "Maximum retry attempts for API calls")
	cmd.Flags().DurationVar(&cfg.RequestTimeout, "request-timeout", cfg.RequestTimeout, "Timeout per API request")
	cmd.Flags().StringVar(&cfg.DataDir, "data-dir", cfg.DataDir, "Optional path to cwe_mappings directory")

	return cmd
}
