package runtime

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/WritingPanda/ghas-reporting-engine-action/internal/analyzer"
	"github.com/WritingPanda/ghas-reporting-engine-action/internal/config"
	githubclient "github.com/WritingPanda/ghas-reporting-engine-action/internal/github"
	"github.com/WritingPanda/ghas-reporting-engine-action/internal/mapping"
	"github.com/WritingPanda/ghas-reporting-engine-action/internal/reporters"
)

// Execute orchestrates fetch -> analyze -> report.
func Execute(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	if err := os.MkdirAll(cfg.OutputDir, 0o755); err != nil {
		return err
	}

	mapper, err := mapping.NewMapper(cfg.ResolveDataDir())
	if err != nil {
		return err
	}
	analyzerSvc := analyzer.New(cfg, mapper)
	client := githubclient.New(cfg, logger)

	alerts, err := client.FetchAlerts(ctx)
	if err != nil {
		return err
	}
	if len(alerts) == 0 {
		logger.Warn("no alerts returned")
	}

	analysis := analyzerSvc.Analyze(alerts)

	meta := map[string]any{
		"Target":     cfg.TargetName(),
		"TargetType": cfg.TargetType(),
		"Framework":  "",
		"DateRange":  fmt.Sprintf("%s to %s", cfg.SinceDate().Format("2006-01-02"), cfg.UntilDate().Format("2006-01-02")),
	}

	for _, framework := range cfg.ReportTypes {
		meta["Framework"] = framework
		path := cfg.ReportPath(framework)
		if err := reporters.WriteHTML(analysis, framework, alerts, meta, path, reporters.ReportTemplate); err != nil {
			return err
		}
		logger.Info("report generated", "path", filepath.Clean(path))
	}

	return nil
}
