package githubclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/WritingPanda/ghas-reporting-engine-action/internal/config"
	"github.com/WritingPanda/ghas-reporting-engine-action/internal/models"
)

// Client wraps GitHub REST API calls used by the CLI.
type Client struct {
	cfg    config.Config
	http   *http.Client
	logger *slog.Logger
}

// New creates a GitHub client with retry-aware HTTP settings.
func New(cfg config.Config, logger *slog.Logger) *Client {
	return &Client{
		cfg:    cfg,
		http:   &http.Client{Timeout: cfg.RequestTimeout},
		logger: logger,
	}
}

// FetchAlerts retrieves alerts for the configured organization or enterprise.
func (c *Client) FetchAlerts(ctx context.Context) ([]models.Alert, error) {
	if c.cfg.Organization != "" {
		return c.fetchPaged(ctx, fmt.Sprintf("/orgs/%s/code-scanning/alerts", url.PathEscape(c.cfg.Organization)))
	}
	if c.cfg.Enterprise != "" {
		return c.fetchPaged(ctx, fmt.Sprintf("/enterprises/%s/code-scanning/alerts", url.PathEscape(c.cfg.Enterprise)))
	}
	return nil, errors.New("neither organization nor enterprise provided")
}

func (c *Client) fetchPaged(ctx context.Context, endpoint string) ([]models.Alert, error) {
	perPage := 100
	page := 1
	alerts := []models.Alert{}

	for {
		q := url.Values{}
		q.Set("per_page", fmt.Sprintf("%d", perPage))
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("sort", "created")
		q.Set("direction", "desc")
		states := []string{"open"}
		if c.cfg.IncludeDismissed {
			states = append(states, "dismissed")
		}
		if c.cfg.IncludeFixed {
			states = append(states, "fixed")
		}
		q.Set("state", strings.Join(states, ","))

		fullURL := c.cfg.APIBaseURL + endpoint + "?" + q.Encode()
		respBody, status, err := c.doRequest(ctx, fullURL)
		if err != nil {
			return nil, err
		}
		if status == http.StatusNotFound && c.cfg.Enterprise != "" {
			// Enterprise endpoint unavailable with token permissions.
			return alerts, fmt.Errorf("enterprise alerts endpoint unavailable (404); ensure token has required scope")
		}

		batch := []models.Alert{}
		if err := json.Unmarshal(respBody, &batch); err != nil {
			return nil, fmt.Errorf("decode alerts: %w", err)
		}

		alerts = append(alerts, batch...)
		if len(batch) < perPage {
			break
		}
		page++
	}

	// Filter by date window.
	filtered := make([]models.Alert, 0, len(alerts))
	for _, a := range alerts {
		if a.CreatedAt.Before(c.cfg.SinceDate()) || a.CreatedAt.After(c.cfg.UntilDate()) {
			continue
		}
		filtered = append(filtered, a)
	}

	// Apply severity filter if provided.
	if len(c.cfg.SeverityFilters) > 0 {
		allowed := map[string]struct{}{}
		for _, s := range c.cfg.SeverityFilters {
			allowed[s] = struct{}{}
		}
		tmp := filtered[:0]
		for _, a := range filtered {
			if _, ok := allowed[a.Severity()]; ok {
				tmp = append(tmp, a)
			}
		}
		filtered = tmp
	}

	c.logger.Info("fetched alerts", "count", len(filtered))
	return filtered, nil
}

func (c *Client) doRequest(ctx context.Context, fullURL string) ([]byte, int, error) {
	var lastErr error
	for attempt := 0; attempt <= c.cfg.MaxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("Authorization", "token "+c.cfg.GitHubToken)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("User-Agent", "ghas-reporting-engine-go")

		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
		} else {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return body, resp.StatusCode, nil
			}
			if resp.StatusCode == http.StatusTooManyRequests && attempt < c.cfg.MaxRetries {
				time.Sleep(time.Duration(attempt+1) * time.Second)
				continue
			}
			if resp.StatusCode >= 500 && attempt < c.cfg.MaxRetries {
				time.Sleep(time.Duration(attempt+1) * time.Second)
				continue
			}
			return nil, resp.StatusCode, fmt.Errorf("github api error: %s", resp.Status)
		}
		time.Sleep(time.Duration(attempt+1) * time.Second)
	}
	return nil, 0, fmt.Errorf("request failed after retries: %w", lastErr)
}
