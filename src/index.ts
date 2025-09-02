import { getInput, setFailed, info } from './lib/log';
import { fetchAlerts } from './lib/ghas';
import { buildReports, Report } from './lib/reports';
import { buildMarkdownSummary } from './lib/markdown';
import { writeFileSync, mkdirSync } from 'fs';
import path from 'path';
import dotenv from 'dotenv';

dotenv.config();

async function run() {
  try {
    const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || process.env.INPUT_TOKEN;
    if (!token) {
      info('No GITHUB_TOKEN found in env or inputs; proceeding with empty alert set (add with: token: ${{ github.token }} in workflow).');
    }

    const owner = getInput('owner') || process.env.GITHUB_REPOSITORY?.split('/')[0];
    const repo = getInput('repo') || process.env.GITHUB_REPOSITORY?.split('/')[1];
    if (!owner || !repo) throw new Error('owner/repo not resolved');

    const frameworksRaw = getInput('frameworks') || process.env.FRAMEWORKS || 'owasp,sans,kev';
    const frameworks = frameworksRaw.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
    const since = getInput('since');
    const until = getInput('until');
    const includeDependabot = (getInput('include_dependabot') || 'true').toLowerCase() === 'true';
    const outputFormat = (getInput('output_format') || process.env.OUTPUT_FORMAT || 'json').toLowerCase(); // json | md | both
    const includeEmpty = (getInput('include_empty') || process.env.INCLUDE_EMPTY || 'true').toLowerCase() === 'true';

    let alerts: any[] = [];
    if (token) {
      info(`Fetching alerts for ${owner}/${repo}`);
      alerts = await fetchAlerts({ token, owner, repo, since, until, includeDependabot });
    } else {
      alerts = [];
    }

    info(`Building reports for frameworks: ${frameworks.join(', ')}`);
    const reports = await buildReports({ alerts, frameworks });

    const outDir = path.join(process.cwd(), 'reports');
    mkdirSync(outDir, { recursive: true });
    const writeJson = outputFormat === 'json' || outputFormat === 'both';
    const writeMd = outputFormat === 'md' || outputFormat === 'both';

    if (writeJson) {
      for (const r of reports) {
        if (!includeEmpty && r.type !== 'summary' && (r.matchedAlerts || 0) === 0) continue;
        const file = path.join(outDir, `${r.type}-report.json`);
        writeFileSync(file, JSON.stringify(r, null, 2));
        info(`Wrote ${file}`);
      }
    }

    if (writeMd) {
      const md = buildMarkdownSummary(reports, { includeEmpty, owner, repo });
      const file = path.join(outDir, 'summary.md');
      writeFileSync(file, md);
      info(`Wrote ${file}`);
      // Attempt to write to GitHub Actions job summary when running in Actions
      try {
        // Dynamically import @actions/core only if available
        const core = await import('@actions/core');
        if ((core as any).summary) {
          await (core as any).summary.addRaw(md, true).write();
          info('Appended markdown summary to job summary.');
        }
      } catch (e) {
        info('Job summary not available (likely local run).');
      }
    }
  } catch (err: any) {
    setFailed(err.message || String(err));
  }
}

run();

// markdown builder moved to lib/markdown
