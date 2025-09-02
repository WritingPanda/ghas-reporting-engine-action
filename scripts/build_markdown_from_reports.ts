import { readFileSync, writeFileSync } from 'fs';
import path from 'path';
import { buildMarkdownSummary } from '../src/lib/markdown';
import { Report } from '../src/lib/reports';

// Simple utility to load all *-report.json in ./reports and build summary.md
function loadReports(dir: string): Report[] {
  const fs = require('fs');
  const files: string[] = fs.readdirSync(dir).filter((f: string) => f.endsWith('-report.json'));
  const reports: Report[] = [];
  for (const file of files) {
    const full = path.join(dir, file);
    const content = readFileSync(full, 'utf8');
    try {
      const json = JSON.parse(content);
      reports.push(json);
    } catch (e) {
      console.error(`Failed to parse ${file}:`, e);
    }
  }
  return reports;
}

function main() {
  const reportsDir = path.join(process.cwd(), 'reports');
  const reports = loadReports(reportsDir);
  if (!reports.length) {
    console.error('No report JSON files found in reports/.');
    process.exit(1);
  }
  const md = buildMarkdownSummary(reports, { includeEmpty: true });
  const out = path.join(reportsDir, 'summary-from-json.md');
  writeFileSync(out, md);
  console.log(`Wrote ${out}`);
}

main();
