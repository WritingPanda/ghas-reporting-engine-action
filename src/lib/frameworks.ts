import { readFileSync } from 'fs';
import path from 'path';

export interface FrameworkData {
  id: string;              // owasp | sans | kev
  name: string;            // Human friendly
  cwes: Set<string>;       // Canonical CWE IDs (CWE-###)
  sourcePath: string;      // Relative path to instructions file
}

function extractCWEs(markdown: string): Set<string> {
  const set = new Set<string>();
  const regex = /CWE-\d{1,4}/g; // basic CWE pattern
  let m: RegExpExecArray | null;
  while ((m = regex.exec(markdown)) !== null) {
    set.add(m[0]);
  }
  return set;
}

const cache: Record<string, FrameworkData> = {};

const FRAMEWORK_SPECS: Array<{ id: string; name: string; file: string }> = [
  { id: 'owasp', name: 'OWASP Top 10 (2021)', file: '.github/instructions/owasptop10.instructions.md' },
  { id: 'sans', name: 'SANS Top 25', file: '.github/instructions/sanstop25.instructions.md' },
  { id: 'kev', name: 'MITRE Top 10 KEV CWE', file: '.github/instructions/MITREKEV.instructions.md' }
];

export function loadFramework(id: string): FrameworkData | undefined {
  id = id.toLowerCase();
  if (cache[id]) return cache[id];
  const spec = FRAMEWORK_SPECS.find(f => f.id === id);
  if (!spec) return undefined;
  try {
    const filePath = path.join(process.cwd(), spec.file);
    const content = readFileSync(filePath, 'utf8');
    const cwes = extractCWEs(content);
    const data: FrameworkData = { id: spec.id, name: spec.name, cwes, sourcePath: spec.file };
    cache[id] = data;
    return data;
  } catch (e) {
    return undefined;
  }
}

export function loadFrameworks(ids: string[]): FrameworkData[] {
  const unique = Array.from(new Set(ids.map(i => i.toLowerCase())));
  return unique.map(loadFramework).filter((f): f is FrameworkData => !!f);
}

export interface AlertLike {
  id: number | string;
  rule?: { id?: string; severity?: string; cwe?: string | string[] };
  [k: string]: any;
}

export interface FrameworkMatchResult {
  framework: string;
  matchedAlerts: Set<number | string>;
  matchedCWEs: Set<string>;
}

export function extractAlertCWEs(alert: AlertLike): string[] {
  const set = new Set<string>();
  const pushFromString = (s: string) => {
    // Match canonical CWE-### AND permissive patterns like external/cwe/cwe-79 or cwe_89
    const regex = /cwe[-_:\/ ]?(\d{1,4})/gi;
    let m: RegExpExecArray | null;
    while ((m = regex.exec(s)) !== null) {
      const num = m[1].replace(/^0+/, '') || m[1];
      set.add(`CWE-${num}`);
    }
  };
  const add = (val?: string | string[]) => {
    if (!val) return;
    if (Array.isArray(val)) val.forEach(v => add(v));
    else pushFromString(val);
  };
  add(alert.rule?.cwe as any);
  add(alert.rule?.id);
  if (Array.isArray((alert as any).rule?.tags)) (alert as any).rule.tags.forEach((t: string) => add(t));
  // Supplemental mapping based on ruleId patterns when no CWE present
  if (set.size === 0 && alert.rule?.id) {
    const supplemental = mapRuleIdToCWEs(alert.rule.id);
    supplemental.forEach(c => set.add(c));
  }
  return Array.from(set);
}

// Known supplemental ruleId -> CWE mappings (primarily CodeQL java/* & generic patterns)
const RULE_CWE_MAP: Record<string, string[]> = {
  'xss': ['CWE-79'],
  'sql-injection': ['CWE-89'],
  'command-line-injection': ['CWE-78'],
  'path-injection': ['CWE-22'],
  'ssrf': ['CWE-918'],
  'insecure-cookie': ['CWE-614'],
  'weak-cryptographic-algorithm': ['CWE-327'],
  'hardcoded-credential-api-call': ['CWE-798', 'CWE-259'],
  'log-injection': ['CWE-117'],
  'http-response-splitting': ['CWE-113'],
  'stack-trace-exposure': ['CWE-209'],
  'unsafe-cert-trust': ['CWE-295'],
  'rsa-without-oaep': ['CWE-780']
};

function mapRuleIdToCWEs(ruleId: string): string[] {
  const lower = ruleId.toLowerCase();
  if (RULE_CWE_MAP[lower]) return RULE_CWE_MAP[lower];
  const last = lower.split('/').pop() || lower;
  if (RULE_CWE_MAP[last]) return RULE_CWE_MAP[last];
  return [];
}

export function matchFrameworks(alerts: AlertLike[], frameworks: FrameworkData[]): Record<string, FrameworkMatchResult> {
  const results: Record<string, FrameworkMatchResult> = {};
  for (const fw of frameworks) {
    results[fw.id] = { framework: fw.id, matchedAlerts: new Set(), matchedCWEs: new Set() };
  }
  for (const alert of alerts) {
    const cwes = extractAlertCWEs(alert);
    for (const fw of frameworks) {
      for (const cwe of cwes) {
        if (fw.cwes.has(cwe)) {
          results[fw.id].matchedAlerts.add(alert.id);
          results[fw.id].matchedCWEs.add(cwe);
        }
      }
    }
  }
  return results;
}
