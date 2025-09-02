"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.loadFramework = loadFramework;
exports.loadFrameworks = loadFrameworks;
exports.extractAlertCWEs = extractAlertCWEs;
exports.matchFrameworks = matchFrameworks;
const fs_1 = require("fs");
const path_1 = __importDefault(require("path"));
function extractCWEs(markdown) {
    const set = new Set();
    const regex = /CWE-\d{1,4}/g; // basic CWE pattern
    let m;
    while ((m = regex.exec(markdown)) !== null) {
        set.add(m[0]);
    }
    return set;
}
const cache = {};
const FRAMEWORK_SPECS = [
    { id: 'owasp', name: 'OWASP Top 10 (2021)', file: '.github/instructions/owasptop10.instructions.md' },
    { id: 'sans', name: 'SANS Top 25', file: '.github/instructions/sanstop25.instructions.md' },
    { id: 'kev', name: 'MITRE Top 10 KEV CWE', file: '.github/instructions/MITREKEV.instructions.md' }
];
function loadFramework(id) {
    id = id.toLowerCase();
    if (cache[id])
        return cache[id];
    const spec = FRAMEWORK_SPECS.find(f => f.id === id);
    if (!spec)
        return undefined;
    try {
        const filePath = path_1.default.join(process.cwd(), spec.file);
        const content = (0, fs_1.readFileSync)(filePath, 'utf8');
        const cwes = extractCWEs(content);
        const data = { id: spec.id, name: spec.name, cwes, sourcePath: spec.file };
        cache[id] = data;
        return data;
    }
    catch (e) {
        return undefined;
    }
}
function loadFrameworks(ids) {
    const unique = Array.from(new Set(ids.map(i => i.toLowerCase())));
    return unique.map(loadFramework).filter((f) => !!f);
}
function extractAlertCWEs(alert) {
    const set = new Set();
    const pushFromString = (s) => {
        // Match canonical CWE-### AND permissive patterns like external/cwe/cwe-79 or cwe_89
        const regex = /cwe[-_:\/ ]?(\d{1,4})/gi;
        let m;
        while ((m = regex.exec(s)) !== null) {
            const num = m[1].replace(/^0+/, '') || m[1];
            set.add(`CWE-${num}`);
        }
    };
    const add = (val) => {
        if (!val)
            return;
        if (Array.isArray(val))
            val.forEach(v => add(v));
        else
            pushFromString(val);
    };
    add(alert.rule?.cwe);
    add(alert.rule?.id);
    if (Array.isArray(alert.rule?.tags))
        alert.rule.tags.forEach((t) => add(t));
    // Supplemental mapping based on ruleId patterns when no CWE present
    if (set.size === 0 && alert.rule?.id) {
        const supplemental = mapRuleIdToCWEs(alert.rule.id);
        supplemental.forEach(c => set.add(c));
    }
    return Array.from(set);
}
// Known supplemental ruleId -> CWE mappings (primarily CodeQL java/* & generic patterns)
const RULE_CWE_MAP = {
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
function mapRuleIdToCWEs(ruleId) {
    const lower = ruleId.toLowerCase();
    if (RULE_CWE_MAP[lower])
        return RULE_CWE_MAP[lower];
    const last = lower.split('/').pop() || lower;
    if (RULE_CWE_MAP[last])
        return RULE_CWE_MAP[last];
    return [];
}
function matchFrameworks(alerts, frameworks) {
    const results = {};
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
