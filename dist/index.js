"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const log_1 = require("./lib/log");
const ghas_1 = require("./lib/ghas");
const reports_1 = require("./lib/reports");
const markdown_1 = require("./lib/markdown");
const fs_1 = require("fs");
const path_1 = __importDefault(require("path"));
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
async function run() {
    try {
        const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || process.env.INPUT_TOKEN;
        if (!token) {
            (0, log_1.info)('No GITHUB_TOKEN found in env or inputs; proceeding with empty alert set (add with: token: ${{ github.token }} in workflow).');
        }
        const owner = (0, log_1.getInput)('owner') || process.env.GITHUB_REPOSITORY?.split('/')[0];
        const repo = (0, log_1.getInput)('repo') || process.env.GITHUB_REPOSITORY?.split('/')[1];
        if (!owner || !repo)
            throw new Error('owner/repo not resolved');
        const frameworksRaw = (0, log_1.getInput)('frameworks') || process.env.FRAMEWORKS || 'owasp,sans,kev';
        const frameworks = frameworksRaw.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
        const since = (0, log_1.getInput)('since');
        const until = (0, log_1.getInput)('until');
        const includeDependabot = ((0, log_1.getInput)('include_dependabot') || 'true').toLowerCase() === 'true';
        const outputFormat = ((0, log_1.getInput)('output_format') || process.env.OUTPUT_FORMAT || 'json').toLowerCase(); // json | md | both
        const includeEmpty = ((0, log_1.getInput)('include_empty') || process.env.INCLUDE_EMPTY || 'true').toLowerCase() === 'true';
        let alerts = [];
        if (token) {
            (0, log_1.info)(`Fetching alerts for ${owner}/${repo}`);
            alerts = await (0, ghas_1.fetchAlerts)({ token, owner, repo, since, until, includeDependabot });
        }
        else {
            alerts = [];
        }
        (0, log_1.info)(`Building reports for frameworks: ${frameworks.join(', ')}`);
        const reports = await (0, reports_1.buildReports)({ alerts, frameworks });
        const outDir = path_1.default.join(process.cwd(), 'reports');
        (0, fs_1.mkdirSync)(outDir, { recursive: true });
        const writeJson = outputFormat === 'json' || outputFormat === 'both';
        const writeMd = outputFormat === 'md' || outputFormat === 'both';
        if (writeJson) {
            for (const r of reports) {
                if (!includeEmpty && r.type !== 'summary' && (r.matchedAlerts || 0) === 0)
                    continue;
                const file = path_1.default.join(outDir, `${r.type}-report.json`);
                (0, fs_1.writeFileSync)(file, JSON.stringify(r, null, 2));
                (0, log_1.info)(`Wrote ${file}`);
            }
        }
        if (writeMd) {
            const md = (0, markdown_1.buildMarkdownSummary)(reports, { includeEmpty, owner, repo });
            const file = path_1.default.join(outDir, 'summary.md');
            (0, fs_1.writeFileSync)(file, md);
            (0, log_1.info)(`Wrote ${file}`);
            // Attempt to write to GitHub Actions job summary when running in Actions
            try {
                // Dynamically import @actions/core only if available
                const core = await Promise.resolve().then(() => __importStar(require('@actions/core')));
                if (core.summary) {
                    await core.summary.addRaw(md, true).write();
                    (0, log_1.info)('Appended markdown summary to job summary.');
                }
            }
            catch (e) {
                (0, log_1.info)('Job summary not available (likely local run).');
            }
        }
    }
    catch (err) {
        (0, log_1.setFailed)(err.message || String(err));
    }
}
run();
// markdown builder moved to lib/markdown
