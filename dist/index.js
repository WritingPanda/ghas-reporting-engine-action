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
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.initializeGitHubClient = initializeGitHubClient;
exports.main = main;
const clients_1 = require("./clients");
const utils_1 = require("./utils");
async function initializeGitHubClient(token, githubUrl = 'https://api.github.com') {
    const config = {
        token,
        userAgent: 'GHAS-Reporting-Engine/1.0.0',
        baseUrl: githubUrl,
    };
    const client = new clients_1.GitHubClient(config);
    const isConnected = await client.testConnection();
    if (!isConnected) {
        throw new Error('Failed to connect to GitHub API. Please check your token and URL.');
    }
    return client;
}
async function fetchAlerts(client, options) {
    const target = {
        type: options.targetType,
        name: options.target,
    };
    utils_1.logger.info(`Fetching alerts for ${options.targetType}: ${options.target}`);
    let alerts = [];
    if (options.targetType === 'organization') {
        alerts = await client.fetchOrganizationAlerts(target);
    }
    else {
        throw new Error('Enterprise alert fetching is not yet implemented');
    }
    if (options.timePeriod.days || options.timePeriod.startDate || options.timePeriod.endDate) {
        alerts = filterAlertsByTimePeriod(alerts, options.timePeriod);
    }
    utils_1.logger.info(`Found ${alerts.length} alerts matching criteria`);
    return alerts;
}
function filterAlertsByTimePeriod(alerts, timePeriod) {
    const now = new Date();
    let startDate = null;
    let endDate = null;
    if (timePeriod.days) {
        startDate = new Date(now.getTime() - (timePeriod.days * 24 * 60 * 60 * 1000));
    }
    if (timePeriod.startDate) {
        startDate = new Date(timePeriod.startDate);
    }
    if (timePeriod.endDate) {
        endDate = new Date(timePeriod.endDate);
    }
    return alerts.filter(alert => {
        const alertDate = new Date(alert.alert.created_at);
        if (startDate && alertDate < startDate) {
            return false;
        }
        if (endDate && alertDate > endDate) {
            return false;
        }
        return true;
    });
}
async function generateReport(alerts, options) {
    const reportData = {
        generatedAt: new Date().toISOString(),
        target: {
            type: options.targetType,
            name: options.target,
        },
        frameworks: options.frameworks,
        timePeriod: options.timePeriod,
        totalAlerts: alerts.length,
        alerts: alerts,
    };
    switch (options.output) {
        case 'json':
            return JSON.stringify(reportData, null, 2);
        case 'markdown':
            return generateMarkdownReport(reportData);
        case 'html':
            return generateHTMLReport(reportData);
        default:
            throw new Error(`Unsupported output format: ${options.output}`);
    }
}
function generateMarkdownReport(data) {
    return `# GHAS Security Report

**Generated:** ${data.generatedAt}
**Target:** ${data.target.type} - ${data.target.name}
**Frameworks:** ${data.frameworks.join(', ')}
**Total Alerts:** ${data.totalAlerts}

## Summary

This report contains ${data.totalAlerts} security alerts from GitHub Advanced Security.

_Note: Detailed markdown report generation will be implemented in the next phase._
`;
}
function generateHTMLReport(data) {
    return `<!DOCTYPE html>
<html>
<head>
    <title>GHAS Security Report</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { border-bottom: 2px solid #333; margin-bottom: 20px; }
        .summary { background: #f5f5f5; padding: 15px; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>GHAS Security Report</h1>
        <p><strong>Generated:</strong> ${data.generatedAt}</p>
        <p><strong>Target:</strong> ${data.target.type} - ${data.target.name}</p>
        <p><strong>Frameworks:</strong> ${data.frameworks.join(', ')}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p>Total Alerts: <strong>${data.totalAlerts}</strong></p>
    </div>
    
    <p><em>Note: Detailed HTML report generation will be implemented in the next phase.</em></p>
</body>
</html>`;
}
async function outputReport(report, options) {
    if (options.outputFile) {
        const fs = await Promise.resolve().then(() => __importStar(require('fs')));
        await fs.promises.writeFile(options.outputFile, report, 'utf8');
        utils_1.logger.info(`Report saved to: ${options.outputFile}`);
    }
    else {
        console.log(report);
    }
    if (options.isAction && process.env.GITHUB_STEP_SUMMARY) {
        const fs = await Promise.resolve().then(() => __importStar(require('fs')));
        let summaryContent = report;
        if (options.output !== 'markdown') {
            summaryContent = `# GHAS Security Report\n\nGenerated at: ${new Date().toISOString()}\n\nSee attached artifact for full report.`;
        }
        await fs.promises.appendFile(process.env.GITHUB_STEP_SUMMARY, summaryContent, 'utf8');
        utils_1.logger.info('Report added to GitHub Action summary');
    }
}
async function main() {
    try {
        const options = (0, utils_1.parseCLIArguments)();
        utils_1.logger.info('Starting GHAS Reporting Engine', {
            target: `${options.targetType}:${options.target}`,
            frameworks: options.frameworks,
            output: options.output,
            isAction: options.isAction,
        });
        const client = await initializeGitHubClient(options.token, options.githubUrl);
        const rateLimit = await client.getRateLimit();
        utils_1.logger.info('GitHub API Rate Limit', {
            remaining: rateLimit.remaining,
            limit: rateLimit.limit,
            reset: rateLimit.reset.toISOString(),
        });
        const alerts = await fetchAlerts(client, options);
        const report = await generateReport(alerts, options);
        await outputReport(report, options);
        utils_1.logger.info('GHAS Reporting Engine completed successfully');
    }
    catch (error) {
        utils_1.logger.error('GHAS Reporting Engine failed', error);
        process.exit(1);
    }
}
__exportStar(require("./types"), exports);
__exportStar(require("./clients"), exports);
__exportStar(require("./utils"), exports);
if (require.main === module) {
    main().catch((error) => {
        utils_1.logger.error('Unhandled error in main', error);
        process.exit(1);
    });
}
//# sourceMappingURL=index.js.map