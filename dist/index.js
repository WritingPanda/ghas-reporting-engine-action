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
Object.defineProperty(exports, "__esModule", { value: true });
exports.run = run;
const core = __importStar(require("@actions/core"));
const ReportingEngine_1 = require("./ReportingEngine");
const Logger_1 = require("./utils/Logger");
/**
 * Main entry point for the GHAS Reporting Engine GitHub Action
 */
async function run() {
    const logger = new Logger_1.Logger();
    try {
        logger.info('Starting GHAS Reporting Engine...');
        // Get input parameters
        const token = process.env.GITHUB_TOKEN || core.getInput('token');
        const organization = core.getInput('organization');
        const enterprise = core.getInput('enterprise');
        const frameworks = core.getInput('frameworks') || 'owasp,sans,kev';
        const outputFormat = core.getInput('output_format') || 'markdown';
        const includeEmpty = core.getBooleanInput('include_empty') || false;
        const sinceDate = core.getInput('since_date');
        const untilDate = core.getInput('until_date');
        const repositories = core.getInput('repositories');
        // Validate inputs
        if (!token) {
            throw new Error('GitHub token is required. Set GITHUB_TOKEN environment variable or token input.');
        }
        if (!organization && !enterprise) {
            throw new Error('Either organization or enterprise must be specified.');
        }
        if (organization && enterprise) {
            throw new Error('Cannot specify both organization and enterprise. Choose one.');
        }
        logger.info(`Target: ${organization ? `Organization: ${organization}` : `Enterprise: ${enterprise}`}`);
        logger.info(`Frameworks: ${frameworks}`);
        logger.info(`Output format: ${outputFormat}`);
        // Initialize and run the reporting engine
        const engine = new ReportingEngine_1.ReportingEngine({
            token,
            organization,
            enterprise,
            frameworks: frameworks.split(',').map(f => f.trim()),
            outputFormat,
            includeEmpty,
            sinceDate,
            untilDate,
            repositories: repositories ? repositories.split(',').map(r => r.trim()) : undefined,
            logger
        });
        const reports = await engine.generateReports();
        // Set outputs for the action
        core.setOutput('reports_generated', reports.length);
        core.setOutput('report_summary', engine.getSummaryText());
        // Add summary to job summary
        await core.summary
            .addHeading('GHAS Framework Compliance Report')
            .addRaw(engine.getSummaryText())
            .write();
        logger.info(`Successfully generated ${reports.length} report(s)`);
    }
    catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.error(`Action failed: ${errorMessage}`);
        core.setFailed(errorMessage);
    }
}
// Only run if this file is being executed directly (not imported)
if (require.main === module) {
    run();
}
