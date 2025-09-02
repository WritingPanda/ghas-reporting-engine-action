import { Alert } from './ghas';
export interface Report {
    type: string;
    generatedAt: string;
    totalAlerts: number;
    matchedAlerts?: number;
    matchedCWEs?: number;
    totalFrameworkCWEs?: number;
    severityBreakdown?: {
        [severity: string]: number;
    };
    findings: any[];
    unmatchedFrameworkCWEs?: string[];
}
export interface BuildReportsParams {
    alerts: Alert[];
    frameworks: string[];
}
export declare function buildReports({ alerts, frameworks }: BuildReportsParams): Promise<Report[]>;
