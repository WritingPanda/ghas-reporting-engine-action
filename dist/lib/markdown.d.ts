import { Report } from './reports';
export interface MarkdownOptions {
    includeEmpty?: boolean;
    owner?: string;
    repo?: string;
    includeAlertDetails?: boolean;
}
export declare function buildMarkdownSummary(reports: Report[], opts?: MarkdownOptions): string;
