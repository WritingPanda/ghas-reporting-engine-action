export interface FrameworkData {
    id: string;
    name: string;
    cwes: Set<string>;
    sourcePath: string;
}
export declare function loadFramework(id: string): FrameworkData | undefined;
export declare function loadFrameworks(ids: string[]): FrameworkData[];
export interface AlertLike {
    id: number | string;
    rule?: {
        id?: string;
        severity?: string;
        cwe?: string | string[];
    };
    [k: string]: any;
}
export interface FrameworkMatchResult {
    framework: string;
    matchedAlerts: Set<number | string>;
    matchedCWEs: Set<string>;
}
export declare function extractAlertCWEs(alert: AlertLike): string[];
export declare function matchFrameworks(alerts: AlertLike[], frameworks: FrameworkData[]): Record<string, FrameworkMatchResult>;
