export interface FetchAlertsParams {
    token: string;
    owner: string;
    repo: string;
    since?: string;
    until?: string;
    includeDependabot?: boolean;
}
export interface Alert {
    id: number | string;
    rule?: {
        id?: string;
        severity?: string;
        cwe?: string | string[];
    };
    created_at?: string;
    updated_at?: string;
    [k: string]: any;
}
export declare function fetchAlerts({ token, owner, repo, since, until, includeDependabot }: FetchAlertsParams): Promise<Alert[]>;
