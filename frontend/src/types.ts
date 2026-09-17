export type ClaimType = 'cve' | 'mitre_technique' | 'ioc' | 'sigma_rule' | 'cvss_score' | 'command';
export type ValidationStatus = 'EXISTS' | 'NOT_FOUND' | 'MISMATCH' | 'UNCHECKED' | 'ERROR';
export type VerdictType = 'PASS' | 'FLAG' | 'BLOCK';

export interface Claim {
  type: ClaimType;
  value: string;
  raw_span: string;
  context_hint?: string;
  expected_meta?: Record<string, any>;
}

export interface ValidationDetails {
  status: ValidationStatus;
  source: string;
  details: Record<string, any>;
  message?: string;
}

export interface ClaimResult {
  claim: Claim;
  deterministic: ValidationDetails;
  consistency_score: number;
  faithfulness_score: number;
  risk_score: number;
  verdict: VerdictType;
  evidence_id: string;
  citations: string[];
}

export interface AnalysisSummary {
  analysis_id: string;
  timestamp: string;
  total_claims: number;
  pass_count: number;
  flag_count: number;
  block_count: number;
  overall_risk_score: number;
  verdict: VerdictType;
  claims: ClaimResult[];
}

export interface HistoryItem {
  id: string;
  timestamp: string;
  text_snippet: string;
  total_claims: number;
  pass_count: number;
  flag_count: number;
  block_count: number;
  overall_risk_score: number;
  verdict: VerdictType;
}

export interface HealthStatus {
  status: string;
  app: string;
  version: string;
  services: {
    groq_api: { configured: boolean; model: string };
    ollama: { reachable: boolean; url: string; model: string };
    nvd_api: { key_configured: boolean; cache_items: number };
    mitre_database: { techniques_indexed: number };
    sigma_database: { rules_indexed: number };
    abuseipdb: { configured: boolean };
    virustotal: { configured: boolean };
  };
}
