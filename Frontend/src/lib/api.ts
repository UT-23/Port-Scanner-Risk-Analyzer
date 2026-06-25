/**
 * API service — connects the frontend to the Python FastAPI backend.
 * Falls back gracefully to mock data when the backend is unavailable.
 */

import { ScanResult, PortResult, RiskLevel, PortStatus } from '@/types/scanner';
import { generateMockScanResult } from '@/lib/mockData';

const API_BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:8000';

const COMMONLY_ATTACKED = new Set([
  20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
  443, 445, 587, 993, 995, 1433, 1521, 1723, 2049,
  3306, 3389, 5432, 5900, 6379, 8080, 8443,
]);

interface ApiPortResult {
  port: number;
  service: string;
  status: string;
  risk_level: string;
  response_time_ms: number | null;
  description: string;
  vulnerabilities: string[];
  attack_vectors: string[];
  mitigations: string[];
  details: string;
}

interface ApiIpInfo {
  country_code: string;
  country: string;
  city: string;
  region: string;
  org: string;
  asn: string;
  timezone: string;
  hostname: string;
  reputation_score: number;
  is_blacklisted: boolean;
}

interface ApiScanResponse {
  target: string;
  resolved_ip: string;
  scanned_at: string;
  duration_seconds: number;
  total_ports: number;
  results: ApiPortResult[];
  ip_info?: ApiIpInfo;
}

function deriveOverallRisk(ports: PortResult[]): { risk: RiskLevel; explanation: string } {
  const open = ports.filter((p) => p.status === 'open');
  const criticalCount = open.filter((p) => p.riskLevel === 'critical').length;
  const highCount = open.filter((p) => p.riskLevel === 'high').length;
  const mediumCount = open.filter((p) => p.riskLevel === 'medium').length;

  if (criticalCount > 0) {
    return {
      risk: 'critical',
      explanation: `${criticalCount} CRITICAL service${criticalCount > 1 ? 's' : ''} exposed. Immediate remediation required to prevent system compromise.`,
    };
  }
  if (highCount > 0) {
    return {
      risk: 'high',
      explanation: `${highCount} high-risk service${highCount > 1 ? 's' : ''} detected. Prompt action required to reduce attack surface.`,
    };
  }
  if (mediumCount > 2 || open.length > 5) {
    return {
      risk: 'medium',
      explanation: `${mediumCount} medium-risk service${mediumCount !== 1 ? 's' : ''} identified. Review exposed services and harden configurations.`,
    };
  }
  return {
    risk: 'low',
    explanation: 'System appears well-configured with minimal exposure. Continue monitoring for changes.',
  };
}

function transformApiResponse(apiData: ApiScanResponse, target: string): ScanResult {
  const isIP = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(target);

  const ports: PortResult[] = apiData.results.map((r) => ({
    port: r.port,
    service: r.service,
    status: r.status as PortStatus,
    riskLevel: r.risk_level as RiskLevel,
    responseTime: r.response_time_ms ?? undefined,
    explanation: r.details,
    isCommonlyAttacked: COMMONLY_ATTACKED.has(r.port),
    securityDetails: r.status === 'open'
      ? {
          description: r.description,
          vulnerabilities: r.vulnerabilities,
          attackVectors: r.attack_vectors,
          mitigations: r.mitigations,
        }
      : undefined,
  }));

  const open = ports.filter((p) => p.status === 'open');
  const { risk, explanation } = deriveOverallRisk(ports);

  // Build reputation from real ip_info returned by the backend (ipinfo.io)
  const info = apiData.ip_info;
  const score = info?.reputation_score ?? 100;
  const isBlacklisted = info?.is_blacklisted ?? false;

  const locationParts = [info?.city, info?.region, info?.country].filter(
    (v) => v && v !== 'Unknown',
  );
  const locationStr = locationParts.join(', ') || 'Unknown';

  const warnings: string[] = [];
  if (isBlacklisted) warnings.push('Host reputation score is below safe threshold');
  if (info?.hostname && info.hostname !== apiData.resolved_ip) {
    warnings.push(`Hostname: ${info.hostname}`);
  }
  if (info?.asn) warnings.push(`Network: ${info.asn}`);

  return {
    target: apiData.target,
    targetType: isIP ? 'ip' : 'domain',
    scanDate: apiData.scanned_at,
    duration: apiData.duration_seconds,
    ports,
    summary: {
      totalPorts: ports.length,
      openPorts: open.length,
      closedPorts: ports.filter((p) => p.status === 'closed').length,
      filteredPorts: ports.filter((p) => p.status === 'filtered').length,
      overallRisk: risk,
      riskExplanation: explanation,
    },
    reputation: {
      score,
      isBlacklisted,
      blacklistSources: isBlacklisted ? ['Risk Score'] : [],
      lastSeen: new Date().toISOString(),
      country: locationStr,
      isp: info?.org ?? 'Unknown',
      warnings,
    },
    source: 'api',
  };
}

export interface ScanResponse {
  result: ScanResult;
  source: 'api' | 'mock';
  error?: string;
}

/**
 * Scan a target IP or domain.
 * Tries the real backend first; falls back to mock data if unavailable.
 */
export async function scanTarget(target: string): Promise<ScanResponse> {
  try {
    const url = `${API_BASE}/scan?target=${encodeURIComponent(target)}`;
    const response = await fetch(url, {
      signal: AbortSignal.timeout(90_000), // 90s — allow slow filtered-port scans
    });

    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      const detail: string = body.detail ?? `HTTP ${response.status}`;
      // 400 means the target itself was rejected — surface the error rather than falling back
      if (response.status === 400) {
        throw new Error(detail);
      }
      throw new Error(detail);
    }

    const data: ApiScanResponse = await response.json();
    return { result: transformApiResponse(data, target), source: 'api' };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);

    // Re-throw validation errors so the UI can display them directly
    if (message.startsWith('Invalid target') || message.startsWith('Cannot resolve')) {
      throw new Error(message);
    }

    // For connectivity failures, fall back to mock data
    const result = generateMockScanResult(target);
    return {
      result: { ...result, source: 'mock' },
      source: 'mock',
      error: message,
    };
  }
}

/** Check whether the backend is reachable. */
export async function checkBackendHealth(): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/health`, {
      signal: AbortSignal.timeout(3_000),
    });
    return res.ok;
  } catch {
    return false;
  }
}
