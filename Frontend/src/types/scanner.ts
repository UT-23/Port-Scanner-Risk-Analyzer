export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';
export type PortStatus = 'open' | 'closed' | 'filtered';

export interface SecurityDetails {
  description: string;
  vulnerabilities: string[];
  attackVectors: string[];
  mitigations: string[];
}

export interface PortResult {
  port: number;
  service: string;
  status: PortStatus;
  riskLevel: RiskLevel;
  explanation: string;
  isCommonlyAttacked: boolean;
  responseTime?: number;        // milliseconds; only present when port is open
  securityDetails?: SecurityDetails; // full details; only present for open ports from real API
}

export interface ScanSummary {
  totalPorts: number;
  openPorts: number;
  closedPorts: number;
  filteredPorts: number;
  overallRisk: RiskLevel;
  riskExplanation: string;
}

export interface IPReputation {
  score: number; // 0-100
  isBlacklisted: boolean;
  blacklistSources: string[];
  lastSeen: string;
  country: string;
  isp: string;
  warnings: string[];
}

export interface ScanResult {
  target: string;
  targetType: 'ip' | 'domain';
  scanDate: string;
  duration: number;       // seconds
  ports: PortResult[];
  summary: ScanSummary;
  reputation: IPReputation;
  source?: 'api' | 'mock'; // tracks whether data came from real backend or mock
}

export interface ScanHistoryItem {
  id: string;
  target: string;
  targetType: 'ip' | 'domain';
  scanDate: string;
  overallRisk: RiskLevel;
  openPorts: number;
}
