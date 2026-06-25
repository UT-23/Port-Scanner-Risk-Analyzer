import { ScanResult, ScanHistoryItem, PortResult, RiskLevel } from '@/types/scanner';

const commonlyAttackedPorts = new Set([
  20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
  443, 445, 587, 993, 995, 1433, 1521, 1723, 2049,
  3306, 3389, 5432, 5900, 6379, 8080, 8443,
]);

const portServices: Record<number, string> = {
  20: 'FTP-Data',
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  80: 'HTTP',
  110: 'POP3',
  111: 'RPCBind',
  135: 'MS-RPC',
  139: 'NetBIOS',
  143: 'IMAP',
  443: 'HTTPS',
  445: 'SMB',
  587: 'SMTP-TLS',
  993: 'IMAPS',
  995: 'POP3S',
  1433: 'MSSQL',
  1521: 'Oracle-DB',
  1723: 'PPTP',
  2049: 'NFS',
  3306: 'MySQL',
  3389: 'RDP',
  5432: 'PostgreSQL',
  5900: 'VNC',
  6379: 'Redis',
  8080: 'HTTP-Alt',
  8443: 'HTTPS-Alt',
};

// Risk profiles for open ports by service
const openRiskProfiles: Record<number, RiskLevel> = {
  20: 'high',
  21: 'critical',
  22: 'medium',
  23: 'critical',
  25: 'medium',
  53: 'medium',
  80: 'medium',
  110: 'high',
  111: 'high',
  135: 'critical',
  139: 'critical',
  143: 'high',
  443: 'low',
  445: 'critical',
  587: 'medium',
  993: 'low',
  995: 'low',
  1433: 'critical',
  1521: 'critical',
  1723: 'critical',
  2049: 'critical',
  3306: 'critical',
  3389: 'critical',
  5432: 'critical',
  5900: 'critical',
  6379: 'critical',
  8080: 'medium',
  8443: 'medium',
};

const portExplanations: Record<number, { open: string; closed: string; filtered: string }> = {
  21: {
    open: 'FTP transmits credentials in plaintext. Critical security risk if internet-facing.',
    closed: 'FTP port is closed. No file transfer service is listening.',
    filtered: 'FTP port is filtered by firewall. Inconclusive result.',
  },
  22: {
    open: 'SSH detected. Ensure password authentication is disabled; use key-based auth only.',
    closed: 'SSH port is closed. Remote access via SSH is not available.',
    filtered: 'SSH port is filtered. May be behind a firewall or VPN gateway.',
  },
  23: {
    open: 'Telnet is critically insecure — transmits everything in plaintext. Disable immediately.',
    closed: 'Telnet port is closed. Good — Telnet should never be used.',
    filtered: 'Telnet port appears filtered. Verify it is completely disabled.',
  },
  80: {
    open: 'HTTP lacks encryption. Sensitive data may be exposed over unencrypted connections.',
    closed: 'HTTP port is closed. Web traffic may be served only over HTTPS.',
    filtered: 'HTTP port is filtered. May be behind a reverse proxy or firewall.',
  },
  443: {
    open: 'HTTPS is responding. Verify TLS version and cipher suite configuration.',
    closed: 'HTTPS port is closed. The server may not be serving web traffic.',
    filtered: 'HTTPS port is filtered. Web service may be behind a proxy.',
  },
  445: {
    open: 'SMB is exposed! Never expose SMB to the internet. WannaCry/EternalBlue risk.',
    closed: 'SMB port is closed. Good — this port should never be internet-facing.',
    filtered: 'SMB port is filtered. Ensure this remains blocked at the perimeter.',
  },
  3306: {
    open: 'MySQL is accessible remotely. Database servers should never be internet-facing.',
    closed: 'MySQL port is closed. Database is not exposed to external connections.',
    filtered: 'MySQL port is filtered. Verify database access is restricted to app servers.',
  },
  3389: {
    open: 'RDP is openly accessible! Primary ransomware entry point. Restrict access immediately.',
    closed: 'RDP port is closed. Remote desktop is not directly accessible.',
    filtered: 'RDP port is filtered. Ensure VPN is required before RDP access.',
  },
  6379: {
    open: 'Redis exposed without authentication likely. Data breach and RCE risk.',
    closed: 'Redis port is closed. Cache/data store not directly accessible.',
    filtered: 'Redis port is filtered. Verify Redis is bound to localhost.',
  },
};

function getExplanation(port: number, status: 'open' | 'closed' | 'filtered'): string {
  const entry = portExplanations[port];
  if (entry) return entry[status];
  if (status === 'closed') return `Port ${port} is closed — no service is listening.`;
  if (status === 'filtered') return `Port ${port} is filtered by firewall — result is inconclusive.`;
  return `Port ${port} (${portServices[port] ?? 'Unknown'}) is open. Review service configuration.`;
}

export const generateMockScanResult = (target: string): ScanResult => {
  const isIP = /^(?:(?:\d{1,3}\.){3}\d{1,3})$/.test(target);
  const targetType = isIP ? 'ip' : 'domain';

  const portsToScan = Object.keys(portServices).map(Number).sort((a, b) => a - b);

  const ports: PortResult[] = portsToScan.map((port) => {
    const random = Math.random();
    let status: 'open' | 'closed' | 'filtered';

    // Most dangerous ports are more likely to be closed/filtered in realistic scenarios
    const isDangerous = openRiskProfiles[port] === 'critical';
    if (random < (isDangerous ? 0.12 : 0.25)) {
      status = 'open';
    } else if (random < 0.65) {
      status = 'closed';
    } else {
      status = 'filtered';
    }

    const riskLevel: RiskLevel = status === 'open'
      ? (openRiskProfiles[port] ?? 'medium')
      : 'low';

    return {
      port,
      service: portServices[port] ?? 'Unknown',
      status,
      riskLevel,
      explanation: getExplanation(port, status),
      isCommonlyAttacked: commonlyAttackedPorts.has(port),
      responseTime: status === 'open' ? Math.floor(Math.random() * 200) + 5 : undefined,
    };
  });

  const openPorts = ports.filter((p) => p.status === 'open');
  const criticalCount = openPorts.filter((p) => p.riskLevel === 'critical').length;
  const highCount = openPorts.filter((p) => p.riskLevel === 'high').length;
  const mediumCount = openPorts.filter((p) => p.riskLevel === 'medium').length;

  let overallRisk: RiskLevel;
  let riskExplanation: string;

  if (criticalCount > 0) {
    overallRisk = 'critical';
    riskExplanation = `${criticalCount} CRITICAL service${criticalCount > 1 ? 's' : ''} exposed. Immediate remediation required.`;
  } else if (highCount > 0) {
    overallRisk = 'high';
    riskExplanation = `${highCount} high-risk port${highCount > 1 ? 's' : ''} open. Prompt action required.`;
  } else if (mediumCount > 2 || openPorts.length > 5) {
    overallRisk = 'medium';
    riskExplanation = `${mediumCount} moderate risks identified. Review and harden exposed services.`;
  } else {
    overallRisk = 'low';
    riskExplanation = 'System appears well-configured. Continue monitoring for changes.';
  }

  const reputationScore = Math.floor(Math.random() * 30) + 70;
  const isBlacklisted = reputationScore < 75;

  return {
    target,
    targetType,
    scanDate: new Date().toISOString(),
    duration: Math.floor(Math.random() * 5) + 2,
    ports,
    summary: {
      totalPorts: ports.length,
      openPorts: openPorts.length,
      closedPorts: ports.filter((p) => p.status === 'closed').length,
      filteredPorts: ports.filter((p) => p.status === 'filtered').length,
      overallRisk,
      riskExplanation,
    },
    reputation: {
      score: reputationScore,
      isBlacklisted,
      blacklistSources: isBlacklisted ? ['Spamhaus', 'AbuseIPDB'] : [],
      lastSeen: new Date(Date.now() - Math.random() * 86_400_000 * 7).toISOString(),
      country: ['United States', 'Germany', 'Netherlands', 'Singapore'][Math.floor(Math.random() * 4)],
      isp: ['Amazon Web Services', 'Google Cloud', 'DigitalOcean', 'Cloudflare'][Math.floor(Math.random() * 4)],
      warnings: isBlacklisted
        ? ['IP has been reported for suspicious activity', 'Associated with known malicious traffic']
        : [],
    },
    source: 'mock',
  };
};

export const mockScanHistory: ScanHistoryItem[] = [
  {
    id: '1',
    target: '192.168.1.1',
    targetType: 'ip',
    scanDate: new Date(Date.now() - 86_400_000).toISOString(),
    overallRisk: 'low',
    openPorts: 3,
  },
  {
    id: '2',
    target: 'example.com',
    targetType: 'domain',
    scanDate: new Date(Date.now() - 86_400_000 * 2).toISOString(),
    overallRisk: 'medium',
    openPorts: 5,
  },
  {
    id: '3',
    target: '10.0.0.50',
    targetType: 'ip',
    scanDate: new Date(Date.now() - 86_400_000 * 3).toISOString(),
    overallRisk: 'critical',
    openPorts: 4,
  },
];
