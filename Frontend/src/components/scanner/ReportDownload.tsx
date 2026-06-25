import { ScanResult } from '@/types/scanner';
import { Button } from '@/components/ui/button';
import { FileText, Code, Download } from 'lucide-react';
import { toast } from '@/hooks/use-toast';

interface ReportDownloadProps {
  result: ScanResult;
}

export function ReportDownload({ result }: ReportDownloadProps) {
  const generateTextReport = (): string => {
    const lines = [
      '═══════════════════════════════════════════════════════════════',
      '                    PORT SCANNER & RISK ANALYZER                ',
      '                         SECURITY REPORT                        ',
      '═══════════════════════════════════════════════════════════════',
      '',
      `Target: ${result.target}`,
      `Type: ${result.targetType.toUpperCase()}`,
      `Scan Date: ${new Date(result.scanDate).toLocaleString()}`,
      `Duration: ${result.duration} seconds`,
      '',
      '───────────────────────────────────────────────────────────────',
      '                       SECURITY SUMMARY                         ',
      '───────────────────────────────────────────────────────────────',
      '',
      `Overall Risk Level: ${result.summary.overallRisk.toUpperCase()}`,
      `Total Ports Scanned: ${result.summary.totalPorts}`,
      `Open Ports: ${result.summary.openPorts}`,
      `Closed Ports: ${result.summary.closedPorts}`,
      `Filtered Ports: ${result.summary.filteredPorts}`,
      '',
      `Assessment: ${result.summary.riskExplanation}`,
      '',
      '───────────────────────────────────────────────────────────────',
      '                       PORT SCAN RESULTS                        ',
      '───────────────────────────────────────────────────────────────',
      '',
      'PORT     SERVICE          STATUS     RISK     DETAILS',
      '─────────────────────────────────────────────────────────────────',
    ];

    result.ports.forEach((port) => {
      const portStr = port.port.toString().padEnd(8);
      const serviceStr = port.service.padEnd(16);
      const statusStr = port.status.padEnd(10);
      const riskStr = port.riskLevel.toUpperCase().padEnd(8);
      lines.push(`${portStr} ${serviceStr} ${statusStr} ${riskStr} ${port.explanation}`);
    });

    lines.push('');
    lines.push('───────────────────────────────────────────────────────────────');
    lines.push('                       IP REPUTATION                           ');
    lines.push('───────────────────────────────────────────────────────────────');
    lines.push('');
    lines.push(`Reputation Score: ${result.reputation.score}/100`);
    lines.push(`Blacklisted: ${result.reputation.isBlacklisted ? 'YES' : 'NO'}`);
    lines.push(`Country: ${result.reputation.country}`);
    lines.push(`ISP: ${result.reputation.isp}`);
    
    if (result.reputation.warnings.length > 0) {
      lines.push('');
      lines.push('Warnings:');
      result.reputation.warnings.forEach((w) => lines.push(`  • ${w}`));
    }

    lines.push('');
    lines.push('═══════════════════════════════════════════════════════════════');
    lines.push('                      END OF REPORT                            ');
    lines.push('═══════════════════════════════════════════════════════════════');

    return lines.join('\n');
  };

  const generateHTMLReport = (): string => {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Report - ${result.target}</title>
  <style>
    :root { --bg: #0a0f1a; --card: #111827; --primary: #22d3ee; --text: #e2e8f0; --muted: #64748b; --high: #ef4444; --medium: #f59e0b; --low: #22c55e; }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); padding: 2rem; }
    .container { max-width: 900px; margin: 0 auto; }
    h1 { color: var(--primary); margin-bottom: 0.5rem; }
    h2 { color: var(--primary); margin: 2rem 0 1rem; font-size: 1.25rem; border-bottom: 1px solid #1e293b; padding-bottom: 0.5rem; }
    .meta { color: var(--muted); font-size: 0.875rem; margin-bottom: 2rem; }
    .card { background: var(--card); border-radius: 0.5rem; padding: 1.5rem; margin-bottom: 1.5rem; border: 1px solid #1e293b; }
    .risk-high { color: var(--high); }
    .risk-medium { color: var(--medium); }
    .risk-low { color: var(--low); }
    .badge { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 0.25rem; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; }
    .badge-high { background: rgba(239, 68, 68, 0.2); color: var(--high); }
    .badge-medium { background: rgba(245, 158, 11, 0.2); color: var(--medium); }
    .badge-low { background: rgba(34, 197, 94, 0.2); color: var(--low); }
    table { width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.875rem; }
    th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #1e293b; }
    th { color: var(--muted); font-weight: 500; text-transform: uppercase; font-size: 0.75rem; }
    .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; }
    .stat { text-align: center; padding: 1rem; background: rgba(255,255,255,0.02); border-radius: 0.5rem; }
    .stat-value { font-size: 1.5rem; font-weight: bold; color: var(--primary); font-family: monospace; }
    .stat-label { font-size: 0.75rem; color: var(--muted); margin-top: 0.25rem; }
    .warning { background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 0.5rem; padding: 1rem; margin-bottom: 1rem; }
    .warning-title { color: var(--high); font-weight: bold; margin-bottom: 0.5rem; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🛡️ Security Scan Report</h1>
    <p class="meta">Target: <strong>${result.target}</strong> | Scanned: ${new Date(result.scanDate).toLocaleString()} | Duration: ${result.duration}s</p>
    
    ${result.reputation.isBlacklisted ? `<div class="warning"><div class="warning-title">⚠️ IP BLACKLISTED</div><p>This IP appears on blacklists: ${result.reputation.blacklistSources.join(', ')}</p></div>` : ''}
    
    <div class="card">
      <h2>Security Summary</h2>
      <p>Overall Risk: <span class="badge badge-${result.summary.overallRisk}">${result.summary.overallRisk}</span></p>
      <p style="margin-top: 1rem; color: var(--muted);">${result.summary.riskExplanation}</p>
      <div class="stats" style="margin-top: 1.5rem;">
        <div class="stat"><div class="stat-value">${result.summary.totalPorts}</div><div class="stat-label">Total Scanned</div></div>
        <div class="stat"><div class="stat-value">${result.summary.openPorts}</div><div class="stat-label">Open</div></div>
        <div class="stat"><div class="stat-value">${result.summary.closedPorts}</div><div class="stat-label">Closed</div></div>
        <div class="stat"><div class="stat-value">${result.summary.filteredPorts}</div><div class="stat-label">Filtered</div></div>
      </div>
    </div>
    
    <div class="card">
      <h2>Port Scan Results</h2>
      <table>
        <thead><tr><th>Port</th><th>Service</th><th>Status</th><th>Risk</th><th>Details</th></tr></thead>
        <tbody>
          ${result.ports.map(p => `<tr><td><strong>${p.port}</strong></td><td>${p.service}</td><td class="risk-${p.status === 'open' ? 'medium' : 'low'}">${p.status}</td><td><span class="badge badge-${p.riskLevel}">${p.riskLevel}</span></td><td style="color: var(--muted)">${p.explanation}</td></tr>`).join('')}
        </tbody>
      </table>
    </div>
    
    <div class="card">
      <h2>IP Reputation</h2>
      <p>Score: <strong class="risk-${result.reputation.score >= 80 ? 'low' : result.reputation.score >= 60 ? 'medium' : 'high'}">${result.reputation.score}/100</strong></p>
      <p style="margin-top: 0.5rem; color: var(--muted);">Country: ${result.reputation.country} | ISP: ${result.reputation.isp}</p>
    </div>
    
    <p style="text-align: center; color: var(--muted); margin-top: 2rem; font-size: 0.75rem;">Generated by Port Scanner & Risk Analyzer</p>
  </div>
</body>
</html>`;
  };

  const downloadReport = (type: 'text' | 'html') => {
    const content = type === 'text' ? generateTextReport() : generateHTMLReport();
    const mimeType = type === 'text' ? 'text/plain' : 'text/html';
    const extension = type === 'text' ? 'txt' : 'html';
    
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-report-${result.target.replace(/\./g, '-')}-${Date.now()}.${extension}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    toast({
      title: 'Report Downloaded',
      description: `${type.toUpperCase()} report has been saved to your downloads.`,
    });
  };

  return (
    <div className="flex flex-wrap gap-3">
      <Button variant="cyberOutline" onClick={() => downloadReport('text')}>
        <FileText className="h-4 w-4" />
        Download TXT Report
      </Button>
      <Button variant="cyberOutline" onClick={() => downloadReport('html')}>
        <Code className="h-4 w-4" />
        Download HTML Report
      </Button>
    </div>
  );
}
