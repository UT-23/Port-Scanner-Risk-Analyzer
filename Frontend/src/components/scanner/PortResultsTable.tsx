import { useState } from 'react';
import { PortResult } from '@/types/scanner';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  AlertTriangle, Shield, CheckCircle, Lock, Unlock, Filter,
  Skull, ChevronDown, ChevronRight, ShieldAlert,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';

interface PortResultsTableProps {
  ports: PortResult[];
  educationalMode: boolean;
}

export function PortResultsTable({ ports, educationalMode }: PortResultsTableProps) {
  const [expandedPort, setExpandedPort] = useState<number | null>(null);

  const getRiskBadge = (risk: string) => {
    switch (risk) {
      case 'critical':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-bold uppercase font-mono bg-risk-critical/20 text-risk-critical">
            <Skull className="h-3 w-3" />
            Critical
          </span>
        );
      case 'high':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-bold uppercase font-mono bg-risk-high/20 text-risk-high">
            <AlertTriangle className="h-3 w-3" />
            High
          </span>
        );
      case 'medium':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-bold uppercase font-mono bg-risk-medium/20 text-risk-medium">
            <Shield className="h-3 w-3" />
            Medium
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-bold uppercase font-mono bg-risk-low/20 text-risk-low">
            <CheckCircle className="h-3 w-3" />
            Low
          </span>
        );
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'open':
        return <Unlock className="h-4 w-4 text-risk-medium" />;
      case 'closed':
        return <Lock className="h-4 w-4 text-risk-low" />;
      default:
        return <Filter className="h-4 w-4 text-muted-foreground" />;
    }
  };

  const getRowHighlight = (port: PortResult) => {
    if (port.status !== 'open') return '';
    if (port.riskLevel === 'critical') return 'bg-risk-critical/8';
    if (port.riskLevel === 'high') return 'bg-risk-high/8';
    return '';
  };

  const getEducationalExplanation = (port: PortResult): string => {
    const baseExplanations: Record<string, string> = {
      'FTP':      "FTP sends passwords in plain text — like yelling your PIN number in a crowded room. Very insecure.",
      'FTP-Data': "FTP Data port is where actual file content flows — also completely unencrypted.",
      'SSH':      "SSH (Secure Shell) is a secure tunnel into your computer. Ensure only key-based login is allowed.",
      'Telnet':   "Telnet is an ancient remote access tool that sends everything unencrypted. Never use it — use SSH instead.",
      'HTTP':     "Regular web traffic without encryption — like sending a postcard anyone can read along the way.",
      'HTTPS':    "Encrypted web traffic — like sending a letter in a locked box. Much safer than plain HTTP.",
      'SMB':      "Windows file sharing. The WannaCry ransomware spread through SMB. Never expose this to the internet.",
      'RDP':      "Remote Desktop — lets you see and control a Windows computer. Ransomware groups love finding open RDP.",
      'MySQL':    "Database server. If exposed to the internet, hackers could access or delete all your stored data.",
      'PostgreSQL': "Database server. Should only be accessible from your application server, not the internet.",
      'Redis':    "Fast data cache. Without a password, anyone can read all data and even execute code on your server.",
      'VNC':      "Remote desktop protocol — similar to RDP. Weak by default and should never face the internet.",
      'MSSQL':    "Microsoft SQL Server database. Ransomware groups actively target exposed MSSQL instances.",
      'NetBIOS':  "Old Windows networking — hackers can use it to enumerate users and steal password hashes.",
      'MS-RPC':   "Windows remote procedure calls — historically used by worms like Blaster to spread automatically.",
      'NFS':      "Network File System — allows remote file access. Easy to misconfigure with wide-open access.",
    };
    return baseExplanations[port.service] ?? port.explanation;
  };

  const toggleExpand = (port: number) => {
    setExpandedPort((prev) => (prev === port ? null : port));
  };

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <div className="overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow className="bg-muted/30 hover:bg-muted/30">
              <TableHead className="font-mono text-xs text-muted-foreground w-8" />
              <TableHead className="font-mono text-xs text-muted-foreground">PORT</TableHead>
              <TableHead className="font-mono text-xs text-muted-foreground">SERVICE</TableHead>
              <TableHead className="font-mono text-xs text-muted-foreground">STATUS</TableHead>
              <TableHead className="font-mono text-xs text-muted-foreground">RISK</TableHead>
              <TableHead className="font-mono text-xs text-muted-foreground">RESP TIME</TableHead>
              <TableHead className="font-mono text-xs text-muted-foreground">DETAILS</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {ports.map((port) => (
              <>
                <TableRow
                  key={port.port}
                  className={cn(
                    'transition-colors',
                    port.status === 'open' && 'cursor-pointer hover:bg-muted/20',
                    getRowHighlight(port),
                  )}
                  onClick={() => port.status === 'open' && toggleExpand(port.port)}
                >
                  {/* Expand toggle */}
                  <TableCell className="w-8 text-center">
                    {port.status === 'open' && port.securityDetails ? (
                      expandedPort === port.port
                        ? <ChevronDown className="h-4 w-4 text-muted-foreground" />
                        : <ChevronRight className="h-4 w-4 text-muted-foreground" />
                    ) : null}
                  </TableCell>

                  {/* Port number */}
                  <TableCell className="font-mono font-bold">
                    <div className="flex items-center gap-2">
                      {port.isCommonlyAttacked && (
                        <Tooltip>
                          <TooltipTrigger>
                            <Skull className="h-4 w-4 text-risk-high" />
                          </TooltipTrigger>
                          <TooltipContent>
                            <p className="font-mono text-xs">Commonly targeted port</p>
                          </TooltipContent>
                        </Tooltip>
                      )}
                      <span
                        className={cn(
                          port.status === 'open' && port.riskLevel === 'critical' && 'text-risk-critical',
                          port.status === 'open' && port.riskLevel === 'high' && 'text-risk-high',
                        )}
                      >
                        {port.port}
                      </span>
                    </div>
                  </TableCell>

                  {/* Service */}
                  <TableCell>
                    <span className="font-mono text-sm text-foreground">{port.service}</span>
                  </TableCell>

                  {/* Status */}
                  <TableCell>
                    <div className="flex items-center gap-2">
                      {getStatusIcon(port.status)}
                      <span
                        className={cn(
                          'text-sm font-medium capitalize',
                          port.status === 'open' && 'text-risk-medium',
                          port.status === 'closed' && 'text-risk-low',
                          port.status === 'filtered' && 'text-muted-foreground',
                        )}
                      >
                        {port.status}
                      </span>
                    </div>
                  </TableCell>

                  {/* Risk badge */}
                  <TableCell>{getRiskBadge(port.riskLevel)}</TableCell>

                  {/* Response time */}
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {port.responseTime != null ? `${port.responseTime} ms` : '—'}
                  </TableCell>

                  {/* Brief details */}
                  <TableCell className="max-w-xs">
                    <p className="text-sm text-muted-foreground leading-snug line-clamp-2">
                      {educationalMode ? getEducationalExplanation(port) : port.explanation}
                    </p>
                  </TableCell>
                </TableRow>

                {/* Expanded security details row */}
                {expandedPort === port.port && port.securityDetails && (
                  <TableRow key={`${port.port}-details`} className="bg-muted/10 hover:bg-muted/10">
                    <TableCell colSpan={7} className="p-0">
                      <div className="p-4 border-t border-border/50 space-y-4">
                        <div className="flex items-center gap-2 text-xs font-mono text-primary mb-3">
                          <ShieldAlert className="h-4 w-4" />
                          Security Analysis — {port.service} (:{port.port})
                        </div>

                        <p className="text-sm text-muted-foreground leading-relaxed">
                          {port.securityDetails.description}
                        </p>

                        <div className="grid md:grid-cols-3 gap-4 text-xs">
                          {/* Vulnerabilities */}
                          <div>
                            <h4 className="font-semibold text-risk-high mb-2 uppercase tracking-wide">
                              Known Vulnerabilities
                            </h4>
                            <ul className="space-y-1">
                              {port.securityDetails.vulnerabilities.map((v, i) => (
                                <li key={i} className="flex items-start gap-1 text-muted-foreground">
                                  <span className="text-risk-high mt-0.5">•</span> {v}
                                </li>
                              ))}
                            </ul>
                          </div>

                          {/* Attack Vectors */}
                          <div>
                            <h4 className="font-semibold text-risk-medium mb-2 uppercase tracking-wide">
                              Attack Vectors
                            </h4>
                            <ul className="space-y-1">
                              {port.securityDetails.attackVectors.map((v, i) => (
                                <li key={i} className="flex items-start gap-1 text-muted-foreground">
                                  <span className="text-risk-medium mt-0.5">▸</span> {v}
                                </li>
                              ))}
                            </ul>
                          </div>

                          {/* Mitigations */}
                          <div>
                            <h4 className="font-semibold text-risk-low mb-2 uppercase tracking-wide">
                              Recommended Mitigations
                            </h4>
                            <ul className="space-y-1">
                              {port.securityDetails.mitigations.map((m, i) => (
                                <li key={i} className="flex items-start gap-1 text-muted-foreground">
                                  <span className="text-risk-low mt-0.5">✓</span> {m}
                                </li>
                              ))}
                            </ul>
                          </div>
                        </div>
                      </div>
                    </TableCell>
                  </TableRow>
                )}
              </>
            ))}
          </TableBody>
        </Table>
      </div>
      {ports.some((p) => p.status === 'open' && p.securityDetails) && (
        <div className="px-4 py-2 border-t border-border bg-muted/10 text-xs text-muted-foreground font-mono">
          ↕ Click any open port row to view full security analysis
        </div>
      )}
    </div>
  );
}
