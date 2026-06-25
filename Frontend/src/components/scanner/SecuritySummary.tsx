import { ScanSummary } from '@/types/scanner';
import { Shield, AlertTriangle, CheckCircle, Server, Lock, Unlock, Skull } from 'lucide-react';
import { cn } from '@/lib/utils';

interface SecuritySummaryProps {
  summary: ScanSummary;
  educationalMode: boolean;
}

export function SecuritySummary({ summary, educationalMode }: SecuritySummaryProps) {
  const getRiskIcon = () => {
    switch (summary.overallRisk) {
      case 'critical':
        return <Skull className="h-8 w-8 text-risk-critical" />;
      case 'high':
        return <AlertTriangle className="h-8 w-8 text-risk-high" />;
      case 'medium':
        return <Shield className="h-8 w-8 text-risk-medium" />;
      default:
        return <CheckCircle className="h-8 w-8 text-risk-low" />;
    }
  };

  const getRiskStyles = () => {
    switch (summary.overallRisk) {
      case 'critical':
        return 'border-risk-critical/40 bg-risk-critical/5';
      case 'high':
        return 'border-risk-high/30 bg-risk-high/5';
      case 'medium':
        return 'border-risk-medium/30 bg-risk-medium/5';
      default:
        return 'border-risk-low/30 bg-risk-low/5';
    }
  };

  const getRiskBadgeStyles = () => {
    switch (summary.overallRisk) {
      case 'critical':
        return 'bg-risk-critical/20 text-risk-critical';
      case 'high':
        return 'bg-risk-high/20 text-risk-high';
      case 'medium':
        return 'bg-risk-medium/20 text-risk-medium';
      default:
        return 'bg-risk-low/20 text-risk-low';
    }
  };

  const educationalExplanation = () => {
    switch (summary.overallRisk) {
      case 'critical':
        return "Your system has extremely dangerous security gaps that are actively targeted by hackers and ransomware. Think of it like leaving your home's front door, back door, and windows all wide open with a sign saying 'Valuables inside.' Immediate action is required.";
      case 'high':
        return "Your system has serious security vulnerabilities that hackers could exploit. Think of it like leaving your front door wide open — anyone can walk in. Address these issues as soon as possible.";
      case 'medium':
        return "Your system has some security concerns worth addressing. It's like having a lock on your door but leaving a window cracked — not immediately dangerous, but worth fixing before someone notices.";
      default:
        return "Your system looks well-protected! Like a house with good locks and a security system, you're doing the right things to stay safe. Keep monitoring for any changes.";
    }
  };

  const stats = [
    {
      label: 'Total Scanned',
      value: summary.totalPorts,
      icon: Server,
      color: 'text-primary',
    },
    {
      label: 'Open Ports',
      value: summary.openPorts,
      icon: Unlock,
      color: summary.openPorts > 5 ? 'text-risk-high' : summary.openPorts > 0 ? 'text-risk-medium' : 'text-foreground',
    },
    {
      label: 'Closed',
      value: summary.closedPorts,
      icon: Lock,
      color: 'text-risk-low',
    },
    {
      label: 'Filtered',
      value: summary.filteredPorts,
      icon: Shield,
      color: 'text-muted-foreground',
    },
  ];

  return (
    <div className={cn('rounded-lg border p-6 space-y-6', getRiskStyles())}>
      <div className="flex items-start justify-between">
        <div>
          <h3 className="text-lg font-semibold text-foreground mb-1">Security Summary</h3>
          <p className="text-sm text-muted-foreground font-mono">Risk Assessment Overview</p>
        </div>
        {getRiskIcon()}
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {stats.map((stat) => (
          <div key={stat.label} className="text-center p-3 rounded-md bg-muted/30">
            <stat.icon className={cn('h-5 w-5 mx-auto mb-2', stat.color)} />
            <p className={cn('text-2xl font-bold font-mono', stat.color)}>{stat.value}</p>
            <p className="text-xs text-muted-foreground mt-1">{stat.label}</p>
          </div>
        ))}
      </div>

      <div className="pt-4 border-t border-border">
        <div className="flex items-center gap-2 mb-2">
          <span className={cn('px-2 py-1 rounded text-xs font-bold uppercase font-mono', getRiskBadgeStyles())}>
            {summary.overallRisk} Risk
          </span>
        </div>
        <p className="text-sm text-muted-foreground leading-relaxed">
          {educationalMode ? (
            <>
              <strong className="text-foreground">What this means: </strong>
              {educationalExplanation()}
            </>
          ) : (
            summary.riskExplanation
          )}
        </p>
      </div>
    </div>
  );
}
