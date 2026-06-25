import { IPReputation as IPReputationType } from '@/types/scanner';
import { AlertTriangle, CheckCircle, Globe, Server, Calendar, AlertOctagon } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Progress } from '@/components/ui/progress';

interface IPReputationProps {
  reputation: IPReputationType;
  educationalMode: boolean;
}

export function IPReputation({ reputation, educationalMode }: IPReputationProps) {
  const getScoreColor = () => {
    if (reputation.score >= 80) return 'text-risk-low';
    if (reputation.score >= 60) return 'text-risk-medium';
    return 'text-risk-high';
  };

  const getScoreBarColor = () => {
    if (reputation.score >= 80) return 'bg-risk-low';
    if (reputation.score >= 60) return 'bg-risk-medium';
    return 'bg-risk-high';
  };

  return (
    <div className="space-y-4">
      {reputation.isBlacklisted && (
        <div className="p-4 rounded-lg bg-risk-high/10 border border-risk-high/30 flex items-start gap-3">
          <AlertOctagon className="h-6 w-6 text-risk-high flex-shrink-0 mt-0.5" />
          <div>
            <h4 className="font-semibold text-risk-high mb-1">Warning: IP Blacklisted</h4>
            <p className="text-sm text-muted-foreground">
              {educationalMode
                ? "This IP address has been reported for suspicious activity. Think of it like a neighborhood watch list - other computers have flagged this address as potentially dangerous."
                : `This IP appears on ${reputation.blacklistSources.length} blacklist(s): ${reputation.blacklistSources.join(', ')}`}
            </p>
          </div>
        </div>
      )}

      <div className="rounded-lg border border-border p-6 bg-card">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h3 className="text-lg font-semibold text-foreground mb-1">IP Reputation</h3>
            <p className="text-sm text-muted-foreground font-mono">Threat Intelligence Analysis</p>
          </div>
          {reputation.isBlacklisted ? (
            <AlertTriangle className="h-8 w-8 text-risk-high" />
          ) : (
            <CheckCircle className="h-8 w-8 text-risk-low" />
          )}
        </div>

        <div className="mb-6">
          <div className="flex items-end justify-between mb-2">
            <span className="text-sm text-muted-foreground">Reputation Score</span>
            <span className={cn('text-3xl font-bold font-mono', getScoreColor())}>
              {reputation.score}
              <span className="text-lg text-muted-foreground">/100</span>
            </span>
          </div>
          <div className="h-3 bg-muted rounded-full overflow-hidden">
            <div
              className={cn('h-full transition-all duration-500 rounded-full', getScoreBarColor())}
              style={{ width: `${reputation.score}%` }}
            />
          </div>
          {educationalMode && (
            <p className="text-xs text-muted-foreground mt-2">
              {reputation.score >= 80
                ? "This score is like a credit rating for IP addresses. 80+ means this IP has a good history."
                : reputation.score >= 60
                ? "This score indicates some concerns. Like a fair credit score, it's not bad but could be better."
                : "A low score means this IP has been involved in suspicious activity. Be cautious."}
            </p>
          )}
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="p-3 rounded-md bg-muted/30">
            <div className="flex items-center gap-2 mb-1">
              <Globe className="h-4 w-4 text-primary" />
              <span className="text-xs text-muted-foreground">Country</span>
            </div>
            <p className="font-mono text-sm text-foreground">{reputation.country}</p>
          </div>
          <div className="p-3 rounded-md bg-muted/30">
            <div className="flex items-center gap-2 mb-1">
              <Server className="h-4 w-4 text-primary" />
              <span className="text-xs text-muted-foreground">ISP</span>
            </div>
            <p className="font-mono text-sm text-foreground truncate">{reputation.isp}</p>
          </div>
          <div className="p-3 rounded-md bg-muted/30">
            <div className="flex items-center gap-2 mb-1">
              <Calendar className="h-4 w-4 text-primary" />
              <span className="text-xs text-muted-foreground">Last Seen</span>
            </div>
            <p className="font-mono text-sm text-foreground">
              {new Date(reputation.lastSeen).toLocaleDateString()}
            </p>
          </div>
        </div>

        {reputation.warnings.length > 0 && (
          <div className="mt-4 pt-4 border-t border-border">
            <h4 className="text-sm font-medium text-muted-foreground mb-2">Active Warnings</h4>
            <ul className="space-y-2">
              {reputation.warnings.map((warning, index) => (
                <li key={index} className="flex items-start gap-2 text-sm text-risk-medium">
                  <AlertTriangle className="h-4 w-4 flex-shrink-0 mt-0.5" />
                  {warning}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}
