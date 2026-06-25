import { ScanHistoryItem } from '@/types/scanner';
import { Clock, Server, Globe, AlertTriangle, Shield, CheckCircle, Trash2, Skull } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';

interface ScanHistoryProps {
  history: ScanHistoryItem[];
  onSelect: (target: string) => void;
  onClear: () => void;
}

export function ScanHistory({ history, onSelect, onClear }: ScanHistoryProps) {
  if (history.length === 0) {
    return (
      <div className="rounded-lg border border-border p-6 bg-card text-center">
        <Clock className="h-8 w-8 text-muted-foreground mx-auto mb-3" />
        <p className="text-muted-foreground">No scan history yet</p>
        <p className="text-sm text-muted-foreground mt-1">
          Your previous scans will appear here
        </p>
      </div>
    );
  }

  const getRiskIcon = (risk: string) => {
    switch (risk) {
      case 'critical':
        return <Skull className="h-4 w-4 text-risk-critical" />;
      case 'high':
        return <AlertTriangle className="h-4 w-4 text-risk-high" />;
      case 'medium':
        return <Shield className="h-4 w-4 text-risk-medium" />;
      default:
        return <CheckCircle className="h-4 w-4 text-risk-low" />;
    }
  };

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'critical': return 'text-risk-critical';
      case 'high':     return 'text-risk-high';
      case 'medium':   return 'text-risk-medium';
      default:         return 'text-risk-low';
    }
  };

  return (
    <div className="rounded-lg border border-border bg-card overflow-hidden">
      <div className="p-4 border-b border-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Clock className="h-5 w-5 text-primary" />
          <h3 className="font-semibold text-foreground">Scan History</h3>
        </div>
        <Button variant="cyberGhost" size="sm" onClick={onClear}>
          <Trash2 className="h-4 w-4" />
          Clear
        </Button>
      </div>
      <div className="divide-y divide-border max-h-[300px] overflow-y-auto">
        {history.map((item) => (
          <button
            key={item.id}
            onClick={() => onSelect(item.target)}
            className="w-full p-4 text-left hover:bg-muted/30 transition-colors group"
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                {item.targetType === 'ip' ? (
                  <Server className="h-4 w-4 text-muted-foreground" />
                ) : (
                  <Globe className="h-4 w-4 text-muted-foreground" />
                )}
                <span className="font-mono text-sm text-foreground group-hover:text-primary transition-colors">
                  {item.target}
                </span>
              </div>
              {getRiskIcon(item.overallRisk)}
            </div>
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <span>{new Date(item.scanDate).toLocaleDateString()}</span>
              <span className={cn('font-mono font-semibold capitalize', getRiskColor(item.overallRisk))}>
                {item.overallRisk} · {item.openPorts} open
              </span>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}
