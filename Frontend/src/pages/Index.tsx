import { useState, useEffect } from 'react';
import { Shield, Terminal, Activity, Zap, Wifi, WifiOff } from 'lucide-react';
import { ScannerInput } from '@/components/scanner/ScannerInput';
import { ScanProgress } from '@/components/scanner/ScanProgress';
import { SecuritySummary } from '@/components/scanner/SecuritySummary';
import { PortResultsTable } from '@/components/scanner/PortResultsTable';
import { IPReputation } from '@/components/scanner/IPReputation';
import { ReportDownload } from '@/components/scanner/ReportDownload';
import { ScanHistory } from '@/components/scanner/ScanHistory';
import { EducationalToggle } from '@/components/scanner/EducationalToggle';
import { ScanResult, ScanHistoryItem } from '@/types/scanner';
import { mockScanHistory } from '@/lib/mockData';
import { scanTarget, checkBackendHealth } from '@/lib/api';
import { toast } from 'sonner';

const Index = () => {
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [scanHistory, setScanHistory] = useState<ScanHistoryItem[]>(mockScanHistory);
  const [educationalMode, setEducationalMode] = useState(false);
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null); // null = checking

  // Check backend health on mount
  useEffect(() => {
    checkBackendHealth().then((online) => setBackendOnline(online));
  }, []);

  const handleScan = async (target: string) => {
    setIsScanning(true);
    setScanResult(null);

    try {
      const { result, source, error } = await scanTarget(target);

      if (source === 'mock') {
        setBackendOnline(false);
        toast.warning(
          error?.includes('fetch') || error?.includes('Failed')
            ? 'Backend offline — showing demo data. Start the Python server to scan real targets.'
            : `Backend error: ${error}. Showing demo data.`,
          { duration: 6000 },
        );
      } else {
        setBackendOnline(true);
        toast.success(`Real scan complete for ${target}`, { duration: 3000 });
      }

      setScanResult(result);

      const historyItem: ScanHistoryItem = {
        id: Date.now().toString(),
        target: result.target,
        targetType: result.targetType,
        scanDate: result.scanDate,
        overallRisk: result.summary.overallRisk,
        openPorts: result.summary.openPorts,
      };
      setScanHistory((prev) => [historyItem, ...prev.slice(0, 9)]);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      toast.error(message, { duration: 5000 });
    } finally {
      setIsScanning(false);
    }
  };

  const handleSelectFromHistory = (target: string) => handleScan(target);

  const handleClearHistory = () => setScanHistory([]);

  const BackendBadge = () => {
    if (backendOnline === null) {
      return (
        <div className="flex items-center gap-2 text-xs text-muted-foreground font-mono">
          <Terminal className="h-4 w-4" />
          <span className="hidden sm:inline">Checking API...</span>
          <span className="w-2 h-2 rounded-full bg-muted animate-pulse" />
        </div>
      );
    }
    return (
      <div className="flex items-center gap-2 text-xs font-mono">
        {backendOnline ? (
          <>
            <Wifi className="h-4 w-4 text-risk-low" />
            <span className="hidden sm:inline text-risk-low">Backend Online</span>
            <span className="w-2 h-2 rounded-full bg-risk-low animate-pulse" />
          </>
        ) : (
          <>
            <WifiOff className="h-4 w-4 text-muted-foreground" />
            <span className="hidden sm:inline text-muted-foreground">Demo Mode</span>
            <span className="w-2 h-2 rounded-full bg-muted-foreground" />
          </>
        )}
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="relative">
                <Shield className="h-8 w-8 text-primary" />
                <Activity className="h-3 w-3 text-primary absolute -bottom-0.5 -right-0.5 animate-pulse" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-foreground font-mono tracking-tight">
                  PORT<span className="text-primary">SCAN</span>
                </h1>
                <p className="text-xs text-muted-foreground">Risk Analyzer v2.0</p>
              </div>
            </div>
            <BackendBadge />
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8">
        <div className="grid lg:grid-cols-3 gap-8">
          {/* Main Scanner Panel */}
          <div className="lg:col-span-2 space-y-6">
            {/* Hero Section */}
            <div className="text-center lg:text-left mb-8">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary/10 text-primary text-sm font-mono mb-4">
                <Zap className="h-4 w-4" />
                Enterprise-Grade Security Scanner
              </div>
              <h2 className="text-3xl lg:text-4xl font-bold text-foreground mb-3">
                Scan. Analyze. <span className="text-primary">Protect.</span>
              </h2>
              <p className="text-muted-foreground max-w-xl lg:mx-0 mx-auto text-center lg:text-left">
                Identify open ports, assess security risks, and receive actionable mitigations.
                {backendOnline
                  ? ' Connected to real scanning backend.'
                  : ' Start the Python backend to scan real targets.'}
              </p>
            </div>

            {/* Demo mode notice */}
            {backendOnline === false && (
              <div className="p-4 rounded-lg border border-primary/20 bg-primary/5 text-xs font-mono text-muted-foreground">
                <span className="text-primary font-semibold">// Demo Mode Active</span>
                <br />
                Results shown are simulated. To scan real targets, start the backend:
                <br />
                <span className="text-foreground">$ uvicorn portscanner:app --reload</span>
              </div>
            )}

            {/* Scanner Input */}
            <div className="p-6 rounded-lg border border-border bg-card">
              <ScannerInput onScan={handleScan} isScanning={isScanning} />
            </div>

            {/* Scan Progress */}
            <ScanProgress isScanning={isScanning} />

            {/* Results Section */}
            {scanResult && !isScanning && (
              <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
                {/* Data source badge */}
                <div className="flex items-center gap-2">
                  <span
                    className={`px-2 py-1 rounded text-xs font-mono font-bold ${
                      scanResult.source === 'api'
                        ? 'bg-risk-low/20 text-risk-low'
                        : 'bg-muted text-muted-foreground'
                    }`}
                  >
                    {scanResult.source === 'api' ? '● LIVE SCAN' : '○ DEMO DATA'}
                  </span>
                  <span className="text-xs text-muted-foreground font-mono">
                    {scanResult.target} · {scanResult.duration.toFixed(1)}s · {scanResult.ports.length} ports
                  </span>
                </div>

                {/* Educational Toggle */}
                <EducationalToggle enabled={educationalMode} onToggle={setEducationalMode} />

                {/* Security Summary */}
                <SecuritySummary summary={scanResult.summary} educationalMode={educationalMode} />

                {/* IP Reputation */}
                <IPReputation reputation={scanResult.reputation} educationalMode={educationalMode} />

                {/* Port Results Table */}
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-lg font-semibold text-foreground">Port Scan Results</h3>
                    <span className="text-sm text-muted-foreground font-mono">
                      {scanResult.ports.filter((p) => p.status === 'open').length} open / {scanResult.ports.length} scanned
                    </span>
                  </div>
                  <PortResultsTable ports={scanResult.ports} educationalMode={educationalMode} />
                </div>

                {/* Report Download */}
                <div className="p-6 rounded-lg border border-border bg-card">
                  <h3 className="text-lg font-semibold text-foreground mb-4">Export Report</h3>
                  <ReportDownload result={scanResult} />
                </div>
              </div>
            )}

            {/* Empty State */}
            {!scanResult && !isScanning && (
              <div className="p-12 rounded-lg border border-border bg-card/50 text-center">
                <Shield className="h-16 w-16 text-muted-foreground/30 mx-auto mb-4" />
                <h3 className="text-lg font-semibold text-muted-foreground mb-2">Ready to Scan</h3>
                <p className="text-sm text-muted-foreground max-w-sm mx-auto">
                  Enter an IP address or domain above to begin security assessment.
                  Only scan systems you own or have explicit authorization to test.
                </p>
              </div>
            )}
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            {/* Scan History */}
            <ScanHistory
              history={scanHistory}
              onSelect={handleSelectFromHistory}
              onClear={handleClearHistory}
            />

            {/* Quick Stats */}
            <div className="rounded-lg border border-border bg-card p-6">
              <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-4">
                Quick Info
              </h3>
              <div className="space-y-4 text-sm">
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 rounded bg-primary/10 flex items-center justify-center flex-shrink-0">
                    <Terminal className="h-4 w-4 text-primary" />
                  </div>
                  <div>
                    <p className="font-medium text-foreground">FastAPI Backend</p>
                    <p className="text-muted-foreground text-xs">Real TCP scanning via Python</p>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 rounded bg-risk-low/10 flex items-center justify-center flex-shrink-0">
                    <Shield className="h-4 w-4 text-risk-low" />
                  </div>
                  <div>
                    <p className="font-medium text-foreground">28 Common Ports</p>
                    <p className="text-muted-foreground text-xs">Including all high-risk targets</p>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 rounded bg-risk-medium/10 flex items-center justify-center flex-shrink-0">
                    <Activity className="h-4 w-4 text-risk-medium" />
                  </div>
                  <div>
                    <p className="font-medium text-foreground">4-Level Risk Assessment</p>
                    <p className="text-muted-foreground text-xs">Critical · High · Medium · Low</p>
                  </div>
                </div>
              </div>
            </div>

            {/* API info */}
            <div className="rounded-lg border border-primary/20 bg-primary/5 p-4">
              <p className="text-xs text-muted-foreground font-mono">
                <span className="text-primary font-semibold">// Backend API</span>
                <br />
                GET /scan?target=&lt;ip_or_domain&gt;
                <br />
                GET /health
                <br />
                <span className="text-muted-foreground/70">Port: 8000</span>
              </p>
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-border mt-16 py-6">
        <div className="container mx-auto px-4 text-center text-xs text-muted-foreground font-mono">
          <p>
            Port Scanner &amp; Risk Analyzer v2.0 · For authorized testing only ·{' '}
            <span className="text-primary">Scan responsibly</span>
          </p>
        </div>
      </footer>
    </div>
  );
};

export default Index;
