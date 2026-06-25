import { useEffect, useState } from 'react';
import { Progress } from '@/components/ui/progress';
import { Terminal, Radio } from 'lucide-react';

interface ScanProgressProps {
  isScanning: boolean;
}

const scanMessages = [
  'Initializing port scanner...',
  'Resolving target address...',
  'Probing common ports...',
  'Analyzing service fingerprints...',
  'Checking security configurations...',
  'Querying reputation databases...',
  'Compiling risk assessment...',
  'Generating security report...',
];

export function ScanProgress({ isScanning }: ScanProgressProps) {
  const [progress, setProgress] = useState(0);
  const [messageIndex, setMessageIndex] = useState(0);

  useEffect(() => {
    if (!isScanning) {
      setProgress(0);
      setMessageIndex(0);
      return;
    }

    const progressInterval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 100) return 100;
        return prev + Math.random() * 15;
      });
    }, 300);

    const messageInterval = setInterval(() => {
      setMessageIndex((prev) => (prev + 1) % scanMessages.length);
    }, 800);

    return () => {
      clearInterval(progressInterval);
      clearInterval(messageInterval);
    };
  }, [isScanning]);

  if (!isScanning) return null;

  return (
    <div className="w-full p-6 rounded-lg bg-card border border-border cyber-border">
      <div className="flex items-center gap-3 mb-4">
        <div className="relative">
          <Terminal className="h-5 w-5 text-primary animate-pulse" />
          <Radio className="h-3 w-3 text-primary absolute -top-1 -right-1 animate-ping" />
        </div>
        <span className="text-sm font-mono text-primary text-glow">
          SCAN IN PROGRESS
        </span>
      </div>
      
      <Progress value={Math.min(progress, 100)} className="h-2 mb-4" />
      
      <div className="font-mono text-sm text-muted-foreground">
        <span className="text-primary">$</span> {scanMessages[messageIndex]}
        <span className="animate-pulse">_</span>
      </div>
      
      <div className="mt-4 grid grid-cols-4 gap-2">
        {[...Array(8)].map((_, i) => (
          <div
            key={i}
            className={`h-1 rounded-full transition-all duration-300 ${
              i < Math.floor(progress / 12.5)
                ? 'bg-primary cyber-glow-sm'
                : 'bg-muted'
            }`}
          />
        ))}
      </div>
    </div>
  );
}
