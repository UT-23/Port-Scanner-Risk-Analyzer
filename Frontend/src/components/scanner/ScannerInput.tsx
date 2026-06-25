import { useState } from 'react';
import { Search, Loader2, Shield } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { CyberInput } from '@/components/ui/input';

interface ScannerInputProps {
  onScan: (target: string) => void;
  isScanning: boolean;
}

export function ScannerInput({ onScan, isScanning }: ScannerInputProps) {
  const [target, setTarget] = useState('');
  const [error, setError] = useState('');

  const validateInput = (value: string): boolean => {
    const ipRegex = /^(?:\d{1,3}\.){3}\d{1,3}$/;
    const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    
    if (!value.trim()) {
      setError('Please enter an IP address or domain');
      return false;
    }
    
    if (!ipRegex.test(value) && !domainRegex.test(value)) {
      setError('Invalid IP address or domain format');
      return false;
    }
    
    setError('');
    return true;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (validateInput(target)) {
      onScan(target);
    }
  };

  return (
    <div className="w-full">
      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Shield className="absolute left-4 top-1/2 -translate-y-1/2 h-5 w-5 text-muted-foreground" />
            <CyberInput
              type="text"
              placeholder="Enter IP address or domain (e.g., 192.168.1.1 or example.com)"
              value={target}
              onChange={(e) => {
                setTarget(e.target.value);
                if (error) validateInput(e.target.value);
              }}
              className="pl-12"
              disabled={isScanning}
            />
          </div>
          <Button 
            type="submit" 
            variant="cyber" 
            size="xl"
            disabled={isScanning}
            className="min-w-[140px]"
          >
            {isScanning ? (
              <>
                <Loader2 className="h-5 w-5 animate-spin" />
                Scanning...
              </>
            ) : (
              <>
                <Search className="h-5 w-5" />
                Scan Target
              </>
            )}
          </Button>
        </div>
        {error && (
          <p className="text-sm text-destructive font-mono">{error}</p>
        )}
      </form>
    </div>
  );
}
