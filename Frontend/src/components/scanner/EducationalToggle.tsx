import { Switch } from '@/components/ui/switch';
import { GraduationCap } from 'lucide-react';

interface EducationalToggleProps {
  enabled: boolean;
  onToggle: (enabled: boolean) => void;
}

export function EducationalToggle({ enabled, onToggle }: EducationalToggleProps) {
  return (
    <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/30 border border-border">
      <GraduationCap className={`h-5 w-5 transition-colors ${enabled ? 'text-primary' : 'text-muted-foreground'}`} />
      <div className="flex-1">
        <p className="text-sm font-medium text-foreground">Educational Mode</p>
        <p className="text-xs text-muted-foreground">
          {enabled ? 'Showing beginner-friendly explanations' : 'Showing technical details'}
        </p>
      </div>
      <Switch checked={enabled} onCheckedChange={onToggle} />
    </div>
  );
}
