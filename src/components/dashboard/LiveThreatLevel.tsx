import { useState, useEffect } from 'react';
import { useSystemInfo } from '@/hooks/useSystemInfo';
import { Shield, AlertTriangle, AlertOctagon, CheckCircle, Wifi, WifiOff } from 'lucide-react';
import { cn } from '@/lib/utils';

type ThreatLevelType = 'low' | 'medium' | 'high' | 'critical';

interface ThreatConfig {
  label: string;
  color: string;
  bgColor: string;
  icon: typeof Shield;
  description: string;
}

const threatConfigs: Record<ThreatLevelType, ThreatConfig> = {
  low: {
    label: 'LOW',
    color: 'text-success',
    bgColor: 'bg-success/20',
    icon: CheckCircle,
    description: 'All systems nominal',
  },
  medium: {
    label: 'MEDIUM',
    color: 'text-primary',
    bgColor: 'bg-primary/20',
    icon: Shield,
    description: 'Standard monitoring active',
  },
  high: {
    label: 'HIGH',
    color: 'text-warning',
    bgColor: 'bg-warning/20',
    icon: AlertTriangle,
    description: 'Elevated activity detected',
  },
  critical: {
    label: 'CRITICAL',
    color: 'text-destructive',
    bgColor: 'bg-destructive/20',
    icon: AlertOctagon,
    description: 'Immediate action required',
  },
};

const LiveThreatLevel = () => {
  const { systemInfo } = useSystemInfo(2000);
  const [level, setLevel] = useState<ThreatLevelType>('low');
  const [threatFactors, setThreatFactors] = useState<string[]>([]);

  // Calculate threat level based on real system data
  useEffect(() => {
    if (!systemInfo) return;

    const factors: string[] = [];
    let threatScore = 0;

    // Check network status
    if (!systemInfo.network.online) {
      threatScore += 30;
      factors.push('Network offline - connectivity issue');
    }

    // Check network quality
    if (systemInfo.network.effectiveType === '2g' || systemInfo.network.effectiveType === 'slow-2g') {
      threatScore += 10;
      factors.push('Slow network connection detected');
    }

    // Check high latency
    if (systemInfo.network.rtt > 500) {
      threatScore += 15;
      factors.push(`High network latency: ${systemInfo.network.rtt}ms`);
    }

    // Check battery
    if (systemInfo.battery) {
      if (systemInfo.battery.level < 10 && !systemInfo.battery.charging) {
        threatScore += 20;
        factors.push('Critical battery level');
      } else if (systemInfo.battery.level < 20 && !systemInfo.battery.charging) {
        threatScore += 10;
        factors.push('Low battery warning');
      }
    }

    // Check memory usage (if available)
    if (systemInfo.memory.usedJSHeapSize && systemInfo.memory.jsHeapSizeLimit) {
      const memoryUsage = systemInfo.memory.usedJSHeapSize / systemInfo.memory.jsHeapSizeLimit;
      if (memoryUsage > 0.9) {
        threatScore += 25;
        factors.push('Critical memory usage detected');
      } else if (memoryUsage > 0.7) {
        threatScore += 10;
        factors.push('High memory usage');
      }
    }

    // Check if cookies disabled (security concern for auth)
    if (!systemInfo.cookiesEnabled) {
      threatScore += 5;
      factors.push('Cookies disabled - may affect authentication');
    }

    // Determine threat level
    let newLevel: ThreatLevelType;
    if (threatScore >= 50) {
      newLevel = 'critical';
    } else if (threatScore >= 30) {
      newLevel = 'high';
    } else if (threatScore >= 10) {
      newLevel = 'medium';
    } else {
      newLevel = 'low';
    }

    setLevel(newLevel);
    setThreatFactors(factors);
  }, [systemInfo]);

  const config = threatConfigs[level];
  const Icon = config.icon;

  return (
    <div className="cyber-card p-5 border border-border">
      <div className="relative z-10">
        <h3 className="font-display text-lg font-bold text-foreground tracking-wider mb-4">
          REAL-TIME THREAT LEVEL
        </h3>

        <div className="flex items-center gap-4">
          <div className={cn(
            "p-4 rounded-xl transition-all duration-500",
            config.bgColor,
            level === 'critical' && 'animate-pulse'
          )}>
            <Icon className={cn("w-10 h-10", config.color)} />
          </div>

          <div className="flex-1">
            <p className={cn(
              "font-display text-2xl font-bold tracking-widest",
              config.color
            )}>
              {config.label}
            </p>
            <p className="text-sm text-muted-foreground font-mono mt-1">
              {config.description}
            </p>
          </div>
        </div>

        {/* Threat meter */}
        <div className="mt-4">
          <div className="flex justify-between text-xs font-mono text-muted-foreground mb-2">
            <span>LOW</span>
            <span>CRITICAL</span>
          </div>
          <div className="h-2 bg-muted rounded-full overflow-hidden">
            <div
              className={cn(
                "h-full rounded-full transition-all duration-500",
                level === 'low' && 'w-1/4 bg-success',
                level === 'medium' && 'w-1/2 bg-primary',
                level === 'high' && 'w-3/4 bg-warning',
                level === 'critical' && 'w-full bg-destructive animate-pulse'
              )}
            />
          </div>
        </div>

        {/* Threat Factors */}
        {threatFactors.length > 0 && (
          <div className="mt-4 space-y-2">
            <p className="text-xs font-mono text-muted-foreground uppercase tracking-wider">
              DETECTED FACTORS:
            </p>
            {threatFactors.map((factor, index) => (
              <div 
                key={index}
                className="flex items-center gap-2 text-xs font-mono text-warning"
              >
                <AlertTriangle className="w-3 h-3 flex-shrink-0" />
                <span>{factor}</span>
              </div>
            ))}
          </div>
        )}

        {/* Connection Status */}
        <div className="mt-4 pt-4 border-t border-border">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {systemInfo?.network.online ? (
                <Wifi className="w-4 h-4 text-success" />
              ) : (
                <WifiOff className="w-4 h-4 text-destructive" />
              )}
              <span className="text-xs font-mono text-muted-foreground">
                {systemInfo?.network.online ? 'Connected' : 'Disconnected'}
              </span>
            </div>
            <span className="text-xs font-mono text-muted-foreground">
              {systemInfo?.timestamp?.toLocaleTimeString()}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LiveThreatLevel;
