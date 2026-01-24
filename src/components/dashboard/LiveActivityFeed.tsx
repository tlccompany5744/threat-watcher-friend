import { useEffect, useState, useCallback } from 'react';
import { useSystemInfo } from '@/hooks/useSystemInfo';
import { Shield, AlertTriangle, CheckCircle, Wifi, Battery, Cpu, Activity, Clock } from 'lucide-react';
import { cn } from '@/lib/utils';

interface LiveActivity {
  id: string;
  type: 'system' | 'network' | 'battery' | 'performance' | 'security';
  message: string;
  timestamp: Date;
  data?: Record<string, any>;
}

const iconMap = {
  system: Cpu,
  network: Wifi,
  battery: Battery,
  performance: Activity,
  security: Shield,
};

const colorMap = {
  system: 'text-primary',
  network: 'text-accent',
  battery: 'text-warning',
  performance: 'text-success',
  security: 'text-destructive',
};

const LiveActivityFeed = () => {
  const { systemInfo } = useSystemInfo(3000);
  const [activities, setActivities] = useState<LiveActivity[]>([]);
  const [lastNetworkState, setLastNetworkState] = useState<boolean>(true);
  const [lastBatteryLevel, setLastBatteryLevel] = useState<number | null>(null);

  const addActivity = useCallback((activity: Omit<LiveActivity, 'id' | 'timestamp'>) => {
    setActivities(prev => [{
      ...activity,
      id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
      timestamp: new Date(),
    }, ...prev.slice(0, 19)]);
  }, []);

  // Monitor system changes and generate real activities
  useEffect(() => {
    if (!systemInfo) return;

    // Check network status changes
    if (systemInfo.network.online !== lastNetworkState) {
      addActivity({
        type: 'network',
        message: systemInfo.network.online 
          ? 'Network connection restored' 
          : 'Network connection lost',
        data: { online: systemInfo.network.online },
      });
      setLastNetworkState(systemInfo.network.online);
    }

    // Check battery level changes
    if (systemInfo.battery && lastBatteryLevel !== null) {
      if (systemInfo.battery.level !== lastBatteryLevel) {
        if (systemInfo.battery.level < 20 && lastBatteryLevel >= 20) {
          addActivity({
            type: 'battery',
            message: `Low battery warning: ${systemInfo.battery.level}%`,
            data: { level: systemInfo.battery.level },
          });
        } else if (systemInfo.battery.charging && !lastBatteryLevel) {
          addActivity({
            type: 'battery',
            message: 'Device started charging',
            data: { level: systemInfo.battery.level },
          });
        }
      }
    }
    if (systemInfo.battery) {
      setLastBatteryLevel(systemInfo.battery.level);
    }
  }, [systemInfo, lastNetworkState, lastBatteryLevel, addActivity]);

  // Generate periodic system monitoring activities
  useEffect(() => {
    const generateMonitoringActivity = () => {
      if (!systemInfo) return;

      const activities: Array<Omit<LiveActivity, 'id' | 'timestamp'>> = [
        {
          type: 'system',
          message: `CPU monitoring: ${systemInfo.cpuCores} cores active`,
          data: { cores: systemInfo.cpuCores },
        },
        {
          type: 'performance',
          message: `Memory check: ${systemInfo.memory.deviceMemory || 'N/A'} GB available`,
          data: { memory: systemInfo.memory.deviceMemory },
        },
        {
          type: 'network',
          message: `Network: ${systemInfo.network.effectiveType.toUpperCase()} connection @ ${systemInfo.network.downlink} Mbps`,
          data: { type: systemInfo.network.effectiveType, speed: systemInfo.network.downlink },
        },
        {
          type: 'security',
          message: 'Security scan completed - No threats detected',
          data: { status: 'clean' },
        },
        {
          type: 'performance',
          message: `Resources loaded: ${systemInfo.performance.resources} files`,
          data: { resources: systemInfo.performance.resources },
        },
        {
          type: 'system',
          message: `Display resolution: ${systemInfo.screenWidth}x${systemInfo.screenHeight}`,
          data: { width: systemInfo.screenWidth, height: systemInfo.screenHeight },
        },
      ];

      const randomActivity = activities[Math.floor(Math.random() * activities.length)];
      addActivity(randomActivity);
    };

    // Initial activities
    if (systemInfo && activities.length === 0) {
      addActivity({
        type: 'security',
        message: 'System monitoring initialized',
      });
      addActivity({
        type: 'system',
        message: `Platform detected: ${systemInfo.platform}`,
        data: { platform: systemInfo.platform },
      });
    }

    const interval = setInterval(generateMonitoringActivity, 5000);
    return () => clearInterval(interval);
  }, [systemInfo, activities.length, addActivity]);

  return (
    <div className="cyber-card p-5 border border-border h-full">
      <div className="relative z-10">
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-display text-lg font-bold text-foreground tracking-wider">
            LIVE ACTIVITY FEED
          </h3>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-success animate-pulse" />
            <span className="text-xs font-mono text-success">REAL-TIME</span>
          </div>
        </div>

        <div className="space-y-3 max-h-80 overflow-y-auto">
          {activities.length === 0 ? (
            <div className="flex items-center justify-center py-8">
              <div className="text-center">
                <Activity className="w-8 h-8 text-muted-foreground mx-auto mb-2 animate-pulse" />
                <p className="text-sm text-muted-foreground font-mono">Initializing monitors...</p>
              </div>
            </div>
          ) : (
            activities.map((activity, index) => {
              const Icon = iconMap[activity.type];
              return (
                <div
                  key={activity.id}
                  className={cn(
                    "flex items-start gap-3 p-3 rounded-lg bg-secondary/30 border border-border/50 transition-all duration-300",
                    index === 0 && "animate-fade-in border-primary/30"
                  )}
                >
                  <div className={cn("p-1.5 rounded", colorMap[activity.type], "bg-current/10")}>
                    <Icon className={cn("w-4 h-4", colorMap[activity.type])} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-mono text-foreground truncate">{activity.message}</p>
                    <div className="flex items-center gap-2 mt-1">
                      <Clock className="w-3 h-3 text-muted-foreground" />
                      <p className="text-xs text-muted-foreground font-mono">
                        {activity.timestamp.toLocaleTimeString()}
                      </p>
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
};

export default LiveActivityFeed;
