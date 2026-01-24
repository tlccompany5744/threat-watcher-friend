import { useSystemInfo } from '@/hooks/useSystemInfo';
import { Cpu, HardDrive, Wifi, Battery, Monitor, Clock, Zap, Globe } from 'lucide-react';
import { cn } from '@/lib/utils';

const RealTimeStats = () => {
  const { systemInfo, isLoading } = useSystemInfo(2000);

  if (isLoading || !systemInfo) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="cyber-card p-5 border border-border animate-pulse">
            <div className="h-20 bg-muted rounded" />
          </div>
        ))}
      </div>
    );
  }

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  const formatTime = (seconds: number) => {
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    return `${hrs.toString().padStart(2, '0')}:${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  const getBatteryColor = () => {
    if (!systemInfo.battery) return 'text-muted-foreground';
    if (systemInfo.battery.charging) return 'text-success';
    if (systemInfo.battery.level > 50) return 'text-success';
    if (systemInfo.battery.level > 20) return 'text-warning';
    return 'text-destructive';
  };

  const getNetworkColor = () => {
    if (!systemInfo.network.online) return 'text-destructive';
    if (systemInfo.network.effectiveType === '4g') return 'text-success';
    if (systemInfo.network.effectiveType === '3g') return 'text-warning';
    return 'text-primary';
  };

  return (
    <div className="space-y-6">
      {/* Live indicator */}
      <div className="flex items-center gap-2 mb-4">
        <div className="w-2 h-2 rounded-full bg-success animate-pulse" />
        <span className="text-xs font-mono text-success">LIVE SYSTEM MONITORING</span>
        <span className="text-xs font-mono text-muted-foreground">
          Last updated: {systemInfo.timestamp.toLocaleTimeString()}
        </span>
      </div>

      {/* Primary Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* CPU Cores */}
        <div className="cyber-card p-5 border border-border hover:border-primary/50 transition-all">
          <div className="relative z-10 flex items-start justify-between">
            <div className="space-y-2">
              <p className="text-xs font-mono text-muted-foreground uppercase tracking-wider">CPU CORES</p>
              <p className="text-2xl font-display font-bold text-foreground">{systemInfo.cpuCores}</p>
              <p className="text-xs font-mono text-primary">Hardware Threads</p>
            </div>
            <div className="p-3 rounded-lg bg-primary/10 text-primary">
              <Cpu className="w-6 h-6" />
            </div>
          </div>
        </div>

        {/* Device Memory */}
        <div className="cyber-card p-5 border border-border hover:border-success/50 transition-all">
          <div className="relative z-10 flex items-start justify-between">
            <div className="space-y-2">
              <p className="text-xs font-mono text-muted-foreground uppercase tracking-wider">DEVICE MEMORY</p>
              <p className="text-2xl font-display font-bold text-foreground">
                {systemInfo.memory.deviceMemory > 0 ? `${systemInfo.memory.deviceMemory} GB` : 'N/A'}
              </p>
              <p className="text-xs font-mono text-success">
                {systemInfo.memory.usedJSHeapSize 
                  ? `JS Heap: ${formatBytes(systemInfo.memory.usedJSHeapSize)}`
                  : 'Heap data unavailable'}
              </p>
            </div>
            <div className="p-3 rounded-lg bg-success/10 text-success">
              <HardDrive className="w-6 h-6" />
            </div>
          </div>
        </div>

        {/* Network Status */}
        <div className="cyber-card p-5 border border-border hover:border-accent/50 transition-all">
          <div className="relative z-10 flex items-start justify-between">
            <div className="space-y-2">
              <p className="text-xs font-mono text-muted-foreground uppercase tracking-wider">NETWORK</p>
              <p className={cn("text-2xl font-display font-bold", getNetworkColor())}>
                {systemInfo.network.online ? 'ONLINE' : 'OFFLINE'}
              </p>
              <p className="text-xs font-mono text-muted-foreground">
                {systemInfo.network.effectiveType.toUpperCase()} • {systemInfo.network.downlink} Mbps
              </p>
            </div>
            <div className={cn("p-3 rounded-lg", systemInfo.network.online ? "bg-success/10" : "bg-destructive/10")}>
              <Wifi className={cn("w-6 h-6", getNetworkColor())} />
            </div>
          </div>
        </div>

        {/* Battery Status */}
        <div className="cyber-card p-5 border border-border hover:border-warning/50 transition-all">
          <div className="relative z-10 flex items-start justify-between">
            <div className="space-y-2">
              <p className="text-xs font-mono text-muted-foreground uppercase tracking-wider">BATTERY</p>
              <p className={cn("text-2xl font-display font-bold", getBatteryColor())}>
                {systemInfo.battery ? `${systemInfo.battery.level}%` : 'N/A'}
              </p>
              <p className="text-xs font-mono text-muted-foreground">
                {systemInfo.battery?.charging ? '⚡ Charging' : 'On Battery'}
              </p>
            </div>
            <div className={cn("p-3 rounded-lg", systemInfo.battery?.charging ? "bg-success/10" : "bg-warning/10")}>
              <Battery className={cn("w-6 h-6", getBatteryColor())} />
            </div>
          </div>
        </div>
      </div>

      {/* Secondary Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Display Info */}
        <div className="cyber-card p-5 border border-border hover:border-primary/50 transition-all">
          <div className="relative z-10 flex items-start justify-between">
            <div className="space-y-2">
              <p className="text-xs font-mono text-muted-foreground uppercase tracking-wider">DISPLAY</p>
              <p className="text-lg font-display font-bold text-foreground">
                {systemInfo.screenWidth} × {systemInfo.screenHeight}
              </p>
              <p className="text-xs font-mono text-primary">
                {systemInfo.colorDepth}-bit • {systemInfo.pixelRatio}x DPI
              </p>
            </div>
            <div className="p-3 rounded-lg bg-primary/10 text-primary">
              <Monitor className="w-6 h-6" />
            </div>
          </div>
        </div>

        {/* Session Uptime */}
        <div className="cyber-card p-5 border border-border hover:border-accent/50 transition-all">
          <div className="relative z-10 flex items-start justify-between">
            <div className="space-y-2">
              <p className="text-xs font-mono text-muted-foreground uppercase tracking-wider">SESSION UPTIME</p>
              <p className="text-lg font-display font-bold text-foreground font-mono">
                {formatTime(systemInfo.uptime)}
              </p>
              <p className="text-xs font-mono text-accent">Active Monitoring</p>
            </div>
            <div className="p-3 rounded-lg bg-accent/10 text-accent">
              <Clock className="w-6 h-6" />
            </div>
          </div>
        </div>

        {/* Page Performance */}
        <div className="cyber-card p-5 border border-border hover:border-success/50 transition-all">
          <div className="relative z-10 flex items-start justify-between">
            <div className="space-y-2">
              <p className="text-xs font-mono text-muted-foreground uppercase tracking-wider">PAGE LOAD</p>
              <p className="text-lg font-display font-bold text-foreground">
                {systemInfo.performance.pageLoadTime}ms
              </p>
              <p className="text-xs font-mono text-success">
                FCP: {systemInfo.performance.firstContentfulPaint || 'N/A'}ms
              </p>
            </div>
            <div className="p-3 rounded-lg bg-success/10 text-success">
              <Zap className="w-6 h-6" />
            </div>
          </div>
        </div>

        {/* Resources Loaded */}
        <div className="cyber-card p-5 border border-border hover:border-warning/50 transition-all">
          <div className="relative z-10 flex items-start justify-between">
            <div className="space-y-2">
              <p className="text-xs font-mono text-muted-foreground uppercase tracking-wider">RESOURCES</p>
              <p className="text-lg font-display font-bold text-foreground">
                {systemInfo.performance.resources}
              </p>
              <p className="text-xs font-mono text-warning">
                {formatBytes(systemInfo.performance.transferSize)} transferred
              </p>
            </div>
            <div className="p-3 rounded-lg bg-warning/10 text-warning">
              <Globe className="w-6 h-6" />
            </div>
          </div>
        </div>
      </div>

      {/* System Details Panel */}
      <div className="cyber-card p-5 border border-border">
        <div className="relative z-10">
          <h3 className="font-display text-lg font-bold text-foreground tracking-wider mb-4">
            SYSTEM DETAILS
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-sm">
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Platform:</span>
                <span className="text-foreground">{systemInfo.platform}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Language:</span>
                <span className="text-foreground">{systemInfo.language}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Cookies:</span>
                <span className={systemInfo.cookiesEnabled ? 'text-success' : 'text-destructive'}>
                  {systemInfo.cookiesEnabled ? 'Enabled' : 'Disabled'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Do Not Track:</span>
                <span className={systemInfo.doNotTrack ? 'text-warning' : 'text-muted-foreground'}>
                  {systemInfo.doNotTrack ? 'Enabled' : 'Disabled'}
                </span>
              </div>
            </div>
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Network Type:</span>
                <span className="text-foreground">{systemInfo.network.type}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Connection:</span>
                <span className="text-foreground">{systemInfo.network.effectiveType.toUpperCase()}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Latency (RTT):</span>
                <span className="text-foreground">{systemInfo.network.rtt}ms</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">DOM Loaded:</span>
                <span className="text-foreground">{systemInfo.performance.domContentLoaded}ms</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default RealTimeStats;
