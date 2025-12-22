import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';
import DashboardLayout from '@/components/dashboard/DashboardLayout';
import { Button } from '@/components/ui/button';
import { Activity, Shield, AlertTriangle, Eye, Cpu, HardDrive, Network, Play, Square, CheckCircle } from 'lucide-react';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

interface ProcessInfo {
  id: string;
  name: string;
  cpu: number;
  memory: number;
  status: 'normal' | 'suspicious' | 'blocked';
  fileChanges: number;
}

interface Detection {
  id: string;
  type: 'info' | 'warning' | 'critical';
  message: string;
  timestamp: Date;
}

const DetectionPage = () => {
  const { user, loading } = useAuth();
  const navigate = useNavigate();
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [processes, setProcesses] = useState<ProcessInfo[]>([]);
  const [detections, setDetections] = useState<Detection[]>([]);
  const [stats, setStats] = useState({
    filesScanned: 0,
    threatsBlocked: 0,
    cpuUsage: 0,
    networkActivity: 0
  });

  useEffect(() => {
    if (!loading && !user) {
      navigate('/auth');
    }
  }, [user, loading, navigate]);

  const addDetection = useCallback((type: 'info' | 'warning' | 'critical', message: string) => {
    setDetections(prev => [{
      id: Date.now().toString(),
      type,
      message,
      timestamp: new Date()
    }, ...prev.slice(0, 19)]);
  }, []);

  // Simulate monitoring
  useEffect(() => {
    if (!isMonitoring) return;

    const interval = setInterval(() => {
      // Update stats
      setStats(prev => ({
        filesScanned: prev.filesScanned + Math.floor(Math.random() * 50),
        threatsBlocked: prev.threatsBlocked,
        cpuUsage: Math.floor(Math.random() * 40) + 10,
        networkActivity: Math.floor(Math.random() * 100)
      }));

      // Simulate process monitoring
      const processNames = ['chrome.exe', 'node.exe', 'explorer.exe', 'python.exe', 'vscode.exe', 'suspicious.exe'];
      const newProcess: ProcessInfo = {
        id: Date.now().toString(),
        name: processNames[Math.floor(Math.random() * processNames.length)],
        cpu: Math.floor(Math.random() * 100),
        memory: Math.floor(Math.random() * 500),
        status: 'normal',
        fileChanges: Math.floor(Math.random() * 10)
      };

      // Check for suspicious behavior
      if (newProcess.name === 'suspicious.exe' || newProcess.fileChanges > 7 || newProcess.cpu > 80) {
        newProcess.status = 'suspicious';
        addDetection('warning', `Suspicious activity detected: ${newProcess.name} (${newProcess.fileChanges} file changes)`);
        
        // Auto-block if very suspicious
        if (newProcess.fileChanges > 8) {
          newProcess.status = 'blocked';
          addDetection('critical', `THREAT BLOCKED: ${newProcess.name} terminated - rapid file encryption detected`);
          setStats(prev => ({ ...prev, threatsBlocked: prev.threatsBlocked + 1 }));
          toast.warning(`Threat blocked: ${newProcess.name}`);
        }
      } else {
        addDetection('info', `Process monitored: ${newProcess.name} - OK`);
      }

      setProcesses(prev => [newProcess, ...prev.slice(0, 9)]);
    }, 2000);

    return () => clearInterval(interval);
  }, [isMonitoring, addDetection]);

  const startMonitoring = () => {
    setIsMonitoring(true);
    addDetection('info', 'Detection engine started - monitoring system activity');
    toast.success('Real-time monitoring activated');
  };

  const stopMonitoring = () => {
    setIsMonitoring(false);
    addDetection('info', 'Detection engine stopped');
    toast.info('Monitoring paused');
  };

  const clearDetections = () => {
    setDetections([]);
    setProcesses([]);
    setStats({ filesScanned: 0, threatsBlocked: 0, cpuUsage: 0, networkActivity: 0 });
  };

  if (loading || !user) return null;

  return (
    <DashboardLayout>
      <div className="mb-6">
        <h1 className="font-display text-3xl font-bold text-warning text-glow-cyan tracking-wider flex items-center gap-3">
          <Activity className="w-8 h-8" />
          DETECTION MONITOR
        </h1>
        <p className="text-muted-foreground font-mono mt-2">
          Real-time behavioral analysis and threat detection
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div className="cyber-card p-4 border border-border">
          <div className="relative z-10 flex items-center gap-3">
            <HardDrive className="w-8 h-8 text-primary" />
            <div>
              <p className="text-2xl font-display font-bold text-foreground">{stats.filesScanned.toLocaleString()}</p>
              <p className="text-xs font-mono text-muted-foreground">Files Scanned</p>
            </div>
          </div>
        </div>
        <div className="cyber-card p-4 border border-border">
          <div className="relative z-10 flex items-center gap-3">
            <Shield className="w-8 h-8 text-success" />
            <div>
              <p className="text-2xl font-display font-bold text-success">{stats.threatsBlocked}</p>
              <p className="text-xs font-mono text-muted-foreground">Threats Blocked</p>
            </div>
          </div>
        </div>
        <div className="cyber-card p-4 border border-border">
          <div className="relative z-10 flex items-center gap-3">
            <Cpu className="w-8 h-8 text-warning" />
            <div>
              <p className="text-2xl font-display font-bold text-foreground">{stats.cpuUsage}%</p>
              <p className="text-xs font-mono text-muted-foreground">CPU Usage</p>
            </div>
          </div>
        </div>
        <div className="cyber-card p-4 border border-border">
          <div className="relative z-10 flex items-center gap-3">
            <Network className="w-8 h-8 text-primary" />
            <div>
              <p className="text-2xl font-display font-bold text-foreground">{stats.networkActivity}%</p>
              <p className="text-xs font-mono text-muted-foreground">Network Activity</p>
            </div>
          </div>
        </div>
      </div>

      {/* Controls */}
      <div className="flex gap-4 mb-6">
        <Button
          variant={isMonitoring ? "danger" : "success"}
          size="lg"
          onClick={isMonitoring ? stopMonitoring : startMonitoring}
        >
          {isMonitoring ? (
            <>
              <Square className="w-5 h-5" />
              STOP MONITORING
            </>
          ) : (
            <>
              <Play className="w-5 h-5" />
              START MONITORING
            </>
          )}
        </Button>
        <Button variant="outline" onClick={clearDetections}>
          Clear Logs
        </Button>
        <div className="flex items-center gap-2 ml-auto">
          <div className={cn(
            "w-3 h-3 rounded-full",
            isMonitoring ? "bg-success animate-pulse" : "bg-muted"
          )} />
          <span className="font-mono text-sm text-muted-foreground">
            {isMonitoring ? 'MONITORING ACTIVE' : 'MONITORING PAUSED'}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Process Monitor */}
        <div className="cyber-card p-5 border border-border">
          <div className="relative z-10">
            <h3 className="font-display text-lg font-bold text-foreground tracking-wider mb-4 flex items-center gap-2">
              <Eye className="w-5 h-5 text-primary" />
              PROCESS MONITOR
            </h3>
            <div className="space-y-2 max-h-80 overflow-y-auto">
              {processes.length === 0 ? (
                <p className="text-muted-foreground font-mono text-sm p-4 text-center">
                  Start monitoring to see process activity
                </p>
              ) : (
                processes.map((proc) => (
                  <div
                    key={proc.id}
                    className={cn(
                      "flex items-center gap-3 p-3 rounded-lg border transition-all",
                      proc.status === 'normal' && "bg-secondary/30 border-border/50",
                      proc.status === 'suspicious' && "bg-warning/10 border-warning/30",
                      proc.status === 'blocked' && "bg-destructive/10 border-destructive/30"
                    )}
                  >
                    <div className={cn(
                      "w-2 h-2 rounded-full",
                      proc.status === 'normal' && "bg-success",
                      proc.status === 'suspicious' && "bg-warning animate-pulse",
                      proc.status === 'blocked' && "bg-destructive"
                    )} />
                    <div className="flex-1">
                      <p className="font-mono text-sm text-foreground">{proc.name}</p>
                      <p className="text-xs text-muted-foreground font-mono">
                        CPU: {proc.cpu}% | MEM: {proc.memory}MB | Files: {proc.fileChanges}
                      </p>
                    </div>
                    {proc.status === 'blocked' && (
                      <span className="text-xs font-mono text-destructive px-2 py-1 bg-destructive/20 rounded">
                        BLOCKED
                      </span>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Detection Log */}
        <div className="cyber-card p-5 border border-border">
          <div className="relative z-10">
            <h3 className="font-display text-lg font-bold text-foreground tracking-wider mb-4 flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-warning" />
              DETECTION LOG
            </h3>
            <div className="space-y-2 max-h-80 overflow-y-auto">
              {detections.length === 0 ? (
                <p className="text-muted-foreground font-mono text-sm p-4 text-center">
                  No detections yet
                </p>
              ) : (
                detections.map((det) => (
                  <div
                    key={det.id}
                    className={cn(
                      "p-3 rounded-lg border animate-fade-in",
                      det.type === 'info' && "bg-primary/5 border-primary/20",
                      det.type === 'warning' && "bg-warning/10 border-warning/30",
                      det.type === 'critical' && "bg-destructive/10 border-destructive/30"
                    )}
                  >
                    <div className="flex items-center gap-2">
                      {det.type === 'info' && <CheckCircle className="w-4 h-4 text-primary" />}
                      {det.type === 'warning' && <AlertTriangle className="w-4 h-4 text-warning" />}
                      {det.type === 'critical' && <Shield className="w-4 h-4 text-destructive" />}
                      <span className="text-xs font-mono text-muted-foreground">
                        {det.timestamp.toLocaleTimeString()}
                      </span>
                    </div>
                    <p className="font-mono text-sm text-foreground mt-1">{det.message}</p>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default DetectionPage;
