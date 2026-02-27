import { useState } from 'react';
import { useAgentTelemetry, type AgentEvent } from '@/hooks/useAgentTelemetry';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import {
  Wifi, WifiOff, Trash2, FileText, FilePlus, FileX, FileEdit,
  FolderOpen, Clock, Radio, AlertTriangle
} from 'lucide-react';

const eventIcons: Record<string, typeof FileText> = {
  add: FilePlus,
  addDir: FolderOpen,
  change: FileEdit,
  unlink: FileX,
  unlinkDir: FileX,
};

const eventColors: Record<string, string> = {
  add: 'text-success',
  addDir: 'text-primary',
  change: 'text-warning',
  unlink: 'text-destructive',
  unlinkDir: 'text-destructive',
};

const AgentTelemetryPanel = () => {
  const [enabled, setEnabled] = useState(false);

  const { events, connected, error, clearEvents } = useAgentTelemetry({ enabled });

  const getFileName = (path: string) => {
    const parts = path.replace(/\\/g, '/').split('/');
    return parts[parts.length - 1] || path;
  };

  const getFileDir = (path: string) => {
    const normalized = path.replace(/\\/g, '/');
    const parts = normalized.split('/');
    parts.pop();
    return parts.slice(-2).join('/');
  };

  const suspiciousCount = events.filter(e => {
    const ext = e.path.split('.').pop()?.toLowerCase();
    return e.event === 'add' && (ext === 'encrypted' || ext === 'locked' || ext === 'cry');
  }).length;

  const recentRate = events.filter(
    e => Date.now() - e.time < 5000
  ).length;

  return (
    <div className="cyber-card p-5 border border-border mb-6">
      <div className="relative z-10">
        {/* Header */}
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-display text-lg font-bold text-foreground tracking-wider flex items-center gap-2">
            <Radio className="w-5 h-5 text-primary" />
            AGENT TELEMETRY
          </h3>
          <div className="flex items-center gap-2">
            {enabled && (
              <div className="flex items-center gap-2">
                {connected ? (
                  <>
                    <div className="w-2 h-2 rounded-full bg-success animate-pulse" />
                    <span className="text-xs font-mono text-success">CONNECTED</span>
                  </>
                ) : (
                  <>
                    <div className="w-2 h-2 rounded-full bg-destructive animate-pulse" />
                    <span className="text-xs font-mono text-destructive">CONNECTING...</span>
                  </>
                )}
              </div>
            )}
            <Button
              size="sm"
              variant={enabled ? 'danger' : 'cyber'}
              onClick={() => setEnabled(!enabled)}
            >
              {enabled ? <WifiOff className="w-4 h-4 mr-1" /> : <Wifi className="w-4 h-4 mr-1" />}
              {enabled ? 'Disconnect' : 'Connect Agent'}
            </Button>
          </div>
        </div>

        {error && (
          <div className="mb-3 p-2 rounded bg-destructive/10 border border-destructive/30 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-destructive" />
            <span className="text-xs font-mono text-destructive">{error}</span>
          </div>
        )}

        {/* Status indicators */}
        {enabled && connected && (
          <div className="grid grid-cols-3 gap-3 mb-4">
            <div className="text-center p-2 rounded bg-secondary/30">
              <p className="text-xs font-mono text-muted-foreground">Events</p>
              <p className="text-lg font-display font-bold text-foreground">{events.length}</p>
            </div>
            <div className="text-center p-2 rounded bg-secondary/30">
              <p className="text-xs font-mono text-muted-foreground">Rate (5s)</p>
              <p className={cn(
                "text-lg font-display font-bold",
                recentRate > 20 ? "text-destructive" : recentRate > 5 ? "text-warning" : "text-success"
              )}>{recentRate}/5s</p>
            </div>
            <div className="text-center p-2 rounded bg-secondary/30">
              <p className="text-xs font-mono text-muted-foreground">Suspicious</p>
              <p className={cn(
                "text-lg font-display font-bold",
                suspiciousCount > 0 ? "text-destructive" : "text-success"
              )}>{suspiciousCount}</p>
            </div>
          </div>
        )}

        {/* Event feed */}
        {enabled && connected && (
          <div className="space-y-1">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono text-muted-foreground">LIVE FILE EVENTS</span>
              {events.length > 0 && (
                <Button size="sm" variant="ghost" onClick={clearEvents}>
                  <Trash2 className="w-3 h-3 mr-1" /> Clear
                </Button>
              )}
            </div>
            <div className="max-h-64 overflow-y-auto space-y-1">
              {events.length === 0 ? (
                <p className="text-xs font-mono text-muted-foreground text-center py-6">
                  Waiting for file system events from agent...
                </p>
              ) : (
                events.slice(0, 50).map((evt) => {
                  const Icon = eventIcons[evt.event] || FileText;
                  const color = eventColors[evt.event] || 'text-muted-foreground';
                  return (
                    <div
                      key={evt.id}
                      className="flex items-center gap-2 p-2 rounded bg-secondary/20 border border-border/30 text-xs font-mono"
                    >
                      <Icon className={cn("w-3.5 h-3.5 flex-shrink-0", color)} />
                      <span className={cn("font-bold uppercase w-14 flex-shrink-0", color)}>
                        {evt.event}
                      </span>
                      <span className="text-foreground truncate flex-1" title={evt.path}>
                        <span className="text-muted-foreground">{getFileDir(evt.path)}/</span>
                        {getFileName(evt.path)}
                      </span>
                      <span className="text-muted-foreground flex-shrink-0 flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {evt.receivedAt.toLocaleTimeString()}
                      </span>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        )}

        {/* Not connected guide */}
        {!enabled && (
          <div className="p-4 rounded-lg bg-secondary/20 border border-border/50">
            <p className="text-sm font-mono text-muted-foreground mb-3">
              Connect to see <span className="text-primary">real file system telemetry</span> from your local agent.
            </p>
            <div className="space-y-2 text-xs font-mono text-foreground/70">
              <p className="text-primary font-bold">Quick Setup:</p>
              <p>1. Run the agent: <code className="px-1 py-0.5 bg-secondary rounded text-accent">node agent.js</code></p>
              <p>2. Click <span className="text-success">"Connect Agent"</span> above</p>
              <p className="text-muted-foreground mt-2">No local backend needed — agent sends data directly to the cloud.</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default AgentTelemetryPanel;
