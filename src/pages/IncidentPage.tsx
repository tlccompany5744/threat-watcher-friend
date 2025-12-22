import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';
import DashboardLayout from '@/components/dashboard/DashboardLayout';
import { Button } from '@/components/ui/button';
import { ClipboardList, CheckCircle, Circle, AlertTriangle, FileText, Download, Clock } from 'lucide-react';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

interface IncidentStep {
  id: string;
  title: string;
  description: string;
  status: 'pending' | 'in-progress' | 'completed';
  timestamp?: Date;
}

interface LogEntry {
  id: string;
  action: string;
  timestamp: Date;
  severity: 'info' | 'action' | 'success';
}

const IncidentPage = () => {
  const { user, loading } = useAuth();
  const navigate = useNavigate();
  const [currentStep, setCurrentStep] = useState(0);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  const [steps, setSteps] = useState<IncidentStep[]>([
    { id: '1', title: 'Identify & Isolate', description: 'Detect the threat and isolate affected systems', status: 'pending' },
    { id: '2', title: 'Contain Spread', description: 'Prevent ransomware from spreading to other systems', status: 'pending' },
    { id: '3', title: 'Eradicate Threat', description: 'Remove malware and malicious processes', status: 'pending' },
    { id: '4', title: 'Recover Data', description: 'Restore files from backups or decrypt', status: 'pending' },
    { id: '5', title: 'Post-Incident Analysis', description: 'Document findings and improve defenses', status: 'pending' },
  ]);

  useEffect(() => {
    if (!loading && !user) {
      navigate('/auth');
    }
  }, [user, loading, navigate]);

  const addLog = (action: string, severity: 'info' | 'action' | 'success') => {
    setLogs(prev => [{
      id: Date.now().toString(),
      action,
      timestamp: new Date(),
      severity
    }, ...prev]);
  };

  const runIncidentResponse = async () => {
    setIsRunning(true);
    setCurrentStep(0);
    setLogs([]);
    
    const actions = [
      ['🔍 Scanning network for infected hosts...', 'info'],
      ['🚨 Ransomware signature detected on HOST-PC-01', 'action'],
      ['🔌 Disconnecting infected host from network', 'action'],
      ['✅ Host isolated successfully', 'success'],
      ['🔒 Blocking lateral movement paths', 'info'],
      ['🛡️ Updating firewall rules', 'action'],
      ['✅ Containment barriers established', 'success'],
      ['🔎 Identifying malicious processes...', 'info'],
      ['💀 Found: cryptolocker.exe (PID: 4521)', 'action'],
      ['🗑️ Terminating malicious process', 'action'],
      ['✅ Threat eradicated from system', 'success'],
      ['📂 Locating backup systems...', 'info'],
      ['💾 Shadow copies found: 3 restore points', 'action'],
      ['🔄 Initiating file recovery...', 'action'],
      ['✅ 1,247 files recovered successfully', 'success'],
      ['📝 Generating incident report...', 'info'],
      ['📊 Updating threat intelligence database', 'action'],
      ['✅ Post-incident analysis complete', 'success'],
    ];

    for (let i = 0; i < steps.length; i++) {
      setCurrentStep(i);
      setSteps(prev => prev.map((s, idx) => 
        idx === i ? { ...s, status: 'in-progress' } : s
      ));

      // Add relevant logs for this step
      const stepActions = actions.slice(i * 4, (i + 1) * 4);
      for (const [action, severity] of stepActions) {
        await new Promise(resolve => setTimeout(resolve, 800));
        addLog(action as string, severity as 'info' | 'action' | 'success');
      }

      await new Promise(resolve => setTimeout(resolve, 500));
      
      setSteps(prev => prev.map((s, idx) => 
        idx === i ? { ...s, status: 'completed', timestamp: new Date() } : s
      ));
    }

    setIsRunning(false);
    toast.success('Incident response workflow completed!');
  };

  const resetWorkflow = () => {
    setSteps(steps.map(s => ({ ...s, status: 'pending', timestamp: undefined })));
    setLogs([]);
    setCurrentStep(0);
    toast.info('Workflow reset');
  };

  const exportReport = () => {
    const report = `
INCIDENT RESPONSE REPORT
========================
Generated: ${new Date().toLocaleString()}

TIMELINE:
${steps.filter(s => s.timestamp).map(s => 
  `[${s.timestamp?.toLocaleTimeString()}] ${s.title} - ${s.status.toUpperCase()}`
).join('\n')}

ACTIVITY LOG:
${logs.map(l => `[${l.timestamp.toLocaleTimeString()}] ${l.action}`).join('\n')}
    `;
    
    const blob = new Blob([report], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'incident_report.txt';
    a.click();
    toast.success('Report exported');
  };

  if (loading || !user) return null;

  return (
    <DashboardLayout>
      <div className="mb-6">
        <h1 className="font-display text-3xl font-bold text-primary text-glow-cyan tracking-wider flex items-center gap-3">
          <ClipboardList className="w-8 h-8" />
          INCIDENT RESPONSE
        </h1>
        <p className="text-muted-foreground font-mono mt-2">
          Automated incident response workflow and documentation
        </p>
      </div>

      {/* Controls */}
      <div className="flex gap-4 mb-6">
        <Button
          variant="cyber"
          size="lg"
          onClick={runIncidentResponse}
          disabled={isRunning}
        >
          {isRunning ? (
            <>
              <div className="w-4 h-4 border-2 border-primary-foreground/30 border-t-primary-foreground rounded-full animate-spin" />
              RESPONDING...
            </>
          ) : (
            <>
              <AlertTriangle className="w-5 h-5" />
              RUN INCIDENT RESPONSE
            </>
          )}
        </Button>
        <Button variant="outline" onClick={resetWorkflow} disabled={isRunning}>
          Reset Workflow
        </Button>
        <Button variant="outline" onClick={exportReport} disabled={logs.length === 0}>
          <Download className="w-4 h-4 mr-2" />
          Export Report
        </Button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Workflow Steps */}
        <div className="cyber-card p-5 border border-border">
          <div className="relative z-10">
            <h3 className="font-display text-lg font-bold text-foreground tracking-wider mb-4">
              RESPONSE WORKFLOW
            </h3>
            <div className="space-y-4">
              {steps.map((step, idx) => (
                <div
                  key={step.id}
                  className={cn(
                    "flex items-start gap-4 p-4 rounded-lg border transition-all duration-300",
                    step.status === 'pending' && "bg-secondary/30 border-border/50",
                    step.status === 'in-progress' && "bg-warning/10 border-warning/50 animate-pulse",
                    step.status === 'completed' && "bg-success/10 border-success/30"
                  )}
                >
                  <div className="flex-shrink-0 mt-1">
                    {step.status === 'pending' && <Circle className="w-6 h-6 text-muted-foreground" />}
                    {step.status === 'in-progress' && (
                      <div className="w-6 h-6 border-2 border-warning border-t-transparent rounded-full animate-spin" />
                    )}
                    {step.status === 'completed' && <CheckCircle className="w-6 h-6 text-success" />}
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center justify-between">
                      <h4 className="font-display font-bold text-foreground">{step.title}</h4>
                      <span className={cn(
                        "text-xs font-mono px-2 py-1 rounded",
                        step.status === 'pending' && "text-muted-foreground bg-muted",
                        step.status === 'in-progress' && "text-warning bg-warning/20",
                        step.status === 'completed' && "text-success bg-success/20"
                      )}>
                        {step.status.toUpperCase()}
                      </span>
                    </div>
                    <p className="text-sm text-muted-foreground font-mono mt-1">{step.description}</p>
                    {step.timestamp && (
                      <p className="text-xs text-muted-foreground font-mono mt-2 flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        Completed at {step.timestamp.toLocaleTimeString()}
                      </p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Activity Log */}
        <div className="cyber-card p-5 border border-border">
          <div className="relative z-10">
            <h3 className="font-display text-lg font-bold text-foreground tracking-wider mb-4 flex items-center gap-2">
              <FileText className="w-5 h-5 text-primary" />
              INCIDENT LOG
            </h3>
            <div className="space-y-2 max-h-[500px] overflow-y-auto">
              {logs.length === 0 ? (
                <p className="text-muted-foreground font-mono text-sm p-4 text-center">
                  Start incident response to see activity log
                </p>
              ) : (
                logs.map((log) => (
                  <div
                    key={log.id}
                    className={cn(
                      "p-3 rounded-lg border animate-fade-in",
                      log.severity === 'info' && "bg-primary/5 border-primary/20",
                      log.severity === 'action' && "bg-warning/10 border-warning/30",
                      log.severity === 'success' && "bg-success/10 border-success/30"
                    )}
                  >
                    <div className="flex items-center justify-between">
                      <p className="font-mono text-sm text-foreground">{log.action}</p>
                      <span className="text-xs font-mono text-muted-foreground">
                        {log.timestamp.toLocaleTimeString()}
                      </span>
                    </div>
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

export default IncidentPage;
