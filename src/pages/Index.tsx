import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';
import DashboardLayout from '@/components/dashboard/DashboardLayout';
import RealTimeStats from '@/components/dashboard/RealTimeStats';
import LiveActivityFeed from '@/components/dashboard/LiveActivityFeed';
import LiveThreatLevel from '@/components/dashboard/LiveThreatLevel';
import { Lock, CheckCircle, Activity, AlertTriangle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Link } from 'react-router-dom';

const Index = () => {
  const { user, loading } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (!loading && !user) {
      navigate('/auth');
    }
  }, [user, loading, navigate]);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="animate-pulse text-primary font-display text-xl">
          INITIALIZING SYSTEM MONITORING...
        </div>
      </div>
    );
  }

  if (!user) return null;

  return (
    <DashboardLayout>
      {/* Header */}
      <div className="mb-8">
        <h1 className="font-display text-3xl font-bold text-primary text-glow-cyan tracking-wider">
          SECURITY COMMAND CENTER
        </h1>
        <p className="text-muted-foreground font-mono mt-2">
          Real-Time System Monitoring & Security Dashboard
        </p>
      </div>

      {/* Real-Time Stats Grid */}
      <RealTimeStats />

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8 mt-8">
        <div className="lg:col-span-2">
          <LiveActivityFeed />
        </div>
        <div>
          <LiveThreatLevel />
        </div>
      </div>

      {/* Quick Actions */}
      <div className="cyber-card p-6 border border-border">
        <div className="relative z-10">
          <h3 className="font-display text-lg font-bold text-foreground tracking-wider mb-4">
            QUICK ACTIONS
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <Link to="/encrypt">
              <Button variant="danger" className="w-full justify-start gap-3">
                <Lock className="w-5 h-5" />
                <span>Run Encryption Sim</span>
              </Button>
            </Link>
            <Link to="/decrypt">
              <Button variant="success" className="w-full justify-start gap-3">
                <CheckCircle className="w-5 h-5" />
                <span>File Recovery</span>
              </Button>
            </Link>
            <Link to="/detection">
              <Button variant="warning" className="w-full justify-start gap-3">
                <Activity className="w-5 h-5" />
                <span>Detection Monitor</span>
              </Button>
            </Link>
            <Link to="/assistant">
              <Button variant="outline" className="w-full justify-start gap-3">
                <AlertTriangle className="w-5 h-5" />
                <span>AI Assistant</span>
              </Button>
            </Link>
          </div>
        </div>
      </div>

      {/* Info Banner */}
      <div className="mt-6 p-4 rounded-lg bg-primary/10 border border-primary/30">
        <div className="flex items-center gap-3">
          <Activity className="w-5 h-5 text-primary flex-shrink-0" />
          <p className="text-sm font-mono text-primary">
            <strong>LIVE MONITORING:</strong> Dashboard displays real system data using Browser APIs (CPU cores, memory, network, battery, performance metrics).
          </p>
        </div>
      </div>

      {/* Warning Banner */}
      <div className="mt-4 p-4 rounded-lg bg-warning/10 border border-warning/30">
        <div className="flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-warning flex-shrink-0" />
          <p className="text-sm font-mono text-warning">
            <strong>EDUCATIONAL ENVIRONMENT:</strong> This platform is for cybersecurity training only. 
            Never deploy these techniques on real systems.
          </p>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default Index;
