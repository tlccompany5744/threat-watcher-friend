import { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';
import DashboardLayout from '@/components/dashboard/DashboardLayout';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import {
  Crosshair, Play, Square, RotateCcw, Download, Shield, AlertTriangle,
  Brain, Trophy, Eye, Zap, ChevronRight, Clock, Target, BarChart3,
  FileWarning, Activity, Lock, GraduationCap, Siren
} from 'lucide-react';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';
import { killChainSteps, type KillStage } from '@/simulation/killChain';
import { analyzeBehavior, generateMetricsForStage, type BehaviorAnalysis } from '@/simulation/behaviorAnalyzer';
import { getMentorInsight, getDecisionMentorAdvice, type MentorMode } from '@/simulation/mentorEngine';
import { calculateScore, generateForensicsReport, type ScoreMetrics, type ScoreResult } from '@/simulation/scoringEngine';

type SimPhase = 'idle' | 'running' | 'decision' | 'post-decision' | 'complete';

const CyberRangePage = () => {
  const { user, loading } = useAuth();
  const navigate = useNavigate();

  // Simulation state
  const [phase, setPhase] = useState<SimPhase>('idle');
  const [currentStageIdx, setCurrentStageIdx] = useState(-1);
  const [expandedStage, setExpandedStage] = useState<number | null>(null);
  const [mentorMode, setMentorMode] = useState<MentorMode>('student');
  const [behaviorAnalysis, setBehaviorAnalysis] = useState<BehaviorAnalysis | null>(null);
  const [decision, setDecision] = useState<string | null>(null);
  const [decisionAdvice, setDecisionAdvice] = useState<string>('');
  const [scoreResult, setScoreResult] = useState<ScoreResult | null>(null);
  const [killChainLog, setKillChainLog] = useState<string[]>([]);
  const [filesEncrypted, setFilesEncrypted] = useState(0);
  const [stageProgress, setStageProgress] = useState(0);
  const totalFiles = 1247;

  // Timing
  const simStartRef = useRef(0);
  const detectionTimeRef = useRef(0);
  const decisionStartRef = useRef(0);
  const decisionTimeRef = useRef(0);

  useEffect(() => {
    if (!loading && !user) navigate('/auth');
  }, [user, loading, navigate]);

  const resetSimulation = useCallback(() => {
    setPhase('idle');
    setCurrentStageIdx(-1);
    setExpandedStage(null);
    setBehaviorAnalysis(null);
    setDecision(null);
    setDecisionAdvice('');
    setScoreResult(null);
    setKillChainLog([]);
    setFilesEncrypted(0);
    setStageProgress(0);
    simStartRef.current = 0;
    detectionTimeRef.current = 0;
    decisionStartRef.current = 0;
    decisionTimeRef.current = 0;
  }, []);

  const runSimulation = useCallback(async () => {
    resetSimulation();
    setPhase('running');
    simStartRef.current = Date.now();

    for (let i = 0; i < killChainSteps.length; i++) {
      const step = killChainSteps[i];
      setCurrentStageIdx(i);
      setExpandedStage(i);
      setKillChainLog(prev => [...prev, `${step.label}: ${step.description}`]);

      // Update behavior analysis
      const metrics = generateMetricsForStage(i);
      const analysis = analyzeBehavior(metrics);
      setBehaviorAnalysis(analysis);

      // Simulate file encryption progress
      if (i >= 2 && i <= 4) {
        const encrypted = Math.round((i - 1) / 4 * totalFiles * (0.7 + Math.random() * 0.3));
        setFilesEncrypted(encrypted);
      }

      // Progress animation within each stage
      const steps_count = 10;
      for (let p = 0; p <= steps_count; p++) {
        setStageProgress((p / steps_count) * 100);
        await new Promise(r => setTimeout(r, step.duration / steps_count));
      }

      // At DEFENSE_TRIGGER, pause for user decision
      if (step.stage === 'DEFENSE_TRIGGER') {
        detectionTimeRef.current = Math.round((Date.now() - simStartRef.current) / 1000);
        decisionStartRef.current = Date.now();
        setPhase('decision');
        return; // Wait for user decision
      }
    }
  }, [resetSimulation]);

  const handleDecision = useCallback((chosen: string) => {
    decisionTimeRef.current = Math.round((Date.now() - decisionStartRef.current) / 1000);
    setDecision(chosen);
    setDecisionAdvice(getDecisionMentorAdvice(chosen, behaviorAnalysis?.threatScore || 0));
    setPhase('post-decision');

    // Continue simulation with containment + recovery
    const continueSimulation = async () => {
      // Containment phase
      setCurrentStageIdx(6);
      setExpandedStage(6);
      setKillChainLog(prev => [...prev, `Containment: Operator chose "${chosen}"`]);

      let finalEncrypted = filesEncrypted;
      if (chosen === 'ISOLATE') {
        finalEncrypted = Math.min(filesEncrypted + 20, totalFiles);
      } else if (chosen === 'KILL') {
        finalEncrypted = Math.min(filesEncrypted + 5, totalFiles);
      } else {
        finalEncrypted = Math.min(filesEncrypted + 400, totalFiles);
      }
      setFilesEncrypted(finalEncrypted);

      for (let p = 0; p <= 10; p++) {
        setStageProgress((p / 10) * 100);
        await new Promise(r => setTimeout(r, 200));
      }

      // Recovery phase
      setCurrentStageIdx(7);
      setExpandedStage(7);
      setKillChainLog(prev => [...prev, `Recovery: Restoring ${totalFiles - finalEncrypted} files from backup`]);

      for (let p = 0; p <= 10; p++) {
        setStageProgress((p / 10) * 100);
        await new Promise(r => setTimeout(r, 300));
      }

      const recoveryRate = chosen === 'MONITOR' ? 45 + Math.round(Math.random() * 20) : 85 + Math.round(Math.random() * 14);

      // Calculate final score
      const scoreMetrics: ScoreMetrics = {
        detectionTime: detectionTimeRef.current,
        decisionTime: decisionTimeRef.current,
        decision: chosen,
        threatScoreAtDecision: behaviorAnalysis?.threatScore || 0,
        filesEncryptedBeforeAction: finalEncrypted,
        totalFiles,
        correctDecisionMade: chosen === 'ISOLATE',
        recoverySuccess: recoveryRate,
      };

      const result = calculateScore(scoreMetrics);
      setScoreResult(result);
      setPhase('complete');
      toast.success('Simulation complete! Review your score below.');
    };

    setTimeout(continueSimulation, 1500);
  }, [behaviorAnalysis, filesEncrypted]);

  const exportReport = useCallback(() => {
    if (!scoreResult || !decision) return;
    const metrics: ScoreMetrics = {
      detectionTime: detectionTimeRef.current,
      decisionTime: decisionTimeRef.current,
      decision,
      threatScoreAtDecision: behaviorAnalysis?.threatScore || 0,
      filesEncryptedBeforeAction: filesEncrypted,
      totalFiles,
      correctDecisionMade: decision === 'ISOLATE',
      recoverySuccess: scoreResult.breakdown.find(b => b.metric === 'Recovery Success')?.score ? 
        Math.round((scoreResult.breakdown.find(b => b.metric === 'Recovery Success')!.score / 10) * 100) : 90,
    };
    const report = generateForensicsReport(metrics, scoreResult, killChainLog, [decision]);
    const blob = new Blob([report], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cyber_range_report_${new Date().toISOString().split('T')[0]}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success('Forensics report exported!');
  }, [scoreResult, decision, behaviorAnalysis, filesEncrypted, killChainLog]);

  const currentStage = currentStageIdx >= 0 ? killChainSteps[currentStageIdx] : null;
  const mentorInsight = currentStage ? getMentorInsight(currentStage.stage, mentorMode) : null;

  if (loading || !user) return null;

  return (
    <DashboardLayout>
      {/* Header */}
      <div className="mb-6 flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="font-display text-3xl font-bold text-destructive text-glow-red tracking-wider flex items-center gap-3">
            <Crosshair className="w-8 h-8" />
            CYBER RANGE
          </h1>
          <p className="text-muted-foreground font-mono mt-1 text-sm">
            Interactive ransomware decision-response training simulator
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-muted-foreground">Mode:</span>
          <Button
            size="sm"
            variant={mentorMode === 'student' ? 'cyber' : 'outline'}
            onClick={() => setMentorMode('student')}
          >
            <GraduationCap className="w-4 h-4 mr-1" /> Student
          </Button>
          <Button
            size="sm"
            variant={mentorMode === 'soc' ? 'cyber' : 'outline'}
            onClick={() => setMentorMode('soc')}
          >
            <Siren className="w-4 h-4 mr-1" /> SOC
          </Button>
        </div>
      </div>

      {/* Controls */}
      <div className="flex flex-wrap gap-3 mb-6">
        {phase === 'idle' && (
          <Button variant="danger" size="lg" onClick={runSimulation}>
            <Play className="w-5 h-5 mr-2" /> LAUNCH SIMULATION
          </Button>
        )}
        {(phase === 'running' || phase === 'decision') && (
          <Button variant="outline" onClick={resetSimulation}>
            <Square className="w-4 h-4 mr-2" /> ABORT
          </Button>
        )}
        {phase === 'complete' && (
          <>
            <Button variant="cyber" onClick={resetSimulation}>
              <RotateCcw className="w-4 h-4 mr-2" /> NEW SIMULATION
            </Button>
            <Button variant="outline" onClick={exportReport}>
              <Download className="w-4 h-4 mr-2" /> EXPORT REPORT
            </Button>
          </>
        )}
        <div className="flex items-center gap-2 ml-auto">
          <div className={cn(
            "w-3 h-3 rounded-full",
            phase === 'idle' ? "bg-muted" :
            phase === 'complete' ? "bg-success" :
            phase === 'decision' ? "bg-warning animate-pulse" :
            "bg-destructive animate-pulse"
          )} />
          <span className="font-mono text-sm text-muted-foreground uppercase">{phase}</span>
        </div>
      </div>

      {/* ─── PILLAR 1: Kill-Chain Timeline ─── */}
      <div className="cyber-card p-5 border border-border mb-6">
        <div className="relative z-10">
          <h3 className="font-display text-lg font-bold text-foreground tracking-wider mb-4 flex items-center gap-2">
            <Target className="w-5 h-5 text-destructive" />
            RANSOMWARE KILL-CHAIN
          </h3>
          {/* Timeline bar */}
          <div className="flex gap-1 mb-4 overflow-x-auto pb-2">
            {killChainSteps.map((step, idx) => {
              const isActive = idx === currentStageIdx;
              const isDone = idx < currentStageIdx;
              const isFuture = idx > currentStageIdx;
              return (
                <button
                  key={step.stage}
                  onClick={() => isDone || isActive ? setExpandedStage(expandedStage === idx ? null : idx) : null}
                  className={cn(
                    "flex-1 min-w-[100px] px-3 py-2 rounded-lg border text-xs font-mono transition-all cursor-pointer",
                    isActive && "bg-destructive/20 border-destructive text-destructive animate-pulse",
                    isDone && "bg-success/15 border-success/40 text-success",
                    isFuture && "bg-secondary/30 border-border/50 text-muted-foreground opacity-50",
                    !isActive && !isDone && !isFuture && "bg-secondary/30 border-border/50"
                  )}
                >
                  <div className="flex items-center gap-1">
                    {isDone && <Shield className="w-3 h-3" />}
                    {isActive && <Zap className="w-3 h-3" />}
                    <span className="truncate">{step.label}</span>
                  </div>
                </button>
              );
            })}
          </div>

          {/* Stage progress */}
          {currentStage && phase !== 'idle' && phase !== 'complete' && (
            <Progress value={stageProgress} className="h-2 mb-4" />
          )}

          {/* Expanded stage detail */}
          {expandedStage !== null && expandedStage <= currentStageIdx && (
            <div className="p-4 rounded-lg bg-secondary/20 border border-border/50 space-y-3 animate-fade-in">
              <h4 className="font-display text-sm font-bold text-foreground">
                {killChainSteps[expandedStage].label}
              </h4>
              <p className="font-mono text-xs text-muted-foreground">
                {killChainSteps[expandedStage].description}
              </p>
              <div className="space-y-1">
                <p className="text-xs font-mono text-primary">Evidence:</p>
                {killChainSteps[expandedStage].evidence.map((ev, i) => (
                  <p key={i} className="font-mono text-xs text-foreground/70 pl-3 border-l-2 border-primary/30">
                    {ev}
                  </p>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        {/* ─── PILLAR 2: Behavior-Based AI Detection ─── */}
        <div className="cyber-card p-5 border border-border">
          <div className="relative z-10">
            <h3 className="font-display text-lg font-bold text-foreground tracking-wider mb-4 flex items-center gap-2">
              <Brain className="w-5 h-5 text-primary" />
              AI BEHAVIORAL ANALYSIS
            </h3>
            {behaviorAnalysis ? (
              <div className="space-y-4">
                {/* Threat Gauge */}
                <div className="text-center">
                  <div className={cn(
                    "text-5xl font-display font-black",
                    behaviorAnalysis.threatScore >= 80 && "text-destructive text-glow-red",
                    behaviorAnalysis.threatScore >= 55 && behaviorAnalysis.threatScore < 80 && "text-warning",
                    behaviorAnalysis.threatScore < 55 && "text-success"
                  )}>
                    {behaviorAnalysis.threatScore}%
                  </div>
                  <div className={cn(
                    "text-sm font-mono font-bold mt-1",
                    behaviorAnalysis.verdict === 'RANSOMWARE_CONFIRMED' && "text-destructive",
                    behaviorAnalysis.verdict === 'HIGH_RISK' && "text-warning",
                    behaviorAnalysis.verdict === 'SUSPICIOUS' && "text-warning",
                    behaviorAnalysis.verdict === 'NORMAL' && "text-success"
                  )}>
                    {behaviorAnalysis.verdict.replace(/_/g, ' ')}
                  </div>
                  <Progress
                    value={behaviorAnalysis.threatScore}
                    className={cn("h-3 mt-3", behaviorAnalysis.threatScore >= 80 && "[&>div]:bg-destructive")}
                  />
                  <p className="text-xs font-mono text-muted-foreground mt-1">
                    Confidence: {behaviorAnalysis.confidence}%
                  </p>
                </div>
                {/* Reasons */}
                <div className="space-y-1 max-h-40 overflow-y-auto">
                  {behaviorAnalysis.reasons.map((r, i) => (
                    <p key={i} className="font-mono text-xs text-foreground/80 flex items-start gap-2">
                      <AlertTriangle className="w-3 h-3 text-warning flex-shrink-0 mt-0.5" />
                      {r}
                    </p>
                  ))}
                </div>
              </div>
            ) : (
              <p className="text-muted-foreground font-mono text-sm text-center py-8">
                Launch simulation to see behavioral analysis
              </p>
            )}
          </div>
        </div>

        {/* ─── PILLAR 4: AI Mentor ─── */}
        <div className="cyber-card p-5 border border-border">
          <div className="relative z-10">
            <h3 className="font-display text-lg font-bold text-foreground tracking-wider mb-4 flex items-center gap-2">
              <Eye className="w-5 h-5 text-accent" />
              AI SOC MENTOR
              <span className={cn(
                "text-xs px-2 py-0.5 rounded-full font-mono",
                mentorMode === 'student' ? "bg-primary/20 text-primary" : "bg-muted text-muted-foreground"
              )}>
                {mentorMode === 'student' ? 'GUIDED' : 'SILENT'}
              </span>
            </h3>
            {mentorMode === 'soc' ? (
              <div className="text-center py-8">
                <Siren className="w-10 h-10 text-muted-foreground/30 mx-auto mb-2" />
                <p className="text-muted-foreground font-mono text-sm">
                  SOC Mode: No guidance. You're on your own, analyst.
                </p>
              </div>
            ) : mentorInsight ? (
              <div className="space-y-3 animate-fade-in">
                <p className="font-mono text-sm text-foreground leading-relaxed">
                  {mentorInsight.message}
                </p>
                {mentorInsight.tip && (
                  <div className="p-3 rounded-lg bg-primary/10 border border-primary/20">
                    <p className="text-xs font-mono text-primary">💡 {mentorInsight.tip}</p>
                  </div>
                )}
                {mentorInsight.realWorldNote && (
                  <div className="p-3 rounded-lg bg-warning/10 border border-warning/20">
                    <p className="text-xs font-mono text-warning">🌍 {mentorInsight.realWorldNote}</p>
                  </div>
                )}
              </div>
            ) : (
              <p className="text-muted-foreground font-mono text-sm text-center py-8">
                Mentor insights will appear during simulation
              </p>
            )}
            {decisionAdvice && (
              <div className="mt-4 p-3 rounded-lg bg-accent/10 border border-accent/20 animate-fade-in">
                <p className="text-xs font-mono text-accent">{decisionAdvice}</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ─── PILLAR 3: Decision Panel ─── */}
      {phase === 'decision' && (
        <div className="cyber-card p-6 border-2 border-warning mb-6 animate-pulse">
          <div className="relative z-10 text-center space-y-4">
            <div className="flex items-center justify-center gap-2">
              <Siren className="w-6 h-6 text-warning" />
              <h3 className="font-display text-xl font-bold text-warning tracking-wider">
                RANSOMWARE ACTIVITY DETECTED
              </h3>
              <Siren className="w-6 h-6 text-warning" />
            </div>
            <p className="font-mono text-sm text-foreground">
              Threat Score: <span className="text-destructive font-bold">{behaviorAnalysis?.threatScore}%</span>
              {' '} | Files at risk: <span className="text-warning font-bold">{totalFiles}</span>
              {' '} | Already encrypted: <span className="text-destructive font-bold">{filesEncrypted}</span>
            </p>
            <p className="font-mono text-lg text-warning font-bold">
              Choose your response strategy:
            </p>
            <div className="flex flex-wrap justify-center gap-4">
              <Button
                variant="cyber"
                size="lg"
                className="min-w-[200px]"
                onClick={() => handleDecision('ISOLATE')}
              >
                <Shield className="w-5 h-5 mr-2" />
                ISOLATE FILESYSTEM
              </Button>
              <Button
                variant="danger"
                size="lg"
                className="min-w-[200px]"
                onClick={() => handleDecision('KILL')}
              >
                <Zap className="w-5 h-5 mr-2" />
                KILL PROCESS
              </Button>
              <Button
                variant="outline"
                size="lg"
                className="min-w-[200px]"
                onClick={() => handleDecision('MONITOR')}
              >
                <Activity className="w-5 h-5 mr-2" />
                CONTINUE MONITORING
              </Button>
            </div>
            <div className="flex items-center justify-center gap-2 text-xs font-mono text-muted-foreground">
              <Clock className="w-3 h-3" />
              Decision timer active — faster response = higher score
            </div>
          </div>
        </div>
      )}

      {/* ─── Live Stats Bar ─── */}
      {phase !== 'idle' && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <div className="cyber-card p-4 border border-border">
            <div className="relative z-10 flex items-center gap-3">
              <Clock className="w-5 h-5 text-primary" />
              <div>
                <p className="text-lg font-display font-bold text-foreground">
                  {detectionTimeRef.current || Math.round((Date.now() - simStartRef.current) / 1000)}s
                </p>
                <p className="text-xs font-mono text-muted-foreground">Detection Time</p>
              </div>
            </div>
          </div>
          <div className="cyber-card p-4 border border-border">
            <div className="relative z-10 flex items-center gap-3">
              <FileWarning className="w-5 h-5 text-destructive" />
              <div>
                <p className="text-lg font-display font-bold text-destructive">{filesEncrypted}</p>
                <p className="text-xs font-mono text-muted-foreground">Files Encrypted</p>
              </div>
            </div>
          </div>
          <div className="cyber-card p-4 border border-border">
            <div className="relative z-10 flex items-center gap-3">
              <BarChart3 className="w-5 h-5 text-warning" />
              <div>
                <p className="text-lg font-display font-bold text-foreground">
                  {behaviorAnalysis?.threatScore || 0}%
                </p>
                <p className="text-xs font-mono text-muted-foreground">Threat Score</p>
              </div>
            </div>
          </div>
          <div className="cyber-card p-4 border border-border">
            <div className="relative z-10 flex items-center gap-3">
              <Lock className="w-5 h-5 text-accent" />
              <div>
                <p className="text-lg font-display font-bold text-foreground">
                  {decision || '—'}
                </p>
                <p className="text-xs font-mono text-muted-foreground">Decision</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ─── PILLAR 5 & 6: Score + Forensics Report ─── */}
      {phase === 'complete' && scoreResult && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Scoring */}
          <div className="cyber-card p-6 border border-border">
            <div className="relative z-10">
              <h3 className="font-display text-lg font-bold text-foreground tracking-wider mb-4 flex items-center gap-2">
                <Trophy className="w-5 h-5 text-warning" />
                SOC READINESS SCORE
              </h3>
              <div className="text-center mb-6">
                <div className={cn(
                  "text-7xl font-display font-black",
                  scoreResult.totalScore >= 80 && "text-success text-glow-green",
                  scoreResult.totalScore >= 55 && scoreResult.totalScore < 80 && "text-warning",
                  scoreResult.totalScore < 55 && "text-destructive text-glow-red"
                )}>
                  {scoreResult.totalScore}
                </div>
                <p className="font-mono text-sm text-muted-foreground">/ {scoreResult.maxScore}</p>
                <div className="mt-2">
                  <span className="px-4 py-1 rounded-full bg-primary/20 text-primary font-display font-bold text-lg">
                    {scoreResult.grade}
                  </span>
                </div>
                <p className="font-mono text-sm text-foreground mt-3">{scoreResult.analystLevel}</p>
              </div>
              {/* Breakdown */}
              <div className="space-y-3">
                {scoreResult.breakdown.map((item, i) => (
                  <div key={i} className="space-y-1">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-muted-foreground">{item.metric}</span>
                      <span className={item.impact === 'positive' ? 'text-success' : 'text-destructive'}>
                        {item.score}/{item.maxScore}
                      </span>
                    </div>
                    <Progress value={(item.score / item.maxScore) * 100} className="h-2" />
                    <p className="text-xs font-mono text-foreground/60">{item.detail}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Feedback & Forensics */}
          <div className="cyber-card p-6 border border-border">
            <div className="relative z-10">
              <h3 className="font-display text-lg font-bold text-foreground tracking-wider mb-4 flex items-center gap-2">
                <FileWarning className="w-5 h-5 text-accent" />
                INCIDENT FORENSICS
              </h3>
              <div className="space-y-3 mb-6">
                <h4 className="font-mono text-xs text-primary font-bold">FEEDBACK</h4>
                {scoreResult.feedback.map((f, i) => (
                  <p key={i} className="font-mono text-sm text-foreground/80 flex items-start gap-2">
                    <ChevronRight className="w-3 h-3 text-primary flex-shrink-0 mt-1" />
                    {f}
                  </p>
                ))}
              </div>
              <div className="space-y-2">
                <h4 className="font-mono text-xs text-primary font-bold">ATTACK TIMELINE</h4>
                {killChainLog.map((log, i) => (
                  <p key={i} className="font-mono text-xs text-foreground/60 pl-3 border-l-2 border-primary/20">
                    <span className="text-muted-foreground">[{i + 1}]</span> {log}
                  </p>
                ))}
              </div>
              <Button variant="outline" className="w-full mt-4" onClick={exportReport}>
                <Download className="w-4 h-4 mr-2" /> Export Full Forensics Report
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Educational footer */}
      <div className="mt-6 p-4 rounded-lg bg-warning/10 border border-warning/30">
        <div className="flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-warning flex-shrink-0" />
          <p className="text-xs font-mono text-warning">
            <strong>EDUCATIONAL CYBER RANGE:</strong> This is an interactive decision-response simulator for cybersecurity training. No real malware is used. All simulations run safely in-browser.
          </p>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default CyberRangePage;
