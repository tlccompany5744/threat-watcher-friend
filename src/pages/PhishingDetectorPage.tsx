import { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/hooks/useAuth";
import DashboardLayout from "@/components/dashboard/DashboardLayout";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import { motion, AnimatePresence } from "framer-motion";
import {
  Shield,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Search,
  Link2,
  FileWarning,
  Mail,
  Globe,
  Lock,
  Zap,
  Activity,
  Eye,
  ShieldAlert,
  ShieldCheck,
  Loader2,
  Brain,
  Sparkles,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { supabase } from "@/integrations/supabase/client";

// ─── Detection Engine ────────────────────────────────────────────────
interface Indicator {
  type: "critical" | "warning" | "info" | "safe";
  category: string;
  detail: string;
  score: number;
}

const PHISHING_KEYWORDS = [
  { word: "urgent", weight: 15 },
  { word: "verify your account", weight: 20 },
  { word: "login immediately", weight: 20 },
  { word: "bank alert", weight: 20 },
  { word: "password reset", weight: 15 },
  { word: "click here", weight: 15 },
  { word: "suspended", weight: 15 },
  { word: "confirm your identity", weight: 20 },
  { word: "unusual activity", weight: 15 },
  { word: "act now", weight: 10 },
  { word: "limited time", weight: 10 },
  { word: "won a prize", weight: 25 },
  { word: "congratulations", weight: 10 },
  { word: "wire transfer", weight: 25 },
  { word: "social security", weight: 25 },
  { word: "update your payment", weight: 20 },
  { word: "dear customer", weight: 10 },
  { word: "dear user", weight: 10 },
];

const SUSPICIOUS_TLDS = [".ru", ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".buzz", ".club", ".icu", ".cam"];

const DANGEROUS_EXTENSIONS = [".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".wsf", ".msi", ".pif", ".com", ".hta"];

function analyzeEmail(raw: string): { score: number; indicators: Indicator[] } {
  const email = raw.toLowerCase();
  const indicators: Indicator[] = [];
  let score = 0;

  // 1. Keyword detection
  PHISHING_KEYWORDS.forEach(({ word, weight }) => {
    if (email.includes(word)) {
      score += weight;
      indicators.push({
        type: weight >= 20 ? "critical" : "warning",
        category: "Keyword Detection",
        detail: `Phishing keyword detected: "${word}"`,
        score: weight,
      });
    }
  });

  // 2. URL / link analysis
  const linkPattern = /https?:\/\/[^\s"'<>]+/gi;
  const links = raw.match(linkPattern) || [];
  if (links.length > 0) {
    indicators.push({
      type: "warning",
      category: "URL Analysis",
      detail: `${links.length} external link(s) found`,
      score: 10,
    });
    score += 10;

    // Check for URL shorteners
    const shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly"];
    links.forEach((link) => {
      if (shorteners.some((s) => link.includes(s))) {
        score += 20;
        indicators.push({
          type: "critical",
          category: "URL Analysis",
          detail: `Shortened/obfuscated URL: ${link.slice(0, 60)}`,
          score: 20,
        });
      }
    });

    // Check for IP-based URLs
    const ipUrl = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
    links.forEach((link) => {
      if (ipUrl.test(link)) {
        score += 25;
        indicators.push({
          type: "critical",
          category: "URL Analysis",
          detail: `IP-based URL detected (potential phishing): ${link.slice(0, 60)}`,
          score: 25,
        });
      }
    });
  }

  // 3. Suspicious TLDs
  SUSPICIOUS_TLDS.forEach((tld) => {
    if (email.includes(tld)) {
      score += 30;
      indicators.push({
        type: "critical",
        category: "Domain Analysis",
        detail: `Suspicious top-level domain detected: ${tld}`,
        score: 30,
      });
    }
  });

  // 4. Attachment threats
  DANGEROUS_EXTENSIONS.forEach((ext) => {
    if (email.includes(ext)) {
      score += 25;
      indicators.push({
        type: "critical",
        category: "Attachment Threat",
        detail: `Dangerous file extension referenced: ${ext}`,
        score: 25,
      });
    }
  });

  // 5. SPF / DKIM header analysis
  if (email.includes("spf=fail") || email.includes("spf=softfail")) {
    score += 25;
    indicators.push({
      type: "critical",
      category: "Header Analysis",
      detail: "SPF authentication failed — sender domain not verified",
      score: 25,
    });
  }
  if (email.includes("dkim=fail")) {
    score += 25;
    indicators.push({
      type: "critical",
      category: "Header Analysis",
      detail: "DKIM signature verification failed",
      score: 25,
    });
  }
  if (email.includes("spf=pass")) {
    indicators.push({ type: "safe", category: "Header Analysis", detail: "SPF authentication passed", score: 0 });
  }
  if (email.includes("dkim=pass")) {
    indicators.push({ type: "safe", category: "Header Analysis", detail: "DKIM signature verified", score: 0 });
  }

  // 6. Reply-to / From mismatch
  const fromMatch = email.match(/from:\s*[^<]*<([^>]+)>/i);
  const replyMatch = email.match(/reply-to:\s*[^<]*<([^>]+)>/i);
  if (fromMatch && replyMatch) {
    const fromDomain = fromMatch[1].split("@")[1];
    const replyDomain = replyMatch[1].split("@")[1];
    if (fromDomain !== replyDomain) {
      score += 20;
      indicators.push({
        type: "critical",
        category: "Sender Spoofing",
        detail: `Reply-To domain (${replyDomain}) doesn't match From domain (${fromDomain})`,
        score: 20,
      });
    }
  }

  // 7. Urgency language patterns
  const urgencyPatterns = ["immediately", "within 24 hours", "expire", "action required", "final warning", "last chance"];
  urgencyPatterns.forEach((p) => {
    if (email.includes(p)) {
      score += 10;
      indicators.push({
        type: "warning",
        category: "Urgency Detection",
        detail: `Urgency pressure phrase: "${p}"`,
        score: 10,
      });
    }
  });

  // Cap score at 100
  score = Math.min(score, 100);

  // Add safe indicators if score is low
  if (score === 0) {
    indicators.push({ type: "safe", category: "Overall", detail: "No suspicious indicators detected", score: 0 });
  }

  return { score, indicators };
}

function getThreatLevel(score: number) {
  if (score >= 60) return { label: "HIGH PHISHING", color: "text-destructive", bg: "bg-destructive/20", border: "border-destructive" };
  if (score >= 30) return { label: "MEDIUM RISK", color: "text-warning", bg: "bg-warning/20", border: "border-warning" };
  return { label: "SAFE", color: "text-success", bg: "bg-success/20", border: "border-success" };
}

// ─── Scan Steps ──────────────────────────────────────────────────────
const SCAN_STEPS = [
  { label: "Header Analysis", icon: Mail },
  { label: "Link Inspection", icon: Link2 },
  { label: "Content Detection", icon: Search },
  { label: "Domain Verification", icon: Globe },
  { label: "Attachment Scan", icon: FileWarning },
  { label: "AI Threat Assessment", icon: Brain },
];

// ─── Component ───────────────────────────────────────────────────────
const PhishingDetectorPage = () => {
  const { user, loading } = useAuth();
  const navigate = useNavigate();
  const { toast } = useToast();

  const [emailContent, setEmailContent] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanStep, setScanStep] = useState(-1);
  const [result, setResult] = useState<{ score: number; indicators: Indicator[] } | null>(null);
  const [aiReport, setAiReport] = useState<string | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const gaugeRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!loading && !user) navigate("/auth");
  }, [user, loading, navigate]);

  const runScan = async () => {
    if (!emailContent.trim()) {
      toast({ title: "Empty input", description: "Paste an email header or body to analyze.", variant: "destructive" });
      return;
    }
    setResult(null);
    setAiReport(null);
    setIsScanning(true);
    setScanStep(0);

    // Animated scan steps
    for (let i = 0; i < SCAN_STEPS.length; i++) {
      setScanStep(i);
      await new Promise((r) => setTimeout(r, 600));
    }

    const analysis = analyzeEmail(emailContent);
    setResult(analysis);
    setIsScanning(false);
    setScanStep(-1);

    toast({
      title: `Scan Complete — ${getThreatLevel(analysis.score).label}`,
      description: `Threat score: ${analysis.score}/100 with ${analysis.indicators.length} indicator(s)`,
    });

    // Auto-trigger AI analysis for medium/high threats
    if (analysis.score >= 30) {
      generateAiReport(analysis);
    }
  };

  const generateAiReport = async (analysis: { score: number; indicators: Indicator[] }) => {
    setAiLoading(true);
    try {
      const prompt = `You are a cybersecurity SOC analyst. Analyze this phishing email scan result and provide a professional security assessment report.

Threat Score: ${analysis.score}/100
Threat Level: ${getThreatLevel(analysis.score).label}

Detected Indicators:
${analysis.indicators.map((i) => `- [${i.type.toUpperCase()}] ${i.category}: ${i.detail} (+${i.score})`).join("\n")}

Email Content (first 500 chars):
${emailContent.slice(0, 500)}

Provide:
1. Executive summary (2-3 sentences)
2. Key findings (bullet points)
3. Risk assessment
4. Recommended actions for the SOC team
Keep it concise and professional.`;

      const { data, error } = await supabase.functions.invoke("ai-assistant", {
        body: { message: prompt },
      });

      if (error) throw error;
      setAiReport(data?.response || data?.message || "AI analysis unavailable.");
    } catch {
      setAiReport("AI analysis could not be generated. The detection engine results above are still valid.");
    } finally {
      setAiLoading(false);
    }
  };

  if (loading) return null;

  const threat = result ? getThreatLevel(result.score) : null;

  return (
    <DashboardLayout>
      <div className="space-y-6 max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-lg bg-primary/10 border border-primary/30">
            <ShieldAlert className="w-7 h-7 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-display font-bold text-foreground tracking-wide">
              Phishing Mail Detector
            </h1>
            <p className="text-sm font-mono text-muted-foreground">Real-Time Email Threat Analyzer</p>
          </div>
        </div>

        {/* ── Email Input Panel ─────────────────────────────────── */}
        <Card className="cyber-card border-border">
          <CardHeader className="pb-3">
            <CardTitle className="text-base font-mono flex items-center gap-2">
              <Mail className="w-4 h-4 text-primary" />
              Email Input
            </CardTitle>
            <CardDescription className="font-mono text-xs">
              Paste the full email content including headers for the most accurate analysis
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Textarea
              value={emailContent}
              onChange={(e) => setEmailContent(e.target.value)}
              placeholder={`Paste email headers + body here...\n\nExample:\nFrom: security@bank-al3rt.xyz\nReply-To: hacker@evil.ru\nSubject: Urgent: Verify Your Account Immediately\n\nDear Customer,\nYour account has been suspended. Click here to verify: http://192.168.1.1/login\nAct now or your account will be deleted within 24 hours.`}
              className="min-h-[200px] font-mono text-sm bg-secondary/30 border-border focus:border-primary resize-y"
            />
            <div className="flex items-center gap-3">
              <Button
                onClick={runScan}
                disabled={isScanning || !emailContent.trim()}
                variant="cyber"
                size="lg"
                className="gap-2"
              >
                {isScanning ? (
                  <>
                    <Loader2 className="w-5 h-5 animate-spin" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <Zap className="w-5 h-5" />
                    Analyze Email
                  </>
                )}
              </Button>
              <span className="text-xs font-mono text-muted-foreground">
                {emailContent.length} characters
              </span>
            </div>
          </CardContent>
        </Card>

        {/* ── Animated Scan Progress ────────────────────────────── */}
        <AnimatePresence>
          {isScanning && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
            >
              <Card className="cyber-card border-primary/30 glow-border">
                <CardContent className="p-6">
                  <div className="flex items-center gap-2 mb-4">
                    <Activity className="w-5 h-5 text-primary animate-pulse" />
                    <span className="font-mono text-sm text-primary">Scanning email...</span>
                  </div>
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                    {SCAN_STEPS.map((step, i) => {
                      const StepIcon = step.icon;
                      const done = i < scanStep;
                      const active = i === scanStep;
                      return (
                        <motion.div
                          key={step.label}
                          initial={{ opacity: 0.3 }}
                          animate={{ opacity: done || active ? 1 : 0.3 }}
                          className={cn(
                            "flex items-center gap-2 p-3 rounded-lg border font-mono text-xs transition-all",
                            done && "border-success/50 bg-success/10 text-success",
                            active && "border-primary/50 bg-primary/10 text-primary animate-pulse",
                            !done && !active && "border-border bg-secondary/20 text-muted-foreground"
                          )}
                        >
                          {done ? (
                            <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
                          ) : active ? (
                            <Loader2 className="w-4 h-4 animate-spin flex-shrink-0" />
                          ) : (
                            <StepIcon className="w-4 h-4 flex-shrink-0" />
                          )}
                          {step.label}
                        </motion.div>
                      );
                    })}
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          )}
        </AnimatePresence>

        {/* ── Results ───────────────────────────────────────────── */}
        <AnimatePresence>
          {result && threat && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="space-y-6"
            >
              {/* Score + Level Row */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Threat Score Gauge */}
                <Card className={cn("cyber-card border", threat.border)}>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base font-mono flex items-center gap-2">
                      <Activity className="w-4 h-4 text-primary" />
                      Threat Score
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="flex flex-col items-center py-4">
                      {/* Circular gauge */}
                      <div className="relative w-44 h-44" ref={gaugeRef}>
                        <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
                          <circle
                            cx="60" cy="60" r="52"
                            fill="none"
                            stroke="hsl(var(--muted))"
                            strokeWidth="10"
                          />
                          <motion.circle
                            cx="60" cy="60" r="52"
                            fill="none"
                            stroke={
                              result.score >= 60
                                ? "hsl(var(--destructive))"
                                : result.score >= 30
                                ? "hsl(var(--warning))"
                                : "hsl(var(--success))"
                            }
                            strokeWidth="10"
                            strokeLinecap="round"
                            strokeDasharray={`${2 * Math.PI * 52}`}
                            initial={{ strokeDashoffset: 2 * Math.PI * 52 }}
                            animate={{
                              strokeDashoffset: 2 * Math.PI * 52 * (1 - result.score / 100),
                            }}
                            transition={{ duration: 1.2, ease: "easeOut" }}
                            style={{
                              filter:
                                result.score >= 60
                                  ? "drop-shadow(0 0 8px hsl(var(--destructive)/0.6))"
                                  : result.score >= 30
                                  ? "drop-shadow(0 0 8px hsl(var(--warning)/0.6))"
                                  : "drop-shadow(0 0 8px hsl(var(--success)/0.6))",
                            }}
                          />
                        </svg>
                        <div className="absolute inset-0 flex flex-col items-center justify-center">
                          <motion.span
                            className={cn("text-4xl font-display font-bold", threat.color)}
                            initial={{ scale: 0 }}
                            animate={{ scale: 1 }}
                            transition={{ delay: 0.5, type: "spring" }}
                          >
                            {result.score}
                          </motion.span>
                          <span className="text-xs font-mono text-muted-foreground">/100</span>
                        </div>
                      </div>
                      <Badge
                        className={cn(
                          "mt-4 font-mono text-sm px-4 py-1",
                          threat.bg, threat.color, threat.border, "border"
                        )}
                      >
                        {threat.label}
                      </Badge>
                    </div>
                  </CardContent>
                </Card>

                {/* Detection Summary */}
                <Card className="cyber-card border-border">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base font-mono flex items-center gap-2">
                      <Eye className="w-4 h-4 text-primary" />
                      Detection Results
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      {/* Category breakdown */}
                      {(() => {
                        const categories = new Map<string, { count: number; maxType: string; totalScore: number }>();
                        result.indicators.forEach((ind) => {
                          const existing = categories.get(ind.category);
                          if (existing) {
                            existing.count++;
                            existing.totalScore += ind.score;
                            if (ind.type === "critical") existing.maxType = "critical";
                          } else {
                            categories.set(ind.category, { count: 1, maxType: ind.type, totalScore: ind.score });
                          }
                        });
                        return Array.from(categories.entries()).map(([cat, data]) => (
                          <div
                            key={cat}
                            className={cn(
                              "flex items-center justify-between p-3 rounded-lg border font-mono text-sm",
                              data.maxType === "critical" && "border-destructive/30 bg-destructive/5",
                              data.maxType === "warning" && "border-warning/30 bg-warning/5",
                              data.maxType === "safe" && "border-success/30 bg-success/5",
                              data.maxType === "info" && "border-border bg-secondary/20"
                            )}
                          >
                            <div className="flex items-center gap-2">
                              {data.maxType === "critical" && <XCircle className="w-4 h-4 text-destructive" />}
                              {data.maxType === "warning" && <AlertTriangle className="w-4 h-4 text-warning" />}
                              {data.maxType === "safe" && <ShieldCheck className="w-4 h-4 text-success" />}
                              {data.maxType === "info" && <Shield className="w-4 h-4 text-muted-foreground" />}
                              <span>{cat}</span>
                            </div>
                            <div className="flex items-center gap-2">
                              <span className="text-xs text-muted-foreground">{data.count} finding(s)</span>
                              {data.totalScore > 0 && (
                                <Badge variant="outline" className="text-xs">
                                  +{data.totalScore}
                                </Badge>
                              )}
                            </div>
                          </div>
                        ));
                      })()}
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* ── Suspicious Indicators Detail ──────────────────── */}
              <Card className="cyber-card border-border">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base font-mono flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-warning" />
                    Suspicious Indicators
                  </CardTitle>
                  <CardDescription className="font-mono text-xs">
                    {result.indicators.length} indicator(s) detected during analysis
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 max-h-[400px] overflow-y-auto pr-2">
                    {result.indicators.map((ind, i) => (
                      <motion.div
                        key={i}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: i * 0.05 }}
                        className={cn(
                          "flex items-start gap-3 p-3 rounded-lg border font-mono text-sm",
                          ind.type === "critical" && "border-destructive/30 bg-destructive/5",
                          ind.type === "warning" && "border-warning/30 bg-warning/5",
                          ind.type === "safe" && "border-success/30 bg-success/5",
                          ind.type === "info" && "border-border bg-secondary/20"
                        )}
                      >
                        <div className="flex-shrink-0 mt-0.5">
                          {ind.type === "critical" && <XCircle className="w-4 h-4 text-destructive" />}
                          {ind.type === "warning" && <AlertTriangle className="w-4 h-4 text-warning" />}
                          {ind.type === "safe" && <CheckCircle2 className="w-4 h-4 text-success" />}
                          {ind.type === "info" && <Shield className="w-4 h-4 text-muted-foreground" />}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-0.5">
                            <Badge
                              variant="outline"
                              className={cn(
                                "text-[10px] uppercase",
                                ind.type === "critical" && "border-destructive/50 text-destructive",
                                ind.type === "warning" && "border-warning/50 text-warning",
                                ind.type === "safe" && "border-success/50 text-success"
                              )}
                            >
                              {ind.category}
                            </Badge>
                            {ind.score > 0 && (
                              <span className="text-[10px] text-destructive font-bold">+{ind.score}</span>
                            )}
                          </div>
                          <p className="text-foreground/80">{ind.detail}</p>
                        </div>
                      </motion.div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* ── AI Analysis Report ────────────────────────────── */}
              <Card className="cyber-card border-border">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base font-mono flex items-center gap-2">
                    <Sparkles className="w-4 h-4 text-primary" />
                    AI Security Analysis Report
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {aiLoading ? (
                    <div className="flex items-center gap-3 p-6 justify-center">
                      <Loader2 className="w-5 h-5 animate-spin text-primary" />
                      <span className="font-mono text-sm text-muted-foreground">
                        Generating AI threat assessment...
                      </span>
                    </div>
                  ) : aiReport ? (
                    <div className="bg-secondary/30 rounded-lg p-4 border border-border font-mono text-sm whitespace-pre-wrap text-foreground/80 leading-relaxed">
                      {aiReport}
                    </div>
                  ) : (
                    <div className="flex flex-col items-center gap-3 py-6">
                      <Brain className="w-8 h-8 text-muted-foreground" />
                      <p className="font-mono text-sm text-muted-foreground">
                        AI report auto-generates for medium/high threats, or click below
                      </p>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => result && generateAiReport(result)}
                        disabled={!result}
                        className="gap-2"
                      >
                        <Sparkles className="w-4 h-4" />
                        Generate AI Report
                      </Button>
                    </div>
                  )}
                </CardContent>
              </Card>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </DashboardLayout>
  );
};

export default PhishingDetectorPage;
