import { useState, useEffect, useRef, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/hooks/useAuth";
import * as pdfjsLib from "pdfjs-dist";

// Configure PDF.js worker
pdfjsLib.GlobalWorkerOptions.workerSrc = `https://cdnjs.cloudflare.com/ajax/libs/pdf.js/4.4.168/pdf.worker.min.mjs`;
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
  Upload,
  FileText,
  Radio,
  Trash2,
} from "lucide-react";
import { cn } from "@/lib/utils";

// ─── Detection Engine ────────────────────────────────────────────────
interface Indicator {
  type: "critical" | "warning" | "info" | "safe";
  category: string;
  detail: string;
  score: number;
}

interface MonitoredEmail {
  id: string;
  fileName: string;
  content: string;
  score: number;
  level: string;
  indicators: Indicator[];
  timestamp: Date;
  status: "scanning" | "safe" | "suspicious" | "phishing";
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
const DANGEROUS_EXTENSIONS = [".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".wsf", ".msi", ".pif", ".hta"];

function analyzeEmail(raw: string): { score: number; indicators: Indicator[] } {
  const email = raw.toLowerCase();
  const indicators: Indicator[] = [];
  let score = 0;

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

  const linkPattern = /https?:\/\/[^\s"'<>]+/gi;
  const links = raw.match(linkPattern) || [];
  if (links.length > 0) {
    indicators.push({ type: "warning", category: "URL Analysis", detail: `${links.length} external link(s) found`, score: 10 });
    score += 10;

    const shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly"];
    links.forEach((link) => {
      if (shorteners.some((s) => link.includes(s))) {
        score += 20;
        indicators.push({ type: "critical", category: "URL Analysis", detail: `Shortened/obfuscated URL: ${link.slice(0, 60)}`, score: 20 });
      }
    });

    const ipUrl = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
    links.forEach((link) => {
      if (ipUrl.test(link)) {
        score += 25;
        indicators.push({ type: "critical", category: "URL Analysis", detail: `IP-based URL detected: ${link.slice(0, 60)}`, score: 25 });
      }
    });
  }

  SUSPICIOUS_TLDS.forEach((tld) => {
    if (email.includes(tld)) {
      score += 30;
      indicators.push({ type: "critical", category: "Domain Analysis", detail: `Suspicious TLD detected: ${tld}`, score: 30 });
    }
  });

  DANGEROUS_EXTENSIONS.forEach((ext) => {
    // Only flag if it looks like a filename (preceded by word char), not domain like .com
    const extRegex = new RegExp(`\\w${ext.replace('.', '\\.')}(?:\\s|$|[^a-z])`, 'i');
    if (extRegex.test(raw)) {
      score += 25;
      indicators.push({ type: "critical", category: "Attachment Threat", detail: `Dangerous file extension referenced: ${ext}`, score: 25 });
    }
  });

  if (email.includes("spf=fail") || email.includes("spf=softfail")) {
    score += 25;
    indicators.push({ type: "critical", category: "Header Analysis", detail: "SPF authentication failed — sender domain not verified", score: 25 });
  }
  if (email.includes("dkim=fail")) {
    score += 25;
    indicators.push({ type: "critical", category: "Header Analysis", detail: "DKIM signature verification failed", score: 25 });
  }
  if (email.includes("spf=pass")) {
    indicators.push({ type: "safe", category: "Header Analysis", detail: "SPF authentication passed", score: 0 });
  }
  if (email.includes("dkim=pass")) {
    indicators.push({ type: "safe", category: "Header Analysis", detail: "DKIM signature verified", score: 0 });
  }

  const fromMatch = email.match(/from:\s*[^<]*<([^>]+)>/i);
  const replyMatch = email.match(/reply-to:\s*[^<]*<([^>]+)>/i);
  if (fromMatch && replyMatch) {
    const fromDomain = fromMatch[1].split("@")[1];
    const replyDomain = replyMatch[1].split("@")[1];
    if (fromDomain !== replyDomain) {
      score += 20;
      indicators.push({ type: "critical", category: "Sender Spoofing", detail: `Reply-To domain (${replyDomain}) doesn't match From domain (${fromDomain})`, score: 20 });
    }
  }

  const urgencyPatterns = ["immediately", "within 24 hours", "expire", "action required", "final warning", "last chance"];
  urgencyPatterns.forEach((p) => {
    if (email.includes(p)) {
      score += 10;
      indicators.push({ type: "warning", category: "Urgency Detection", detail: `Urgency pressure phrase: "${p}"`, score: 10 });
    }
  });

  score = Math.min(score, 100);

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

const SCAN_STEPS = [
  { label: "Header Analysis", icon: Mail },
  { label: "Link Inspection", icon: Link2 },
  { label: "Content Detection", icon: Search },
  { label: "Domain Verification", icon: Globe },
  { label: "Attachment Scan", icon: FileWarning },
  { label: "AI Threat Assessment", icon: Brain },
];

// ─── SSE Stream Parser ──────────────────────────────────────────────
async function streamAiResponse(
  prompt: string,
  onDelta: (text: string) => void,
  onDone: () => void,
  onError: (err: string) => void
) {
  const url = `${import.meta.env.VITE_SUPABASE_URL}/functions/v1/ai-assistant`;
  try {
    const resp = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY}`,
        apikey: import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY,
      },
      body: JSON.stringify({ message: prompt }),
    });

    if (!resp.ok) {
      if (resp.status === 429) { onError("Rate limit exceeded. Please try again in a moment."); return; }
      if (resp.status === 402) { onError("Usage limit reached. Please add credits to continue."); return; }
      const errText = await resp.text();
      try {
        const errJson = JSON.parse(errText);
        onError(errJson.error || "AI service error");
      } catch {
        onError("AI service error");
      }
      return;
    }

    if (!resp.body) { onError("No response body"); return; }

    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      let newlineIdx: number;
      while ((newlineIdx = buffer.indexOf("\n")) !== -1) {
        let line = buffer.slice(0, newlineIdx);
        buffer = buffer.slice(newlineIdx + 1);
        if (line.endsWith("\r")) line = line.slice(0, -1);
        if (line.startsWith(":") || line.trim() === "") continue;
        if (!line.startsWith("data: ")) continue;

        const jsonStr = line.slice(6).trim();
        if (jsonStr === "[DONE]") { onDone(); return; }

        try {
          const parsed = JSON.parse(jsonStr);
          const content = parsed.choices?.[0]?.delta?.content;
          if (content) onDelta(content);
        } catch {
          buffer = line + "\n" + buffer;
          break;
        }
      }
    }

    // Flush remaining
    if (buffer.trim()) {
      for (let raw of buffer.split("\n")) {
        if (!raw) continue;
        if (raw.endsWith("\r")) raw = raw.slice(0, -1);
        if (!raw.startsWith("data: ")) continue;
        const jsonStr = raw.slice(6).trim();
        if (jsonStr === "[DONE]") continue;
        try {
          const parsed = JSON.parse(jsonStr);
          const content = parsed.choices?.[0]?.delta?.content;
          if (content) onDelta(content);
        } catch { /* ignore */ }
      }
    }
    onDone();
  } catch (e) {
    onError(e instanceof Error ? e.message : "Network error");
  }
}

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
  const [uploadedFiles, setUploadedFiles] = useState<File[]>([]);
  const [monitoredEmails, setMonitoredEmails] = useState<MonitoredEmail[]>([]);
  const [isMonitoring, setIsMonitoring] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const gaugeRef = useRef<HTMLDivElement>(null);
  const autoScanRef = useRef(false);

  useEffect(() => {
    if (!loading && !user) navigate("/auth");
  }, [user, loading, navigate]);

  // Auto-scan when file is uploaded
  useEffect(() => {
    if (autoScanRef.current && emailContent.trim() && !isScanning) {
      autoScanRef.current = false;
      runScan();
    }
  }, [emailContent]);

  // Handle file upload
  const handleFileUpload = useCallback(async (files: FileList | null) => {
    if (!files) return;
    const validFiles: File[] = [];
    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      const ext = file.name.toLowerCase();
      if (ext.endsWith(".eml") || ext.endsWith(".msg") || ext.endsWith(".txt") || ext.endsWith(".mhtml") || ext.endsWith(".pdf")) {
        validFiles.push(file);
      } else {
        toast({ title: "Unsupported file", description: `${file.name} — only .eml, .msg, .txt, .mhtml, .pdf files are supported.`, variant: "destructive" });
      }
    }
    if (validFiles.length === 0) return;

    setUploadedFiles((prev) => [...prev, ...validFiles]);

    // Read first file content into the textarea for analysis
    const firstFile = validFiles[0];
    if (firstFile.name.toLowerCase().endsWith(".pdf")) {
      try {
        const arrayBuffer = await firstFile.arrayBuffer();
        const pdf = await pdfjsLib.getDocument({ data: arrayBuffer }).promise;
        let text = "";
        for (let i = 1; i <= pdf.numPages; i++) {
          const page = await pdf.getPage(i);
          const content = await page.getTextContent();
          text += content.items.map((item: any) => item.str).join(" ") + "\n";
        }
        setEmailContent(text);
        toast({ title: "PDF loaded", description: `${firstFile.name} (${pdf.numPages} pages) — auto-scanning...` });
        // Auto-trigger scan after setting content
        setTimeout(() => {
          autoScanRef.current = true;
        }, 100);
      } catch {
        toast({ title: "PDF Error", description: "Could not extract text from PDF.", variant: "destructive" });
      }
    } else {
      const reader = new FileReader();
      reader.onload = (e) => {
        const content = e.target?.result as string;
        setEmailContent(content);
        toast({ title: "File loaded", description: `${firstFile.name} — auto-scanning...` });
        setTimeout(() => {
          autoScanRef.current = true;
        }, 100);
      };
      reader.readAsText(firstFile);
    }
  }, [toast]);

  // Handle drag & drop
  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    handleFileUpload(e.dataTransfer.files);
  }, [handleFileUpload]);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  }, []);

  // Remove uploaded file
  const removeFile = (index: number) => {
    setUploadedFiles((prev) => prev.filter((_, i) => i !== index));
    if (uploadedFiles.length === 1) setEmailContent("");
  };

  // Real-time monitor: process all uploaded files
  const startRealTimeMonitor = useCallback(async () => {
    if (uploadedFiles.length === 0) {
      toast({ title: "No files", description: "Upload email files to start real-time monitoring.", variant: "destructive" });
      return;
    }
    setIsMonitoring(true);
    setMonitoredEmails([]);

    for (const file of uploadedFiles) {
      const id = crypto.randomUUID();
      // Add as scanning
      setMonitoredEmails((prev) => [
        ...prev,
        { id, fileName: file.name, content: "", score: 0, level: "SCANNING", indicators: [], timestamp: new Date(), status: "scanning" },
      ]);

      // Read file (support PDF)
      let content = "";
      if (file.name.toLowerCase().endsWith(".pdf")) {
        try {
          const arrayBuffer = await file.arrayBuffer();
          const pdf = await pdfjsLib.getDocument({ data: arrayBuffer }).promise;
          for (let i = 1; i <= pdf.numPages; i++) {
            const page = await pdf.getPage(i);
            const tc = await page.getTextContent();
            content += tc.items.map((item: any) => item.str).join(" ") + "\n";
          }
        } catch { content = "[PDF extraction failed]"; }
      } else {
        content = await new Promise<string>((resolve) => {
          const reader = new FileReader();
          reader.onload = (e) => resolve(e.target?.result as string || "");
          reader.readAsText(file);
        });
      }

      // Simulate scan delay for real-time feel
      await new Promise((r) => setTimeout(r, 800));

      const analysis = analyzeEmail(content);
      const level = getThreatLevel(analysis.score);
      const status: MonitoredEmail["status"] = analysis.score >= 60 ? "phishing" : analysis.score >= 30 ? "suspicious" : "safe";

      setMonitoredEmails((prev) =>
        prev.map((em) =>
          em.id === id
            ? { ...em, content, score: analysis.score, level: level.label, indicators: analysis.indicators, status, timestamp: new Date() }
            : em
        )
      );
    }
    setIsMonitoring(false);
    toast({ title: "Monitoring complete", description: `${uploadedFiles.length} email(s) analyzed in real-time.` });
  }, [uploadedFiles, toast]);

  const runScan = async () => {
    if (!emailContent.trim()) {
      toast({ title: "Empty input", description: "Upload an email file or paste content to analyze.", variant: "destructive" });
      return;
    }
    setResult(null);
    setAiReport(null);
    setIsScanning(true);
    setScanStep(0);

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

    if (analysis.score >= 30) {
      generateAiReport(analysis);
    }
  };

  const generateAiReport = async (analysis: { score: number; indicators: Indicator[] }) => {
    setAiLoading(true);
    setAiReport("");

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

    let fullReport = "";
    await streamAiResponse(
      prompt,
      (delta) => {
        fullReport += delta;
        setAiReport(fullReport);
      },
      () => {
        setAiLoading(false);
        if (!fullReport.trim()) {
          setAiReport("AI analysis could not generate a report. The detection engine results above are still valid.");
        }
      },
      (err) => {
        setAiLoading(false);
        setAiReport(`AI analysis error: ${err}. The detection engine results above are still valid.`);
        toast({ title: "AI Error", description: err, variant: "destructive" });
      }
    );
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
              Upload .eml / .msg / .txt / .pdf email files or paste content directly for analysis
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* File Upload Zone */}
            <div
              onDrop={handleDrop}
              onDragOver={handleDragOver}
              onClick={() => fileInputRef.current?.click()}
              className={cn(
                "border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-all duration-200",
                "border-border hover:border-primary/50 hover:bg-primary/5",
                "flex flex-col items-center gap-3"
              )}
            >
              <Upload className="w-10 h-10 text-muted-foreground" />
              <div>
                <p className="font-mono text-sm text-foreground">Drop email files here or click to browse</p>
                <p className="font-mono text-xs text-muted-foreground mt-1">
                  Supports .eml, .msg, .txt, .mhtml, .pdf files (multiple files for batch monitoring)
                </p>
              </div>
              <input
                ref={fileInputRef}
                type="file"
                accept=".eml,.msg,.txt,.mhtml,.pdf"
                multiple
                onChange={(e) => handleFileUpload(e.target.files)}
                className="hidden"
              />
            </div>

            {/* Uploaded Files List */}
            {uploadedFiles.length > 0 && (
              <div className="space-y-2">
                <span className="font-mono text-xs text-muted-foreground">Uploaded files:</span>
                <div className="flex flex-wrap gap-2">
                  {uploadedFiles.map((file, i) => (
                    <div
                      key={i}
                      className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-secondary/50 border border-border font-mono text-xs"
                    >
                      <FileText className="w-3.5 h-3.5 text-primary" />
                      <span className="text-foreground">{file.name}</span>
                      <span className="text-muted-foreground">({(file.size / 1024).toFixed(1)}KB)</span>
                      <button onClick={(e) => { e.stopPropagation(); removeFile(i); }} className="text-muted-foreground hover:text-destructive transition-colors">
                        <Trash2 className="w-3 h-3" />
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Text area for preview / manual paste */}
            <Textarea
              value={emailContent}
              onChange={(e) => setEmailContent(e.target.value)}
              placeholder={`Email content will appear here after file upload, or paste manually...\n\nExample:\nFrom: security@bank-al3rt.xyz\nReply-To: hacker@evil.ru\nSubject: Urgent: Verify Your Account Immediately\n\nDear Customer,\nYour account has been suspended. Click here to verify: http://192.168.1.1/login`}
              className="min-h-[160px] font-mono text-sm bg-secondary/30 border-border focus:border-primary resize-y"
            />

            <div className="flex items-center gap-3 flex-wrap">
              <Button onClick={runScan} disabled={isScanning || !emailContent.trim()} variant="cyber" size="lg" className="gap-2">
                {isScanning ? (
                  <><Loader2 className="w-5 h-5 animate-spin" /> Scanning...</>
                ) : (
                  <><Zap className="w-5 h-5" /> Analyze Email</>
                )}
              </Button>
              {uploadedFiles.length > 1 && (
                <Button onClick={startRealTimeMonitor} disabled={isMonitoring} variant="outline" size="lg" className="gap-2">
                  {isMonitoring ? (
                    <><Loader2 className="w-5 h-5 animate-spin" /> Monitoring...</>
                  ) : (
                    <><Radio className="w-5 h-5" /> Real-Time Batch Scan</>
                  )}
                </Button>
              )}
              <span className="text-xs font-mono text-muted-foreground">
                {emailContent.length} characters | {uploadedFiles.length} file(s)
              </span>
            </div>
          </CardContent>
        </Card>

        {/* ── Real-Time Monitoring Feed ────────────────────────── */}
        {monitoredEmails.length > 0 && (
          <Card className="cyber-card border-primary/30">
            <CardHeader className="pb-3">
              <CardTitle className="text-base font-mono flex items-center gap-2">
                <Radio className="w-4 h-4 text-primary animate-pulse" />
                Real-Time Email Monitor
              </CardTitle>
              <CardDescription className="font-mono text-xs">
                Live scanning and flagging of uploaded email files
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {monitoredEmails.map((em) => (
                  <motion.div
                    key={em.id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    className={cn(
                      "flex items-center justify-between p-3 rounded-lg border font-mono text-sm transition-all",
                      em.status === "scanning" && "border-primary/30 bg-primary/5",
                      em.status === "safe" && "border-success/30 bg-success/5",
                      em.status === "suspicious" && "border-warning/30 bg-warning/5",
                      em.status === "phishing" && "border-destructive/30 bg-destructive/5 animate-pulse"
                    )}
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      {em.status === "scanning" && <Loader2 className="w-4 h-4 text-primary animate-spin flex-shrink-0" />}
                      {em.status === "safe" && <ShieldCheck className="w-4 h-4 text-success flex-shrink-0" />}
                      {em.status === "suspicious" && <AlertTriangle className="w-4 h-4 text-warning flex-shrink-0" />}
                      {em.status === "phishing" && <XCircle className="w-4 h-4 text-destructive flex-shrink-0" />}
                      <div className="min-w-0">
                        <p className="text-foreground truncate">{em.fileName}</p>
                        <p className="text-xs text-muted-foreground">
                          {em.status === "scanning" ? "Scanning..." : `${em.indicators.length} indicators | ${em.timestamp.toLocaleTimeString()}`}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      {em.status !== "scanning" && (
                        <>
                          <span className={cn(
                            "text-xs font-bold",
                            em.status === "safe" && "text-success",
                            em.status === "suspicious" && "text-warning",
                            em.status === "phishing" && "text-destructive"
                          )}>
                            {em.score}/100
                          </span>
                          <Badge
                            variant="outline"
                            className={cn(
                              "text-[10px]",
                              em.status === "safe" && "border-success/50 text-success",
                              em.status === "suspicious" && "border-warning/50 text-warning",
                              em.status === "phishing" && "border-destructive/50 text-destructive"
                            )}
                          >
                            {em.level}
                          </Badge>
                        </>
                      )}
                    </div>
                  </motion.div>
                ))}
              </div>
              {/* Summary */}
              {!isMonitoring && monitoredEmails.length > 0 && (
                <div className="mt-4 p-3 rounded-lg bg-secondary/30 border border-border">
                  <div className="flex gap-4 font-mono text-xs">
                    <span className="text-success">
                      ✓ {monitoredEmails.filter((e) => e.status === "safe").length} Safe
                    </span>
                    <span className="text-warning">
                      ⚠ {monitoredEmails.filter((e) => e.status === "suspicious").length} Suspicious
                    </span>
                    <span className="text-destructive">
                      ✗ {monitoredEmails.filter((e) => e.status === "phishing").length} Phishing
                    </span>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* ── Animated Scan Progress ────────────────────────────── */}
        <AnimatePresence>
          {isScanning && (
            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }}>
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
                          {done ? <CheckCircle2 className="w-4 h-4 flex-shrink-0" /> : active ? <Loader2 className="w-4 h-4 animate-spin flex-shrink-0" /> : <StepIcon className="w-4 h-4 flex-shrink-0" />}
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
            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
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
                      <div className="relative w-44 h-44" ref={gaugeRef}>
                        <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
                          <circle cx="60" cy="60" r="52" fill="none" stroke="hsl(var(--muted))" strokeWidth="10" />
                          <motion.circle
                            cx="60" cy="60" r="52" fill="none"
                            stroke={result.score >= 60 ? "hsl(var(--destructive))" : result.score >= 30 ? "hsl(var(--warning))" : "hsl(var(--success))"}
                            strokeWidth="10" strokeLinecap="round"
                            strokeDasharray={`${2 * Math.PI * 52}`}
                            initial={{ strokeDashoffset: 2 * Math.PI * 52 }}
                            animate={{ strokeDashoffset: 2 * Math.PI * 52 * (1 - result.score / 100) }}
                            transition={{ duration: 1.2, ease: "easeOut" }}
                            style={{
                              filter: result.score >= 60 ? "drop-shadow(0 0 8px hsl(var(--destructive)/0.6))" : result.score >= 30 ? "drop-shadow(0 0 8px hsl(var(--warning)/0.6))" : "drop-shadow(0 0 8px hsl(var(--success)/0.6))",
                            }}
                          />
                        </svg>
                        <div className="absolute inset-0 flex flex-col items-center justify-center">
                          <motion.span className={cn("text-4xl font-display font-bold", threat.color)} initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ delay: 0.5, type: "spring" }}>
                            {result.score}
                          </motion.span>
                          <span className="text-xs font-mono text-muted-foreground">/100</span>
                        </div>
                      </div>
                      <span className={cn("mt-4 font-mono text-sm px-4 py-1 rounded-full border", threat.bg, threat.color, threat.border)}>
                        {threat.label}
                      </span>
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
                                <Badge variant="outline" className="text-xs">+{data.totalScore}</Badge>
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
                            {ind.score > 0 && <span className="text-[10px] text-destructive font-bold">+{ind.score}</span>}
                          </div>
                          <p className="text-foreground/80">{ind.detail}</p>
                        </div>
                      </motion.div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* ── AI Analysis Report (Streaming) ────────────────── */}
              <Card className="cyber-card border-border">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base font-mono flex items-center gap-2">
                    <Sparkles className="w-4 h-4 text-primary" />
                    AI Security Analysis Report
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {aiLoading || aiReport ? (
                    <div className="bg-secondary/30 rounded-lg p-4 border border-border font-mono text-sm whitespace-pre-wrap text-foreground/80 leading-relaxed">
                      {aiReport || ""}
                      {aiLoading && <span className="inline-block w-2 h-4 bg-primary animate-pulse ml-0.5" />}
                    </div>
                  ) : (
                    <div className="flex flex-col items-center gap-3 py-6">
                      <Brain className="w-8 h-8 text-muted-foreground" />
                      <p className="font-mono text-sm text-muted-foreground">
                        AI report auto-generates for medium/high threats, or click below
                      </p>
                      <Button variant="outline" size="sm" onClick={() => result && generateAiReport(result)} disabled={!result} className="gap-2">
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
