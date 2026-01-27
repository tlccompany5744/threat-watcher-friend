import { 
  Users, ShieldCheck, Radar, TrendingUp, Eye, Mail, Sparkles 
} from 'lucide-react';

export interface ExtendedLiveLab {
  id: string;
  title: string;
  description: string;
  difficulty: 'beginner' | 'intermediate' | 'advanced' | 'expert';
  challenge: string;
  hint: string;
  solution: string;
  validator: (input: string) => boolean;
  completed: boolean;
  points: number;
  timeEstimate: string;
  skills: string[];
}

export interface ExtendedLesson {
  id: string;
  title: string;
  content: string;
  codeExample?: string;
  keyPoints?: string[];
  liveLab?: ExtendedLiveLab;
  completed: boolean;
}

export interface ExtendedModule {
  id: string;
  title: string;
  description: string;
  icon: typeof Users;
  color: string;
  bgGradient: string;
  lessons: ExtendedLesson[];
  completed: boolean;
  category: 'fundamentals' | 'offensive' | 'defensive' | 'advanced';
  prerequisites?: string[];
  estimatedTime: string;
}

export const extendedModules: ExtendedModule[] = [
  // ============ SECURITY AWARENESS FOR EMPLOYEES ============
  {
    id: 'security-awareness',
    title: 'Security Awareness Training',
    description: 'Essential cybersecurity training for all employees - phishing, passwords, and safe practices',
    icon: Users,
    color: 'text-emerald-500',
    bgGradient: 'from-emerald-500/20 to-teal-500/20',
    completed: false,
    category: 'fundamentals',
    estimatedTime: '3 hours',
    lessons: [
      {
        id: 'awareness-1',
        title: 'Recognizing Phishing Attacks',
        completed: false,
        keyPoints: [
          'Common phishing indicators',
          'Spear phishing vs mass phishing',
          'Business Email Compromise (BEC)',
          'Reporting suspicious emails'
        ],
        content: `PHISHING ATTACK RECOGNITION

WHAT IS PHISHING?
Social engineering attack using fake emails, texts, or websites to steal credentials, data, or money.

RED FLAGS TO LOOK FOR:

1. SENDER ADDRESS
   ✗ amazon-support@gmail.com (fake)
   ✓ support@amazon.com (real)
   Watch for: typos, extra characters, wrong domains

2. URGENCY & THREATS
   "Your account will be suspended!"
   "Act now or lose access!"
   "Immediate action required!"

3. SUSPICIOUS LINKS
   Hover before clicking!
   ✗ amaz0n.com (zero instead of 'o')
   ✗ amazon.suspicious-site.com (subdomain trick)
   ✗ bit.ly/xyz (shortened links)

4. POOR GRAMMAR
   "Dear Valued Customer,"
   Spelling mistakes, odd phrasing

5. REQUESTS FOR SENSITIVE INFO
   Legitimate companies NEVER ask for:
   • Passwords via email
   • SSN or tax IDs
   • Full credit card numbers

TYPES OF PHISHING:

SPEAR PHISHING - Targeted at specific person
WHALING - Targets executives
BEC - Impersonates CEO/CFO for wire transfers

WHAT TO DO:
1. DON'T click links or attachments
2. Verify sender through known channels
3. Report to IT/Security team
4. Delete the email`,
        codeExample: `// Phishing Detection Checklist
const phishingIndicators = {
  senderChecks: [
    "Is the domain legitimate? (check after the @)",
    "Does the display name match the email?",
    "Is this person's usual communication style?"
  ],
  contentChecks: [
    "Creating urgency or fear?",
    "Asking for credentials or payment?",
    "Generic greeting (Dear Customer)?",
    "Grammar/spelling errors?"
  ],
  linkChecks: [
    "Hover to preview - does URL match text?",
    "Is the domain misspelled?",
    "Using URL shorteners (bit.ly, tinyurl)?"
  ],
  reportingSteps: [
    "1. Don't click anything",
    "2. Forward to security@yourcompany.com",
    "3. Report in email client",
    "4. Delete from inbox and trash"
  ]
};`,
        liveLab: {
          id: 'lab-phishing-id',
          title: 'Spot the Phish',
          description: 'Identify phishing indicators in an email',
          difficulty: 'beginner',
          challenge: 'Email from "IT-Support@yourcompany.corn" says: "Dear Employee, Your password expires today. Click here to reset: http://bit.ly/reset123". Name TWO red flags.',
          hint: 'Look at the sender domain and the link carefully...',
          solution: '1. Domain typo ".corn" instead of ".com", 2. Shortened URL (bit.ly) hides real destination',
          validator: (input: string) => {
            const lower = input.toLowerCase();
            const hasDomainIssue = lower.includes('corn') || lower.includes('domain') || lower.includes('typo');
            const hasLinkIssue = lower.includes('bit.ly') || lower.includes('shorten') || lower.includes('url');
            return hasDomainIssue || hasLinkIssue;
          },
          completed: false,
          points: 25,
          timeEstimate: '5 min',
          skills: ['Phishing detection', 'Email security']
        }
      },
      {
        id: 'awareness-2',
        title: 'Password Security & MFA',
        completed: false,
        keyPoints: [
          'Creating strong passwords',
          'Password managers benefits',
          'Multi-factor authentication',
          'Avoiding password reuse'
        ],
        content: `PASSWORD SECURITY BEST PRACTICES

WHY PASSWORDS MATTER:
• 81% of breaches involve weak or stolen passwords
• Average person has 100+ accounts

STRONG PASSWORD RULES:
❌ WEAK: Password123, Company2024, Your name + birthdate
✓ STRONG: 16+ characters, mix of upper/lower/numbers/symbols

BEST APPROACH: PASSPHRASES
"correct-horse-battery-staple-42!" - Long, memorable, hard to crack

PASSWORD MANAGERS:
• Generate unique strong passwords
• Store securely encrypted
• Auto-fill (prevents phishing!)
Recommended: Bitwarden, 1Password, Dashlane

MULTI-FACTOR AUTHENTICATION (MFA):
Something you KNOW (password) + Something you HAVE (phone) + Something you ARE (fingerprint)

MFA METHODS (Best to Worst):
1. Hardware keys (YubiKey)
2. Authenticator apps (Google Auth, Authy)
3. Push notifications
4. SMS codes

NEVER:
• Reuse passwords across sites
• Share passwords via email/chat
• Write passwords on sticky notes`,
        codeExample: `// Password Strength Checker
function checkPasswordStrength(password) {
  let score = 0;
  const feedback = [];
  
  if (password.length >= 16) score += 2;
  else feedback.push("Use 16+ characters");
  
  if (/[A-Z]/.test(password)) score += 1;
  if (/[a-z]/.test(password)) score += 1;
  if (/[0-9]/.test(password)) score += 1;
  if (/[!@#$%^&*]/.test(password)) score += 1;
  
  if (/password|123456|qwerty/i.test(password)) {
    score -= 3;
    feedback.push("Avoid common passwords");
  }
  
  return { score, feedback };
}`,
        liveLab: {
          id: 'lab-password',
          title: 'Password Evaluation',
          description: 'Assess password security',
          difficulty: 'beginner',
          challenge: 'Rank these passwords from WEAKEST to STRONGEST: A) "Summer2024!", B) "correct-horse-battery-staple", C) "J@n3.D0e.1985", D) "xK9#mP2$vL5@nQ8"',
          hint: 'Consider length, personal info, dictionary words, and randomness...',
          solution: 'Weakest to Strongest: C (personal info), A (predictable), D (short but random), B (longest passphrase)',
          validator: (input: string) => {
            const lower = input.toLowerCase();
            return (lower.includes('c') && lower.includes('weak')) || 
                   (lower.includes('b') && lower.includes('strong'));
          },
          completed: false,
          points: 30,
          timeEstimate: '8 min',
          skills: ['Password security', 'Risk assessment']
        }
      },
      {
        id: 'awareness-3',
        title: 'Safe Browsing & Social Media',
        completed: false,
        keyPoints: [
          'Identifying malicious websites',
          'Safe downloading practices',
          'Social media privacy risks',
          'Public Wi-Fi security'
        ],
        content: `SAFE BROWSING & SOCIAL MEDIA

WEBSITE SECURITY CHECKS:
✓ HTTPS (padlock icon) - but attackers use HTTPS too!
✓ Check domain carefully
   • bankofamerica.com (real)
   • bank0famerica.com (fake)

DOWNLOADING SAFELY:
1. Only from official sources
2. Verify downloads (check hashes)
3. Watch for dangerous file types: .exe, .bat, .js

SOCIAL MEDIA RISKS:
What attackers learn from your posts:
• Your job title & company
• Vacation dates (house empty!)
• Family member names
• Pet names (password hints)

PUBLIC WI-FI:
• Avoid banking/shopping
• Use VPN always
• Disable auto-connect
• Verify network name with staff`,
        liveLab: {
          id: 'lab-social-engineering',
          title: 'Social Media OSINT',
          description: 'Understand information exposure risks',
          difficulty: 'beginner',
          challenge: 'An employee posts: "Excited for my first day at Acme Corp! Starting as Senior Developer. Flying to NYC tomorrow!" What info could an attacker use?',
          hint: 'Think about what details could be used for spear phishing...',
          solution: 'Company name, job title, location, travel dates, new employee status',
          validator: (input: string) => {
            const lower = input.toLowerCase();
            return (lower.includes('company') || lower.includes('acme')) &&
                   (lower.includes('title') || lower.includes('travel') || lower.includes('new'));
          },
          completed: false,
          points: 35,
          timeEstimate: '10 min',
          skills: ['OSINT awareness', 'Social engineering', 'Privacy']
        }
      },
      {
        id: 'awareness-4',
        title: 'Data Handling & Classification',
        completed: false,
        keyPoints: [
          'Data classification levels',
          'Handling sensitive information',
          'Secure file sharing',
          'Clean desk policy'
        ],
        content: `DATA HANDLING & CLASSIFICATION

DATA CLASSIFICATION LEVELS:

PUBLIC - Marketing materials, press releases
INTERNAL - Company policies, org charts
CONFIDENTIAL - Employee records, financial reports
RESTRICTED - Customer PII, source code, encryption keys

HANDLING SENSITIVE DATA:
DO:
✓ Encrypt files before sending
✓ Use approved file sharing tools
✓ Verify recipient identity

DON'T:
✗ Email sensitive attachments unencrypted
✗ Use personal cloud storage
✗ Leave on screen when away

CLEAN DESK POLICY:
• Lock computer when away (Win+L)
• Secure documents in drawers
• Shred sensitive printouts
• No passwords on sticky notes!`,
        liveLab: {
          id: 'lab-data-class',
          title: 'Data Classification',
          description: 'Classify information correctly',
          difficulty: 'beginner',
          challenge: 'Classify this data: Customer credit card numbers with CVV codes. What classification level and handling is required?',
          hint: 'This is PCI DSS regulated data...',
          solution: 'RESTRICTED - Requires encryption, strict access controls, PCI DSS compliance',
          validator: (input: string) => {
            const lower = input.toLowerCase();
            return (lower.includes('restrict') || lower.includes('secret')) &&
                   (lower.includes('encrypt') || lower.includes('pci'));
          },
          completed: false,
          points: 30,
          timeEstimate: '8 min',
          skills: ['Data classification', 'Compliance']
        }
      }
    ]
  },
  // ============ ZERO TRUST ARCHITECTURE ============
  {
    id: 'zero-trust',
    title: 'Zero Trust Security',
    description: 'Modern security architecture - never trust, always verify',
    icon: ShieldCheck,
    color: 'text-indigo-500',
    bgGradient: 'from-indigo-500/20 to-purple-500/20',
    completed: false,
    category: 'advanced',
    estimatedTime: '4 hours',
    prerequisites: ['network-defense'],
    lessons: [
      {
        id: 'zt-1',
        title: 'Zero Trust Fundamentals',
        completed: false,
        keyPoints: [
          'Never trust, always verify principle',
          'Microsegmentation concepts',
          'Least privilege access',
          'Continuous verification'
        ],
        content: `ZERO TRUST ARCHITECTURE

CORE PRINCIPLE: "Never Trust, Always Verify"

Traditional (Castle & Moat):
• Trust inside the network
• Firewall protects perimeter
• Once inside, free access

Zero Trust:
• Trust nothing by default
• Verify every request
• Assume breach

ZERO TRUST PILLARS:

1. VERIFY EXPLICITLY
   Every access request verified:
   • User identity
   • Device health
   • Location
   • Data sensitivity

2. LEAST PRIVILEGE ACCESS
   • Just-in-time access
   • Just-enough access
   • Time-limited permissions

3. ASSUME BREACH
   • Minimize blast radius
   • Segment access
   • Encrypt all traffic
   • Continuous monitoring

KEY COMPONENTS:
IDENTITY - Strong auth (MFA), risk-based access
DEVICES - Health verification, endpoint detection
NETWORK - Microsegmentation, encrypted comms
DATA - Classification, encryption everywhere`,
        codeExample: `// Zero Trust Access Decision
interface AccessRequest {
  userId: string;
  deviceId: string;
  resourceId: string;
  location: string;
}

function calculateAccessDecision(request, signals) {
  // Block high-risk users
  if (signals.userRisk === 'high') {
    return { allowed: false, reason: 'High risk user' };
  }
  
  // Require device compliance for sensitive resources
  if (signals.sensitiveResource && !signals.deviceCompliance) {
    return { allowed: false, reason: 'Device not compliant' };
  }
  
  // Step-up auth for anomalies
  if (signals.unusualLocation || signals.afterHours) {
    return { allowed: true, requireMFA: true };
  }
  
  return { allowed: true, requireMFA: false };
}`,
        liveLab: {
          id: 'lab-zero-trust',
          title: 'Zero Trust Decision',
          description: 'Apply Zero Trust principles',
          difficulty: 'intermediate',
          challenge: 'An employee with valid credentials accesses the payroll system from a new device in a different country at 3 AM. What should Zero Trust do?',
          hint: 'Consider the anomalies and appropriate response...',
          solution: 'Block or require step-up authentication (MFA), alert security team, log the attempt',
          validator: (input: string) => {
            const lower = input.toLowerCase();
            return (lower.includes('block') || lower.includes('mfa') || lower.includes('verify')) &&
                   (lower.includes('alert') || lower.includes('log'));
          },
          completed: false,
          points: 75,
          timeEstimate: '15 min',
          skills: ['Zero Trust', 'Access control', 'Risk assessment']
        }
      },
      {
        id: 'zt-2',
        title: 'Identity & Access Management',
        completed: false,
        keyPoints: [
          'Identity lifecycle management',
          'Role-based access control (RBAC)',
          'Privileged access management',
          'Just-in-time access'
        ],
        content: `IDENTITY & ACCESS MANAGEMENT (IAM)

IDENTITY LIFECYCLE:
Joiner → Mover → Leaver

JOINER (New hire): Create accounts, assign base access
MOVER (Role change): Update access, remove old permissions
LEAVER (Departure): Disable accounts immediately, revoke all access

ACCESS CONTROL MODELS:

RBAC (Role-Based)
• Access based on job role
• Example: "Developer" role gets code repos
• Easier to manage at scale

ABAC (Attribute-Based)
• Access based on attributes
• Example: "Department=Finance AND Location=HQ"
• More granular control

PRIVILEGED ACCESS MANAGEMENT (PAM):
• Just-in-time access (request when needed)
• Session recording
• Password vaulting
• Multi-person approval
• Time-limited access

HIGH-RISK ACCOUNTS:
• Domain Admins
• Database Admins
• Cloud root accounts`,
        liveLab: {
          id: 'lab-pam',
          title: 'Privileged Access',
          description: 'Design PAM controls',
          difficulty: 'intermediate',
          challenge: 'A developer needs production database access to debug an urgent issue. What PAM controls should be in place?',
          hint: 'Think about approval, time limits, and accountability...',
          solution: 'Approval workflow, time-limited access, session recording, read-only if possible, audit logging',
          validator: (input: string) => {
            const lower = input.toLowerCase();
            const hasApproval = lower.includes('approv') || lower.includes('request');
            const hasTimeLimit = lower.includes('time') || lower.includes('limit') || lower.includes('temporary');
            const hasAudit = lower.includes('log') || lower.includes('record') || lower.includes('audit');
            return (hasApproval && hasTimeLimit) || (hasApproval && hasAudit);
          },
          completed: false,
          points: 75,
          timeEstimate: '15 min',
          skills: ['PAM', 'Access control', 'Security architecture']
        }
      }
    ]
  },
  // ============ SOC OPERATIONS ============
  {
    id: 'soc-operations',
    title: 'Security Operations Center',
    description: 'SOC workflows, alert triage, playbooks, and team operations',
    icon: Radar,
    color: 'text-amber-500',
    bgGradient: 'from-amber-500/20 to-orange-500/20',
    completed: false,
    category: 'defensive',
    estimatedTime: '5 hours',
    prerequisites: ['detection'],
    lessons: [
      {
        id: 'soc-1',
        title: 'SOC Fundamentals & Tiers',
        completed: false,
        keyPoints: [
          'SOC organizational structure',
          'Tier 1/2/3 responsibilities',
          'Alert triage workflows',
          'Escalation procedures'
        ],
        content: `SECURITY OPERATIONS CENTER (SOC)

SOC MISSION: Monitor, detect, analyze, respond to security incidents 24/7

SOC TIERS:

TIER 1 - Alert Analyst
• First line of defense
• Monitor SIEM dashboards
• Initial alert triage
• False positive filtering
• Escalate to Tier 2

TIER 2 - Incident Handler
• Deep-dive analysis
• Threat hunting
• Incident investigation
• Coordinate response

TIER 3 - Senior Analyst/Architect
• Advanced threat analysis
• Malware reverse engineering
• Detection engineering
• Process improvement

ALERT TRIAGE WORKFLOW:
1. RECEIVE ALERT - Source identification
2. VALIDATE - Is this a true positive?
3. INVESTIGATE - Gather context, timeline
4. CLASSIFY - Severity determination
5. RESPOND/ESCALATE - Take action or escalate

KEY METRICS:
• MTTD (Mean Time To Detect)
• MTTR (Mean Time To Respond)
• False Positive Rate`,
        codeExample: `// SOC Alert Triage System
class SOCTriage {
  private slaByPriority = {
    critical: 15,  // 15 minutes
    high: 60,      // 1 hour
    medium: 240,   // 4 hours
    low: 1440      // 24 hours
  };
  
  async triageAlert(alert) {
    // Check known false positives
    if (await this.isKnownFalsePositive(alert)) {
      return { classification: 'false_positive' };
    }
    
    // Enrich with threat intel
    const enriched = await this.enrichAlert(alert);
    
    // Check escalation criteria
    const needsEscalation = 
      alert.severity === 'critical' ||
      enriched.matchesThreatIntel;
    
    return { classification: 'needs_investigation', escalated: needsEscalation };
  }
}`,
        liveLab: {
          id: 'lab-soc-triage',
          title: 'Alert Prioritization',
          description: 'Prioritize SOC alerts correctly',
          difficulty: 'intermediate',
          challenge: 'You have 3 alerts: A) Failed login from known IP, B) Malware hash detected on CFO laptop, C) Port scan from external IP. Which do you investigate FIRST?',
          hint: 'Consider severity and business impact...',
          solution: 'B - Malware on executive laptop is highest priority (confirmed threat on critical asset)',
          validator: (input: string) => {
            const lower = input.toLowerCase();
            return lower.includes('b') && (lower.includes('malware') || lower.includes('cfo') || lower.includes('executive'));
          },
          completed: false,
          points: 75,
          timeEstimate: '15 min',
          skills: ['SOC operations', 'Alert triage', 'Prioritization']
        }
      },
      {
        id: 'soc-2',
        title: 'Playbooks & Runbooks',
        completed: false,
        keyPoints: [
          'Playbook vs runbook difference',
          'Creating effective playbooks',
          'Automation opportunities',
          'Continuous improvement'
        ],
        content: `SOC PLAYBOOKS & RUNBOOKS

PLAYBOOK: High-level response process for incident types
• Decision points
• Escalation criteria
• Stakeholder communication

RUNBOOK: Detailed step-by-step technical procedures
• Specific commands
• Tool usage
• Verification steps

PHISHING RESPONSE PLAYBOOK EXAMPLE:

1. DETECTION - User reports, Email gateway, SIEM
2. ANALYSIS - Header analysis, URL reputation, Attachment sandboxing
3. CONTAINMENT - Block sender, Quarantine similar emails
4. ERADICATION - Remove from mailboxes, Reset credentials
5. RECOVERY - Restore blocked legitimate senders
6. LESSONS LEARNED - Update filters, Training needs

AUTOMATION OPPORTUNITIES:
• IOC extraction
• Reputation lookups
• Email quarantine
• User notifications
• Ticket creation

SOAR INTEGRATION:
Security Orchestration, Automation & Response
• Playbook automation
• Case management
• Metric tracking`
      }
    ]
  },
  // ============ RISK MANAGEMENT ============
  {
    id: 'risk-management',
    title: 'Cybersecurity Risk Management',
    description: 'Risk assessment, threat modeling, business impact analysis',
    icon: TrendingUp,
    color: 'text-rose-500',
    bgGradient: 'from-rose-500/20 to-pink-500/20',
    completed: false,
    category: 'fundamentals',
    estimatedTime: '4 hours',
    lessons: [
      {
        id: 'risk-1',
        title: 'Risk Assessment Fundamentals',
        completed: false,
        keyPoints: [
          'Risk = Threat × Vulnerability × Impact',
          'Quantitative vs qualitative assessment',
          'Risk treatment options',
          'Risk register management'
        ],
        content: `CYBERSECURITY RISK MANAGEMENT

RISK FORMULA: Risk = Threat × Vulnerability × Impact

THREAT: Who wants to attack?
• Nation states, Cybercriminals, Hacktivists, Insiders

VULNERABILITY: What weaknesses exist?
• Unpatched systems, Misconfigurations, Weak auth

IMPACT: What's the damage?
• Financial loss, Reputation damage, Regulatory penalties

ASSESSMENT METHODS:

QUALITATIVE - High/Medium/Low ratings, faster
QUANTITATIVE - Dollar values, more precise
  ALE = SLE × ARO
  (Annual Loss Expectancy = Single Loss × Annual Rate)

RISK TREATMENT OPTIONS:
1. ACCEPT - Low impact, low likelihood
2. MITIGATE - Implement controls
3. TRANSFER - Insurance, contracts
4. AVOID - Don't do the risky activity

RISK REGISTER tracks:
• Description, Owner
• Likelihood/Impact ratings
• Current controls
• Residual risk
• Treatment plan`,
        codeExample: `// Risk Assessment Calculator
function assessRisk(risk) {
  const inherentScore = risk.likelihood * risk.impact;
  
  // Control effectiveness reduces residual risk
  const controlEffect = Math.min(risk.controls.length * 0.15, 0.6);
  const residualScore = inherentScore * (1 - controlEffect);
  
  // Determine rating
  let rating;
  if (residualScore >= 20) rating = 'critical';
  else if (residualScore >= 12) rating = 'high';
  else if (residualScore >= 6) rating = 'medium';
  else rating = 'low';
  
  return { inherentScore, residualScore, rating };
}

// Quantitative: ALE Calculation
function calculateALE(assetValue, exposureFactor, annualRate) {
  const sle = assetValue * exposureFactor;
  const ale = sle * annualRate;
  return { sle, ale };
}
// Example: $1M asset, 50% exposure, 10% annual rate
// SLE = $500K, ALE = $50K/year`,
        liveLab: {
          id: 'lab-risk',
          title: 'Risk Calculation',
          description: 'Calculate and prioritize risks',
          difficulty: 'intermediate',
          challenge: 'Risk A: Likelihood 3, Impact 5. Risk B: Likelihood 5, Impact 3. Calculate risk scores and determine which needs attention first.',
          hint: 'Multiply likelihood × impact for each risk...',
          solution: 'Both have score of 15, but Risk A (Impact 5) should be prioritized as catastrophic impact is harder to recover from',
          validator: (input: string) => {
            const lower = input.toLowerCase();
            return (lower.includes('15') || lower.includes('equal')) &&
                   (lower.includes('impact') || lower.includes('a'));
          },
          completed: false,
          points: 75,
          timeEstimate: '15 min',
          skills: ['Risk assessment', 'Risk prioritization']
        }
      },
      {
        id: 'risk-2',
        title: 'Threat Modeling',
        completed: false,
        keyPoints: [
          'STRIDE methodology',
          'Attack trees',
          'Data flow diagrams',
          'Prioritizing threats'
        ],
        content: `THREAT MODELING

PURPOSE: Systematically identify threats before exploitation

STRIDE MODEL:

S - SPOOFING - Pretending to be someone else
    Mitigation: Authentication

T - TAMPERING - Modifying data or code
    Mitigation: Integrity controls

R - REPUDIATION - Denying actions performed
    Mitigation: Logging, signatures

I - INFORMATION DISCLOSURE - Exposing data
    Mitigation: Encryption, access control

D - DENIAL OF SERVICE - Making unavailable
    Mitigation: Rate limiting, redundancy

E - ELEVATION OF PRIVILEGE - Gaining unauthorized access
    Mitigation: Authorization, least privilege

THREAT MODELING PROCESS:
1. DECOMPOSE - Draw data flow diagram, identify entry points
2. IDENTIFY THREATS - Apply STRIDE to each component
3. PRIORITIZE - DREAD scoring
4. MITIGATE - Design countermeasures

DREAD SCORING:
D - Damage potential
R - Reproducibility
E - Exploitability
A - Affected users
D - Discoverability`,
        liveLab: {
          id: 'lab-stride',
          title: 'STRIDE Analysis',
          description: 'Apply STRIDE to a component',
          difficulty: 'intermediate',
          challenge: 'A web app accepts file uploads stored in cloud storage. Name ONE threat for each STRIDE category (S, T, R, I, D, E).',
          hint: 'Think about what could go wrong with file uploads...',
          solution: 'S: Upload as another user, T: Replace files, R: Deny uploading malware, I: Access others files, D: Fill quota, E: Execute uploaded code',
          validator: (input: string) => {
            const lower = input.toLowerCase();
            const categories = ['spoof', 'tamper', 'repudi', 'info', 'denial', 'elev', 'priv'];
            return categories.filter(c => lower.includes(c)).length >= 2;
          },
          completed: false,
          points: 100,
          timeEstimate: '20 min',
          skills: ['Threat modeling', 'STRIDE', 'Security design']
        }
      }
    ]
  },
  // ============ INSIDER THREAT ============
  {
    id: 'insider-threat',
    title: 'Insider Threat Detection',
    description: 'Detecting and preventing threats from within the organization',
    icon: Eye,
    color: 'text-fuchsia-500',
    bgGradient: 'from-fuchsia-500/20 to-pink-500/20',
    completed: false,
    category: 'defensive',
    estimatedTime: '3 hours',
    lessons: [
      {
        id: 'insider-1',
        title: 'Understanding Insider Threats',
        completed: false,
        keyPoints: [
          'Types of insider threats',
          'Behavioral indicators',
          'Technical indicators',
          'Prevention strategies'
        ],
        content: `INSIDER THREAT OVERVIEW

INSIDER THREAT TYPES:

1. MALICIOUS INSIDER - Intentional harm (revenge, money, ideology)
2. NEGLIGENT INSIDER - Unintentional (phishing victim, misconfiguration)
3. COMPROMISED INSIDER - Account/credentials stolen

BEHAVIORAL INDICATORS:
• Working unusual hours
• Accessing unneeded data
• Job dissatisfaction
• Financial stress
• Large data downloads before resignation

TECHNICAL INDICATORS:
• Unusual data access patterns
• Large file transfers
• USB device usage
• Cloud storage uploads
• After-hours activity
• Failed access attempts

PREVENTION STRATEGIES:
1. Principle of least privilege
2. User activity monitoring
3. Data Loss Prevention (DLP)
4. Exit procedures
5. Security awareness training
6. Anonymous reporting channels`,
        codeExample: `// Insider Threat Detection
class InsiderThreatDetector {
  async analyzeActivity(behavior) {
    let score = 0;
    const factors = [];
    
    // Unusual time
    const hour = behavior.timestamp.getHours();
    if (hour < 6 || hour > 22) {
      score += 10;
      factors.push('After-hours activity');
    }
    
    // Large data movement
    if (behavior.fileSize > 100_000_000) {
      score += 20;
      factors.push('Large file transfer (>100MB)');
    }
    
    // USB usage
    if (behavior.action === 'usb') {
      score += 25;
      factors.push('USB device usage');
    }
    
    // Departure risk
    if (await checkDepartureStatus(behavior.userId)) {
      score *= 2;  // Double all risk scores
      factors.push('Employee in notice period');
    }
    
    return { score, factors };
  }
}`,
        liveLab: {
          id: 'lab-insider',
          title: 'Insider Threat Scenario',
          description: 'Identify insider threat indicators',
          difficulty: 'intermediate',
          challenge: 'An employee who gave 2-week notice is downloading large amounts of customer data at 11 PM to a USB drive. What indicators are present and what action should be taken?',
          hint: 'Consider both behavioral and technical indicators...',
          solution: 'Indicators: Notice period, after-hours, bulk download, USB, customer data. Action: Disable access, preserve evidence, notify management',
          validator: (input: string) => {
            const lower = input.toLowerCase();
            const hasIndicators = (lower.includes('notice') || lower.includes('resign')) &&
                                 (lower.includes('usb') || lower.includes('after') || lower.includes('bulk'));
            const hasAction = lower.includes('disable') || lower.includes('revoke') || lower.includes('block');
            return hasIndicators && hasAction;
          },
          completed: false,
          points: 75,
          timeEstimate: '15 min',
          skills: ['Insider threat', 'UEBA', 'Incident response']
        }
      }
    ]
  },
  // ============ BUSINESS EMAIL COMPROMISE ============
  {
    id: 'bec-defense',
    title: 'Business Email Compromise',
    description: 'Defending against CEO fraud, invoice scams, and email-based attacks',
    icon: Mail,
    color: 'text-cyan-500',
    bgGradient: 'from-cyan-500/20 to-teal-500/20',
    completed: false,
    category: 'defensive',
    estimatedTime: '2 hours',
    lessons: [
      {
        id: 'bec-1',
        title: 'BEC Attack Techniques',
        completed: false,
        keyPoints: [
          'CEO fraud tactics',
          'Invoice manipulation',
          'Account compromise vs spoofing',
          'Wire transfer fraud'
        ],
        content: `BUSINESS EMAIL COMPROMISE (BEC)

FBI: BEC caused $51+ billion in losses globally

BEC ATTACK TYPES:

1. CEO FRAUD - Impersonate executive, request urgent wire transfer
2. INVOICE MANIPULATION - "Our bank details have changed"
3. ACCOUNT COMPROMISE - Actual email account hacked
4. ATTORNEY IMPERSONATION - "Confidential acquisition"
5. DATA THEFT - Request W-2s, employee data

ATTACK INDICATORS:
• Urgency and secrecy
• Unusual payment requests
• Changed banking details
• "Keep this confidential"
• Unusual timing (Friday afternoon)

TECHNICAL INDICATORS:
• Lookalike domains (examp1e.com)
• Reply-to different from From
• Recent domain registration
• Missing SPF/DKIM/DMARC

PREVENTION:
PROCESS: Dual approval for wires, verbal confirmation via known number
TECHNICAL: Email authentication (DMARC), external email warnings`,
        liveLab: {
          id: 'lab-bec',
          title: 'BEC Detection',
          description: 'Identify BEC attack attempts',
          difficulty: 'beginner',
          challenge: 'Email from "ceo@yourcompary.com" (your company is yourcompany.com): "I need you to process a wire transfer for a confidential acquisition. Don\'t tell anyone." What\'s suspicious?',
          hint: 'Look at the domain spelling and the behavior requested...',
          solution: 'Domain typo (compary vs company), secrecy request, urgency, no phone verification',
          validator: (input: string) => {
            const lower = input.toLowerCase();
            return (lower.includes('domain') || lower.includes('spell') || lower.includes('typo')) &&
                   (lower.includes('secret') || lower.includes('urgent') || lower.includes('wire'));
          },
          completed: false,
          points: 40,
          timeEstimate: '10 min',
          skills: ['BEC detection', 'Email security', 'Fraud prevention']
        }
      }
    ]
  },
  // ============ CYBER HYGIENE ============
  {
    id: 'cyber-hygiene',
    title: 'Cyber Hygiene Essentials',
    description: 'Daily security practices every employee must follow',
    icon: Sparkles,
    color: 'text-green-500',
    bgGradient: 'from-green-500/20 to-emerald-500/20',
    completed: false,
    category: 'fundamentals',
    estimatedTime: '1 hour',
    lessons: [
      {
        id: 'hygiene-1',
        title: 'Daily Security Habits',
        completed: false,
        keyPoints: [
          'Device security basics',
          'Software updates importance',
          'Backup practices',
          'Physical security'
        ],
        content: `CYBER HYGIENE ESSENTIALS

DEVICE SECURITY:
✓ Lock screen when away (Win+L or Ctrl+Cmd+Q)
✓ Strong PIN/Password
✓ Full disk encryption (BitLocker/FileVault)
✓ Antivirus active and updated

SOFTWARE UPDATES:
• 60% of breaches involve unpatched vulnerabilities
• Update: OS, browsers, apps, security software
• Enable auto-update when possible!

BACKUP PRACTICES (3-2-1 Rule):
• 3 copies of data
• 2 different media types
• 1 copy offsite

PHYSICAL SECURITY:
✓ Never leave laptop unattended
✓ Use privacy screens in public
✓ Don't plug in unknown USBs
✓ Shred sensitive documents
✓ Challenge unknown visitors

TRAVEL SECURITY:
• Don't use public charging stations (juice jacking)
• Use hotel safe for devices
• Avoid sensitive work on public WiFi
• Use VPN always`,
        liveLab: {
          id: 'lab-hygiene',
          title: 'Security Habit Check',
          description: 'Assess security behaviors',
          difficulty: 'beginner',
          challenge: 'You find a USB drive in the parking lot labeled "Salary Data 2024". What should you do?',
          hint: 'Think about what attackers might put on a USB drive...',
          solution: 'Never plug it in! Turn it in to IT/Security. It could contain malware (USB drop attack)',
          validator: (input: string) => {
            const lower = input.toLowerCase();
            return (lower.includes("don't") || lower.includes('never') || lower.includes('not plug')) &&
                   (lower.includes('it') || lower.includes('security') || lower.includes('malware'));
          },
          completed: false,
          points: 25,
          timeEstimate: '5 min',
          skills: ['Security awareness', 'Physical security', 'USB threats']
        }
      }
    ]
  }
];
