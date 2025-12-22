import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';
import DashboardLayout from '@/components/dashboard/DashboardLayout';
import { Button } from '@/components/ui/button';
import { BookOpen, Lock, Shield, Activity, Code, CheckCircle, ChevronRight, Award } from 'lucide-react';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

interface Module {
  id: string;
  title: string;
  description: string;
  icon: typeof Lock;
  lessons: Lesson[];
  completed: boolean;
}

interface Lesson {
  id: string;
  title: string;
  content: string;
  codeExample?: string;
  completed: boolean;
}

const LearningPage = () => {
  const { user, loading } = useAuth();
  const navigate = useNavigate();
  const [selectedModule, setSelectedModule] = useState<string | null>(null);
  const [selectedLesson, setSelectedLesson] = useState<string | null>(null);
  const [modules, setModules] = useState<Module[]>([
    {
      id: 'crypto',
      title: 'Cryptography Fundamentals',
      description: 'Learn about encryption algorithms used by ransomware',
      icon: Lock,
      completed: false,
      lessons: [
        {
          id: 'crypto-1',
          title: 'Symmetric Encryption (AES)',
          completed: false,
          content: `AES (Advanced Encryption Standard) is a symmetric encryption algorithm widely used by ransomware.

Key Concepts:
• Same key used for encryption and decryption
• Block cipher with 128-bit blocks
• Key sizes: 128, 192, or 256 bits
• Extremely fast and efficient

How Ransomware Uses AES:
1. Generate random AES key
2. Encrypt all target files with this key
3. Encrypt the AES key with RSA public key
4. Delete original files and key from memory`,
          codeExample: `from cryptography.fernet import Fernet

# Generate encryption key
key = Fernet.generate_key()
cipher = Fernet(key)

# Encrypt data
plaintext = b"Sensitive data here"
encrypted = cipher.encrypt(plaintext)

# Decrypt data
decrypted = cipher.decrypt(encrypted)
print(decrypted.decode())  # "Sensitive data here"`
        },
        {
          id: 'crypto-2',
          title: 'Asymmetric Encryption (RSA)',
          completed: false,
          content: `RSA is an asymmetric encryption algorithm using public/private key pairs.

Key Concepts:
• Public key for encryption, private key for decryption
• Much slower than AES
• Used for key exchange and digital signatures

Ransomware Hybrid Approach:
1. Attacker generates RSA key pair (keeps private key)
2. Victim's machine encrypts files with random AES keys
3. Each AES key is encrypted with attacker's RSA public key
4. Only the attacker's private key can decrypt the AES keys`,
          codeExample: `from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Encrypt with public key
message = b"Secret AES key"
encrypted = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)`
        }
      ]
    },
    {
      id: 'detection',
      title: 'Threat Detection',
      description: 'Behavioral analysis and detection techniques',
      icon: Activity,
      completed: false,
      lessons: [
        {
          id: 'detect-1',
          title: 'Behavioral Indicators',
          completed: false,
          content: `Ransomware exhibits specific behavioral patterns that can be detected:

Key Indicators:
• Rapid file access and modification
• High CPU usage during encryption
• Unusual file extension changes
• Shadow copy deletion attempts
• Registry modifications for persistence

Detection Strategies:
1. Monitor file system events
2. Track process behavior
3. Analyze network traffic
4. Check for known signatures`,
          codeExample: `import psutil
import time

def monitor_suspicious_activity():
    THRESHOLD = 20  # File changes per second
    
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
        cpu = proc.info['cpu_percent']
        
        if cpu > 80:
            print(f"[ALERT] High CPU: {proc.info['name']}")
            
        # In real detection, track file operations
        # and terminate if threshold exceeded`
        },
        {
          id: 'detect-2',
          title: 'Machine Learning Detection',
          completed: false,
          content: `ML-based detection can identify ransomware by learning normal vs. malicious patterns:

Features Used:
• File operation frequency
• CPU/Memory patterns
• API call sequences
• Network behavior

ML Approaches:
• Random Forest classifiers
• Neural networks for behavior analysis
• Anomaly detection algorithms`,
          codeExample: `from sklearn.ensemble import RandomForestClassifier
import pandas as pd

# Training data: [file_changes, cpu_usage, label]
data = pd.DataFrame({
    'file_changes': [5, 10, 200, 300],
    'cpu_usage': [10, 20, 90, 95],
    'label': [0, 0, 1, 1]  # 0=normal, 1=ransomware
})

model = RandomForestClassifier()
model.fit(data[['file_changes', 'cpu_usage']], data['label'])

# Real-time prediction
prediction = model.predict([[150, 85]])
if prediction[0] == 1:
    print("RANSOMWARE DETECTED!")`
        }
      ]
    },
    {
      id: 'response',
      title: 'Incident Response',
      description: 'How to respond to ransomware attacks',
      icon: Shield,
      completed: false,
      lessons: [
        {
          id: 'response-1',
          title: 'Incident Response Lifecycle',
          completed: false,
          content: `The NIST Incident Response Lifecycle:

1. PREPARATION
   • Develop response plans
   • Train personnel
   • Maintain backups

2. DETECTION & ANALYSIS
   • Identify the threat
   • Determine scope
   • Collect evidence

3. CONTAINMENT
   • Isolate affected systems
   • Block lateral movement
   • Preserve evidence

4. ERADICATION
   • Remove malware
   • Patch vulnerabilities
   • Verify clean state

5. RECOVERY
   • Restore from backups
   • Verify data integrity
   • Resume operations

6. LESSONS LEARNED
   • Document incident
   • Update procedures
   • Improve defenses`,
        },
        {
          id: 'response-2',
          title: 'Recovery Strategies',
          completed: false,
          content: `Data Recovery Options:

1. BACKUP RESTORATION
   • Best case scenario
   • Requires offline/immutable backups
   • Test restoration regularly

2. SHADOW COPY RECOVERY
   • Windows VSS snapshots
   • Often deleted by ransomware
   • Check immediately after detection

3. DECRYPTION TOOLS
   • Some ransomware has been cracked
   • Check nomoreransom.org
   • Law enforcement resources

4. PAYING RANSOM (Not Recommended)
   • No guarantee of decryption
   • Funds criminal operations
   • May be targeted again`,
          codeExample: `# Windows Shadow Copy Recovery
import subprocess

def list_shadow_copies():
    result = subprocess.run(
        ['vssadmin', 'list', 'shadows'],
        capture_output=True,
        text=True
    )
    print(result.stdout)

def restore_from_shadow(volume, destination):
    # Example shadow copy path
    shadow_path = r'\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1'
    # Use robocopy or similar to restore files`
        }
      ]
    }
  ]);

  useEffect(() => {
    if (!loading && !user) {
      navigate('/auth');
    }
  }, [user, loading, navigate]);

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
    toast.success('Lesson completed!');
  };

  const currentModule = modules.find(m => m.id === selectedModule);
  const currentLesson = currentModule?.lessons.find(l => l.id === selectedLesson);

  if (loading || !user) return null;

  return (
    <DashboardLayout>
      <div className="mb-6">
        <h1 className="font-display text-3xl font-bold text-primary text-glow-cyan tracking-wider flex items-center gap-3">
          <BookOpen className="w-8 h-8" />
          LEARNING LAB
        </h1>
        <p className="text-muted-foreground font-mono mt-2">
          Interactive cybersecurity training modules
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Modules List */}
        <div className="cyber-card p-4 border border-border">
          <div className="relative z-10">
            <h3 className="font-display font-bold text-foreground mb-4">MODULES</h3>
            <div className="space-y-2">
              {modules.map(mod => {
                const Icon = mod.icon;
                const completedCount = mod.lessons.filter(l => l.completed).length;
                return (
                  <button
                    key={mod.id}
                    onClick={() => {
                      setSelectedModule(mod.id);
                      setSelectedLesson(mod.lessons[0]?.id || null);
                    }}
                    className={cn(
                      "w-full text-left p-3 rounded-lg border transition-all",
                      selectedModule === mod.id
                        ? "bg-primary/10 border-primary"
                        : "bg-secondary/30 border-border/50 hover:border-primary/50"
                    )}
                  >
                    <div className="flex items-center gap-3">
                      <Icon className={cn(
                        "w-5 h-5",
                        mod.completed ? "text-success" : "text-primary"
                      )} />
                      <div className="flex-1">
                        <p className="font-mono text-sm font-bold text-foreground">{mod.title}</p>
                        <p className="text-xs text-muted-foreground">
                          {completedCount}/{mod.lessons.length} lessons
                        </p>
                      </div>
                      {mod.completed && <Award className="w-4 h-4 text-success" />}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* Lessons */}
        {currentModule && (
          <div className="cyber-card p-4 border border-border">
            <div className="relative z-10">
              <h3 className="font-display font-bold text-foreground mb-4">LESSONS</h3>
              <div className="space-y-2">
                {currentModule.lessons.map(lesson => (
                  <button
                    key={lesson.id}
                    onClick={() => setSelectedLesson(lesson.id)}
                    className={cn(
                      "w-full text-left p-3 rounded-lg border transition-all flex items-center gap-3",
                      selectedLesson === lesson.id
                        ? "bg-primary/10 border-primary"
                        : "bg-secondary/30 border-border/50 hover:border-primary/50"
                    )}
                  >
                    {lesson.completed ? (
                      <CheckCircle className="w-4 h-4 text-success flex-shrink-0" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-muted-foreground flex-shrink-0" />
                    )}
                    <span className="font-mono text-sm text-foreground">{lesson.title}</span>
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Lesson Content */}
        <div className="lg:col-span-2 cyber-card p-5 border border-border">
          <div className="relative z-10">
            {currentLesson ? (
              <>
                <div className="flex items-center justify-between mb-4">
                  <h2 className="font-display text-xl font-bold text-foreground">{currentLesson.title}</h2>
                  {currentLesson.completed && (
                    <span className="text-xs font-mono text-success flex items-center gap-1">
                      <CheckCircle className="w-4 h-4" /> Completed
                    </span>
                  )}
                </div>

                <div className="prose prose-invert max-w-none">
                  <pre className="whitespace-pre-wrap text-sm font-mono text-muted-foreground bg-secondary/30 p-4 rounded-lg mb-4">
                    {currentLesson.content}
                  </pre>

                  {currentLesson.codeExample && (
                    <div className="mb-4">
                      <h4 className="font-display font-bold text-foreground mb-2 flex items-center gap-2">
                        <Code className="w-4 h-4 text-accent" />
                        CODE EXAMPLE
                      </h4>
                      <pre className="text-xs font-mono text-accent bg-background/50 p-4 rounded-lg border border-accent/30 overflow-x-auto">
                        {currentLesson.codeExample}
                      </pre>
                    </div>
                  )}
                </div>

                {!currentLesson.completed && (
                  <Button
                    variant="success"
                    className="mt-4"
                    onClick={() => markLessonComplete(currentModule!.id, currentLesson.id)}
                  >
                    <CheckCircle className="w-4 h-4 mr-2" />
                    Mark as Complete
                  </Button>
                )}
              </>
            ) : (
              <div className="flex flex-col items-center justify-center h-64 text-center">
                <BookOpen className="w-16 h-16 text-primary/30 mb-4" />
                <h3 className="font-display text-xl text-foreground mb-2">Select a Module</h3>
                <p className="text-muted-foreground font-mono text-sm">
                  Choose a learning module from the sidebar to start
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
