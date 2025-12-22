import { useState, useCallback, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';
import DashboardLayout from '@/components/dashboard/DashboardLayout';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Lock, FileText, AlertTriangle, Play, Square, Trash2, Plus, Shield } from 'lucide-react';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

interface SimFile {
  id: string;
  name: string;
  content: string;
  encrypted: boolean;
  encryptedContent?: string;
}

const generateKey = (): string => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let key = '';
  for (let i = 0; i < 32; i++) {
    key += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return key;
};

const simpleEncrypt = (text: string, key: string): string => {
  let result = '';
  for (let i = 0; i < text.length; i++) {
    const charCode = text.charCodeAt(i) ^ key.charCodeAt(i % key.length);
    result += String.fromCharCode(charCode);
  }
  return btoa(result);
};

const EncryptPage = () => {
  const { user, loading } = useAuth();
  const navigate = useNavigate();
  const [files, setFiles] = useState<SimFile[]>([
    { id: '1', name: 'document.txt', content: 'Important business data - Q4 financial report summary', encrypted: false },
    { id: '2', name: 'passwords.txt', content: 'admin:supersecret123, user:password456', encrypted: false },
    { id: '3', name: 'project_plan.md', content: '# Project Alpha\n- Phase 1: Research\n- Phase 2: Development', encrypted: false },
  ]);
  const [encryptionKey, setEncryptionKey] = useState<string>('');
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [currentFileIndex, setCurrentFileIndex] = useState(-1);
  const [logs, setLogs] = useState<string[]>([]);
  const [newFileName, setNewFileName] = useState('');
  const [newFileContent, setNewFileContent] = useState('');

  useEffect(() => {
    if (!loading && !user) {
      navigate('/auth');
    }
  }, [user, loading, navigate]);

  const addLog = useCallback((message: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, `[${timestamp}] ${message}`]);
  }, []);

  const runEncryption = async () => {
    const unencryptedFiles = files.filter(f => !f.encrypted);
    if (unencryptedFiles.length === 0) {
      toast.error('No files to encrypt');
      return;
    }

    setIsEncrypting(true);
    const key = generateKey();
    setEncryptionKey(key);
    addLog('🔑 Encryption key generated: ' + key.substring(0, 8) + '...');
    addLog('⚠️ RANSOMWARE SIMULATION STARTED');

    for (let i = 0; i < files.length; i++) {
      if (files[i].encrypted) continue;
      
      setCurrentFileIndex(i);
      addLog(`🔒 Encrypting: ${files[i].name}`);
      
      await new Promise(resolve => setTimeout(resolve, 800));
      
      const encryptedContent = simpleEncrypt(files[i].content, key);
      
      setFiles(prev => prev.map((f, idx) => 
        idx === i ? { ...f, encrypted: true, encryptedContent } : f
      ));
      
      addLog(`✅ Encrypted: ${files[i].name}`);
    }

    setCurrentFileIndex(-1);
    setIsEncrypting(false);
    addLog('💀 ALL FILES ENCRYPTED - Ransom note dropped');
    toast.error('Ransomware simulation complete! All files encrypted.');
  };

  const resetSimulation = () => {
    setFiles(files.map(f => ({ ...f, encrypted: false, encryptedContent: undefined })));
    setEncryptionKey('');
    setLogs([]);
    setCurrentFileIndex(-1);
    toast.success('Simulation reset');
  };

  const addFile = () => {
    if (!newFileName || !newFileContent) {
      toast.error('Please enter file name and content');
      return;
    }
    setFiles(prev => [...prev, {
      id: Date.now().toString(),
      name: newFileName,
      content: newFileContent,
      encrypted: false
    }]);
    setNewFileName('');
    setNewFileContent('');
    toast.success('File added to simulation');
  };

  const removeFile = (id: string) => {
    setFiles(prev => prev.filter(f => f.id !== id));
  };

  if (loading || !user) return null;

  return (
    <DashboardLayout>
      <div className="mb-6">
        <h1 className="font-display text-3xl font-bold text-destructive text-glow-red tracking-wider flex items-center gap-3">
          <Lock className="w-8 h-8" />
          ENCRYPTION SIMULATION
        </h1>
        <p className="text-muted-foreground font-mono mt-2">
          Simulate ransomware file encryption in a safe environment
        </p>
      </div>

      {/* Warning Banner */}
      <div className="mb-6 p-4 rounded-lg bg-destructive/10 border border-destructive/30">
        <div className="flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-destructive flex-shrink-0" />
          <p className="text-sm font-mono text-destructive">
            <strong>SIMULATION MODE:</strong> This demonstrates ransomware behavior for educational purposes only.
            Files are encrypted in-memory and can be recovered within this session.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* File System Panel */}
        <div className="cyber-card p-5 border border-border">
          <div className="relative z-10">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-display text-lg font-bold text-foreground tracking-wider">
                VICTIM FILES
              </h3>
              <span className="text-xs font-mono text-muted-foreground">
                {files.filter(f => f.encrypted).length}/{files.length} encrypted
              </span>
            </div>

            <div className="space-y-3 mb-4 max-h-64 overflow-y-auto">
              {files.map((file, index) => (
                <div
                  key={file.id}
                  className={cn(
                    "flex items-center gap-3 p-3 rounded-lg border transition-all duration-300",
                    file.encrypted 
                      ? "bg-destructive/10 border-destructive/30" 
                      : "bg-secondary/30 border-border/50",
                    currentFileIndex === index && "animate-pulse border-warning"
                  )}
                >
                  <FileText className={cn(
                    "w-5 h-5 flex-shrink-0",
                    file.encrypted ? "text-destructive" : "text-primary"
                  )} />
                  <div className="flex-1 min-w-0">
                    <p className="font-mono text-sm text-foreground truncate">
                      {file.name}{file.encrypted && '.encrypted'}
                    </p>
                    <p className="text-xs text-muted-foreground font-mono truncate">
                      {file.encrypted ? file.encryptedContent?.substring(0, 30) + '...' : file.content.substring(0, 40)}
                    </p>
                  </div>
                  {file.encrypted ? (
                    <Lock className="w-4 h-4 text-destructive" />
                  ) : (
                    <button onClick={() => removeFile(file.id)} className="text-muted-foreground hover:text-destructive">
                      <Trash2 className="w-4 h-4" />
                    </button>
                  )}
                </div>
              ))}
            </div>

            {/* Add File */}
            <div className="space-y-2 p-3 bg-secondary/20 rounded-lg">
              <Input
                placeholder="filename.txt"
                value={newFileName}
                onChange={(e) => setNewFileName(e.target.value)}
                className="font-mono text-sm"
              />
              <Input
                placeholder="File content..."
                value={newFileContent}
                onChange={(e) => setNewFileContent(e.target.value)}
                className="font-mono text-sm"
              />
              <Button variant="outline" size="sm" onClick={addFile} className="w-full">
                <Plus className="w-4 h-4 mr-2" /> Add File
              </Button>
            </div>
          </div>
        </div>

        {/* Control Panel */}
        <div className="space-y-6">
          {/* Encryption Controls */}
          <div className="cyber-card p-5 border border-border">
            <div className="relative z-10">
              <h3 className="font-display text-lg font-bold text-foreground tracking-wider mb-4">
                ENCRYPTION CONTROLS
              </h3>

              <div className="space-y-4">
                <Button
                  variant="danger"
                  size="lg"
                  className="w-full"
                  onClick={runEncryption}
                  disabled={isEncrypting || files.every(f => f.encrypted)}
                >
                  {isEncrypting ? (
                    <>
                      <div className="w-4 h-4 border-2 border-destructive-foreground/30 border-t-destructive-foreground rounded-full animate-spin" />
                      ENCRYPTING...
                    </>
                  ) : (
                    <>
                      <Play className="w-5 h-5" />
                      RUN RANSOMWARE SIM
                    </>
                  )}
                </Button>

                <Button
                  variant="outline"
                  size="lg"
                  className="w-full"
                  onClick={resetSimulation}
                >
                  <Square className="w-5 h-5" />
                  RESET SIMULATION
                </Button>
              </div>

              {encryptionKey && (
                <div className="mt-4 p-3 bg-warning/10 border border-warning/30 rounded-lg">
                  <p className="text-xs font-mono text-warning mb-1">ENCRYPTION KEY (SAVE THIS!):</p>
                  <code className="text-xs font-mono text-foreground break-all">{encryptionKey}</code>
                </div>
              )}
            </div>
          </div>

          {/* Activity Log */}
          <div className="cyber-card p-5 border border-border">
            <div className="relative z-10">
              <h3 className="font-display text-lg font-bold text-foreground tracking-wider mb-4">
                ACTIVITY LOG
              </h3>
              <div className="bg-background/50 rounded-lg p-3 h-48 overflow-y-auto font-mono text-xs">
                {logs.length === 0 ? (
                  <p className="text-muted-foreground">Waiting for simulation to start...</p>
                ) : (
                  logs.map((log, i) => (
                    <p key={i} className="text-accent mb-1">{log}</p>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Ransom Note */}
      {files.every(f => f.encrypted) && files.length > 0 && (
        <div className="mt-6 cyber-card p-6 border-2 border-destructive animate-pulse">
          <div className="relative z-10 text-center">
            <h2 className="font-display text-2xl font-bold text-destructive mb-4">
              💀 YOUR FILES HAVE BEEN ENCRYPTED 💀
            </h2>
            <p className="font-mono text-foreground mb-4">
              All your important files have been encrypted with military-grade encryption.
            </p>
            <p className="font-mono text-muted-foreground text-sm mb-4">
              To recover your files, go to the <strong>Decrypt & Recover</strong> section and use the encryption key.
            </p>
            <Button variant="success" onClick={() => navigate('/decrypt')}>
              <Shield className="w-4 h-4 mr-2" />
              GO TO RECOVERY
            </Button>
          </div>
        </div>
      )}
    </DashboardLayout>
  );
};

export default EncryptPage;
