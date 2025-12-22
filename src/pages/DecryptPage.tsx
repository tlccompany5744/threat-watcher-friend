import { useState, useCallback, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';
import DashboardLayout from '@/components/dashboard/DashboardLayout';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Unlock, FileText, CheckCircle, Key, RefreshCw, Shield, AlertTriangle } from 'lucide-react';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

interface SimFile {
  id: string;
  name: string;
  content: string;
  encrypted: boolean;
  encryptedContent?: string;
}

const simpleDecrypt = (encryptedText: string, key: string): string => {
  try {
    const decoded = atob(encryptedText);
    let result = '';
    for (let i = 0; i < decoded.length; i++) {
      const charCode = decoded.charCodeAt(i) ^ key.charCodeAt(i % key.length);
      result += String.fromCharCode(charCode);
    }
    return result;
  } catch {
    return 'DECRYPTION FAILED';
  }
};

const DecryptPage = () => {
  const { user, loading } = useAuth();
  const navigate = useNavigate();
  const [decryptionKey, setDecryptionKey] = useState('');
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [currentFileIndex, setCurrentFileIndex] = useState(-1);
  const [logs, setLogs] = useState<string[]>([]);
  const [files, setFiles] = useState<SimFile[]>([]);
  const [recoveredFiles, setRecoveredFiles] = useState<SimFile[]>([]);

  useEffect(() => {
    if (!loading && !user) {
      navigate('/auth');
    }
  }, [user, loading, navigate]);

  // Simulated encrypted files
  useEffect(() => {
    const storedFiles: SimFile[] = [
      { id: '1', name: 'document.txt', content: '', encrypted: true, encryptedContent: 'VGhpcyBpcyBlbmNyeXB0ZWQgZGF0YQ==' },
      { id: '2', name: 'passwords.txt', content: '', encrypted: true, encryptedContent: 'U2VjcmV0IHBhc3N3b3JkcyBoZXJl' },
      { id: '3', name: 'project_plan.md', content: '', encrypted: true, encryptedContent: 'UHJvamVjdCBwbGFuIGNvbnRlbnQ=' },
    ];
    setFiles(storedFiles);
  }, []);

  const addLog = useCallback((message: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, `[${timestamp}] ${message}`]);
  }, []);

  const runDecryption = async () => {
    if (!decryptionKey) {
      toast.error('Please enter the decryption key');
      return;
    }

    if (files.length === 0) {
      toast.error('No encrypted files to recover');
      return;
    }

    setIsDecrypting(true);
    setRecoveredFiles([]);
    addLog('🔑 Decryption key received');
    addLog('🛡️ RECOVERY PROCESS STARTED');

    for (let i = 0; i < files.length; i++) {
      setCurrentFileIndex(i);
      addLog(`🔓 Decrypting: ${files[i].name}`);
      
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      const decryptedContent = simpleDecrypt(files[i].encryptedContent || '', decryptionKey);
      
      setRecoveredFiles(prev => [...prev, {
        ...files[i],
        content: decryptedContent,
        encrypted: false
      }]);
      
      addLog(`✅ Recovered: ${files[i].name}`);
    }

    setCurrentFileIndex(-1);
    setIsDecrypting(false);
    addLog('🎉 ALL FILES RECOVERED SUCCESSFULLY');
    toast.success('All files have been recovered!');
  };

  const resetRecovery = () => {
    setRecoveredFiles([]);
    setDecryptionKey('');
    setLogs([]);
    setCurrentFileIndex(-1);
    toast.success('Recovery reset');
  };

  if (loading || !user) return null;

  return (
    <DashboardLayout>
      <div className="mb-6">
        <h1 className="font-display text-3xl font-bold text-success text-glow-green tracking-wider flex items-center gap-3">
          <Unlock className="w-8 h-8" />
          DECRYPT & RECOVER
        </h1>
        <p className="text-muted-foreground font-mono mt-2">
          Recover encrypted files using the decryption key
        </p>
      </div>

      {/* Info Banner */}
      <div className="mb-6 p-4 rounded-lg bg-primary/10 border border-primary/30">
        <div className="flex items-center gap-3">
          <Shield className="w-5 h-5 text-primary flex-shrink-0" />
          <p className="text-sm font-mono text-primary">
            <strong>RECOVERY MODE:</strong> Enter the encryption key from the ransomware simulation to recover your files.
            In real scenarios, this key would need to be obtained from backups or security tools.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Encrypted Files Panel */}
        <div className="cyber-card p-5 border border-border">
          <div className="relative z-10">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-display text-lg font-bold text-foreground tracking-wider">
                ENCRYPTED FILES
              </h3>
              <span className="text-xs font-mono text-destructive">
                {files.length} files locked
              </span>
            </div>

            <div className="space-y-3 max-h-64 overflow-y-auto">
              {files.map((file, index) => (
                <div
                  key={file.id}
                  className={cn(
                    "flex items-center gap-3 p-3 rounded-lg border transition-all duration-300",
                    "bg-destructive/10 border-destructive/30",
                    currentFileIndex === index && "animate-pulse border-success"
                  )}
                >
                  <FileText className="w-5 h-5 text-destructive flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <p className="font-mono text-sm text-foreground truncate">
                      {file.name}.encrypted
                    </p>
                    <p className="text-xs text-muted-foreground font-mono truncate">
                      {file.encryptedContent?.substring(0, 30)}...
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Recovered Files Panel */}
        <div className="cyber-card p-5 border border-border">
          <div className="relative z-10">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-display text-lg font-bold text-foreground tracking-wider">
                RECOVERED FILES
              </h3>
              <span className="text-xs font-mono text-success">
                {recoveredFiles.length} files recovered
              </span>
            </div>

            <div className="space-y-3 max-h-64 overflow-y-auto">
              {recoveredFiles.length === 0 ? (
                <p className="text-muted-foreground font-mono text-sm p-4 text-center">
                  No files recovered yet. Enter the key and run recovery.
                </p>
              ) : (
                recoveredFiles.map((file) => (
                  <div
                    key={file.id}
                    className="flex items-center gap-3 p-3 rounded-lg border bg-success/10 border-success/30 animate-fade-in"
                  >
                    <CheckCircle className="w-5 h-5 text-success flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                      <p className="font-mono text-sm text-foreground truncate">{file.name}</p>
                      <p className="text-xs text-muted-foreground font-mono truncate">
                        {file.content.substring(0, 40)}...
                      </p>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Recovery Controls */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-6">
        <div className="cyber-card p-5 border border-border">
          <div className="relative z-10">
            <h3 className="font-display text-lg font-bold text-foreground tracking-wider mb-4">
              RECOVERY CONTROLS
            </h3>

            <div className="space-y-4">
              <div className="space-y-2">
                <label className="text-sm font-mono text-muted-foreground flex items-center gap-2">
                  <Key className="w-4 h-4 text-primary" />
                  DECRYPTION KEY
                </label>
                <Input
                  placeholder="Enter the encryption key..."
                  value={decryptionKey}
                  onChange={(e) => setDecryptionKey(e.target.value)}
                  className="font-mono"
                />
              </div>

              <Button
                variant="success"
                size="lg"
                className="w-full"
                onClick={runDecryption}
                disabled={isDecrypting || recoveredFiles.length === files.length}
              >
                {isDecrypting ? (
                  <>
                    <div className="w-4 h-4 border-2 border-success-foreground/30 border-t-success-foreground rounded-full animate-spin" />
                    DECRYPTING...
                  </>
                ) : (
                  <>
                    <Unlock className="w-5 h-5" />
                    RUN RECOVERY
                  </>
                )}
              </Button>

              <Button
                variant="outline"
                size="lg"
                className="w-full"
                onClick={resetRecovery}
              >
                <RefreshCw className="w-5 h-5" />
                RESET RECOVERY
              </Button>
            </div>
          </div>
        </div>

        {/* Activity Log */}
        <div className="cyber-card p-5 border border-border">
          <div className="relative z-10">
            <h3 className="font-display text-lg font-bold text-foreground tracking-wider mb-4">
              RECOVERY LOG
            </h3>
            <div className="bg-background/50 rounded-lg p-3 h-48 overflow-y-auto font-mono text-xs">
              {logs.length === 0 ? (
                <p className="text-muted-foreground">Waiting for recovery to start...</p>
              ) : (
                logs.map((log, i) => (
                  <p key={i} className="text-accent mb-1">{log}</p>
                ))
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Success Message */}
      {recoveredFiles.length === files.length && files.length > 0 && (
        <div className="mt-6 cyber-card p-6 border-2 border-success">
          <div className="relative z-10 text-center">
            <CheckCircle className="w-16 h-16 text-success mx-auto mb-4" />
            <h2 className="font-display text-2xl font-bold text-success mb-2">
              ALL FILES RECOVERED
            </h2>
            <p className="font-mono text-muted-foreground">
              Incident response successful. All encrypted files have been restored.
            </p>
          </div>
        </div>
      )}
    </DashboardLayout>
  );
};

export default DecryptPage;
