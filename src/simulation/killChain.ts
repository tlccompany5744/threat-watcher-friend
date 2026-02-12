export type KillStage =
  | 'RECON'
  | 'INITIAL_ACCESS'
  | 'RAPID_ACCESS'
  | 'ENTROPY_SPIKE'
  | 'EXTENSION_MUTATION'
  | 'DEFENSE_TRIGGER'
  | 'CONTAINMENT'
  | 'RECOVERY';

export interface KillChainStep {
  stage: KillStage;
  label: string;
  description: string;
  evidence: string[];
  duration: number; // ms to simulate
  iocType?: 'file' | 'process' | 'network' | 'registry';
}

export const killChainSteps: KillChainStep[] = [
  {
    stage: 'RECON',
    label: 'Reconnaissance',
    description: 'Attacker scans the filesystem to identify valuable targets: documents, databases, backups.',
    evidence: [
      'dir /s /b *.docx *.xlsx *.pdf *.bak',
      'Enumerating 1,247 files across 38 directories',
      'Identified backup folder: D:\\Backups\\',
      'Shadow copies detected: 3 restore points',
    ],
    duration: 3000,
    iocType: 'process',
  },
  {
    stage: 'INITIAL_ACCESS',
    label: 'Initial File Touch',
    description: 'First file modification attempt — testing write access and encryption on a single target.',
    evidence: [
      'Opening file handle: invoice_2024.docx',
      'Write test: 512 bytes XOR cipher applied',
      'File entropy changed: 4.2 → 7.8',
      'Original file size: 245KB → Modified: 245KB',
    ],
    duration: 2500,
    iocType: 'file',
  },
  {
    stage: 'RAPID_ACCESS',
    label: 'Rapid Access Pattern',
    description: 'Mass file operations begin — hundreds of files opened per second, far beyond normal user behavior.',
    evidence: [
      'File open rate: 340 files/second (normal: ~5/s)',
      'Sequential directory traversal detected',
      'Read-modify-write pattern on batch files',
      'I/O queue depth: 98% saturation',
    ],
    duration: 3000,
    iocType: 'process',
  },
  {
    stage: 'ENTROPY_SPIKE',
    label: 'Entropy Spike',
    description: 'File content entropy rises sharply — data is being replaced with encrypted (random) content.',
    evidence: [
      'Average file entropy: 4.1 → 7.92 (max 8.0)',
      '87% of modified files show entropy > 7.5',
      'Shannon entropy analysis: encryption confirmed',
      'Compression ratio test: files no longer compressible',
    ],
    duration: 3500,
    iocType: 'file',
  },
  {
    stage: 'EXTENSION_MUTATION',
    label: 'Extension Mutation',
    description: 'Files are renamed with ransomware-specific extensions, making them unrecognizable to the OS.',
    evidence: [
      'report.docx → report.docx.locked',
      'database.sql → database.sql.encrypted',
      '412 files renamed in 1.2 seconds',
      'Ransom note dropped: README_DECRYPT.txt',
    ],
    duration: 2500,
    iocType: 'file',
  },
  {
    stage: 'DEFENSE_TRIGGER',
    label: 'Defense Trigger',
    description: 'Behavioral detection engine fires — anomaly thresholds exceeded on multiple heuristics.',
    evidence: [
      'ALERT: Entropy heuristic threshold breached',
      'ALERT: File rename velocity exceeded 100/s',
      'ALERT: Suspicious process tree detected',
      'Threat score: 94/100 — CRITICAL',
    ],
    duration: 2000,
    iocType: 'process',
  },
  {
    stage: 'CONTAINMENT',
    label: 'Containment',
    description: 'Operator decision applied — threat isolated based on chosen response strategy.',
    evidence: [
      'Awaiting operator decision...',
      'Response strategy selected',
      'Executing containment protocol',
      'Lateral movement blocked',
    ],
    duration: 2000,
    iocType: 'network',
  },
  {
    stage: 'RECOVERY',
    label: 'Recovery',
    description: 'System restoration initiated — clean backups verified and files restored.',
    evidence: [
      'Backup integrity check: PASSED',
      'Initiating file restoration...',
      'Restored files verified against checksums',
      'System returned to operational state',
    ],
    duration: 3000,
    iocType: 'file',
  },
];
