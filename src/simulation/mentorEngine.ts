import type { KillStage } from './killChain';

export type MentorMode = 'student' | 'soc';

interface MentorInsight {
  message: string;
  tip?: string;
  realWorldNote?: string;
}

const studentInsights: Record<KillStage, MentorInsight> = {
  RECON: {
    message: 'The attacker is scanning your filesystem. Ransomware first maps targets — documents, databases, backups — before encrypting anything.',
    tip: 'In real attacks, this phase is often silent. Canary files (honeypots) placed in sensitive directories can detect this early.',
    realWorldNote: 'WannaCry spent ~30 seconds in recon before encryption began.',
  },
  INITIAL_ACCESS: {
    message: 'A single file has been modified as a test. The ransomware is verifying it can write encrypted data before launching the full attack.',
    tip: 'Monitoring file integrity (FIM) on critical directories catches this immediately.',
    realWorldNote: 'LockBit 3.0 tests encryption on one file before mass deployment.',
  },
  RAPID_ACCESS: {
    message: '⚡ File access rate has spiked dramatically. Normal users open ~5 files/second. This process is hitting 300+. This is a massive red flag.',
    tip: 'Setting file-access-rate thresholds in your EDR can auto-trigger alerts at this stage.',
    realWorldNote: 'Conti ransomware achieved 500 file ops/second during peak encryption.',
  },
  ENTROPY_SPIKE: {
    message: '🔥 File entropy is approaching maximum (8.0). Normal documents have entropy ~4.0. Entropy near 8.0 means the data is now random — it has been encrypted.',
    tip: 'Shannon entropy analysis is one of the most reliable behavioral detection methods.',
    realWorldNote: 'If this were a real attack, every second of delay means ~50 more files encrypted.',
  },
  EXTENSION_MUTATION: {
    message: '📛 Files are being renamed with malicious extensions (.locked, .encrypted). This is the most visible sign of ransomware, but by now, significant damage is done.',
    tip: 'Signature-based detection catches this phase, but behavioral detection should have triggered earlier.',
    realWorldNote: 'REvil used unique per-victim extensions to complicate decryption tool sharing.',
  },
  DEFENSE_TRIGGER: {
    message: '🚨 Your behavioral detection engine has identified this as ransomware with high confidence. This is where YOUR decision matters.',
    tip: 'In real SOC environments, the average decision time is 45 seconds. Faster response = less data loss.',
    realWorldNote: 'Immediate isolation reduces impact by ~72% compared to delayed response.',
  },
  CONTAINMENT: {
    message: '🛡️ Containment is in progress. The effectiveness depends entirely on the response strategy you chose.',
    tip: 'Killing the process stops encryption but may corrupt partially-encrypted files. Isolation preserves forensic evidence.',
    realWorldNote: 'The FBI recommends isolation over process killing to preserve evidence for prosecution.',
  },
  RECOVERY: {
    message: '✅ Recovery is underway. Files are being restored from verified clean backups.',
    tip: 'The 3-2-1 backup rule (3 copies, 2 media, 1 offsite) is your best defense against ransomware.',
    realWorldNote: 'Companies with tested backup procedures recover 95% faster than those without.',
  },
};

export function getMentorInsight(stage: KillStage, mode: MentorMode): MentorInsight | null {
  if (mode === 'soc') return null; // SOC mode: silent, operator figures it out
  return studentInsights[stage] || null;
}

export function getDecisionMentorAdvice(decision: string, threatScore: number): string {
  if (decision === 'ISOLATE') {
    return threatScore > 70
      ? '✅ Excellent call. Isolation at this threat level is the textbook response. You preserved forensic evidence while stopping lateral movement.'
      : '⚠️ Isolation is aggressive for this threat level. You may be over-reacting, but better safe than sorry.';
  }
  if (decision === 'KILL') {
    return threatScore > 70
      ? '⚡ Process kill stops encryption immediately but may corrupt partially-encrypted files and destroys forensic memory state.'
      : '⚠️ Killing the process at moderate threat levels may cause false positives. Consider monitoring first.';
  }
  if (decision === 'MONITOR') {
    return threatScore > 70
      ? '❌ DANGEROUS: Continuing to monitor at this threat level allows the attack to progress. Every second = more data loss.'
      : '🔍 Reasonable choice at this threat level. Keep watching for escalation.';
  }
  return '';
}
