export interface BehaviorMetrics {
  fileAccessRate: number;       // files/second
  entropyGrowth: number;        // 0-1 normalized
  renameSpeed: number;          // renames/second
  directoryTraversal: number;   // directories touched
  cpuSpike: number;             // percentage
  networkEgress: number;        // KB/s outbound
  registryModifications: number;
  shadowCopyDeletion: boolean;
}

export interface BehaviorAnalysis {
  threatScore: number;          // 0-100
  verdict: 'NORMAL' | 'SUSPICIOUS' | 'HIGH_RISK' | 'RANSOMWARE_CONFIRMED';
  confidence: number;           // 0-100
  reasons: string[];
  recommendations: string[];
}

// Weighted behavioral scoring — no signatures, pure heuristics
export function analyzeBehavior(metrics: BehaviorMetrics): BehaviorAnalysis {
  let score = 0;
  const reasons: string[] = [];
  const recommendations: string[] = [];

  // File access frequency (weight: 25)
  if (metrics.fileAccessRate > 100) {
    score += 25;
    reasons.push(`Extreme file access rate: ${metrics.fileAccessRate}/s (normal: <10/s)`);
  } else if (metrics.fileAccessRate > 30) {
    score += 15;
    reasons.push(`Elevated file access rate: ${metrics.fileAccessRate}/s`);
  }

  // Entropy growth (weight: 25)
  if (metrics.entropyGrowth > 0.7) {
    score += 25;
    reasons.push(`Critical entropy increase: ${(metrics.entropyGrowth * 100).toFixed(0)}% — encryption likely`);
  } else if (metrics.entropyGrowth > 0.4) {
    score += 12;
    reasons.push(`Moderate entropy growth: ${(metrics.entropyGrowth * 100).toFixed(0)}%`);
  }

  // Rename speed (weight: 20)
  if (metrics.renameSpeed > 50) {
    score += 20;
    reasons.push(`Mass file renaming: ${metrics.renameSpeed} renames/s`);
  } else if (metrics.renameSpeed > 10) {
    score += 10;
    reasons.push(`Elevated rename activity: ${metrics.renameSpeed}/s`);
  }

  // Directory traversal (weight: 10)
  if (metrics.directoryTraversal > 20) {
    score += 10;
    reasons.push(`Wide directory traversal: ${metrics.directoryTraversal} directories`);
  } else if (metrics.directoryTraversal > 8) {
    score += 5;
    reasons.push(`Moderate directory traversal: ${metrics.directoryTraversal} dirs`);
  }

  // Shadow copy deletion (weight: 15)
  if (metrics.shadowCopyDeletion) {
    score += 15;
    reasons.push('Shadow copy deletion detected — backup destruction attempt');
  }

  // Network egress (weight: 5)
  if (metrics.networkEgress > 500) {
    score += 5;
    reasons.push(`High outbound traffic: ${metrics.networkEgress} KB/s — possible data exfiltration`);
    recommendations.push('Block outbound connections immediately');
  }

  // Determine verdict
  let verdict: BehaviorAnalysis['verdict'] = 'NORMAL';
  if (score >= 80) verdict = 'RANSOMWARE_CONFIRMED';
  else if (score >= 55) verdict = 'HIGH_RISK';
  else if (score >= 30) verdict = 'SUSPICIOUS';

  // Generate recommendations based on score
  if (score >= 80) {
    recommendations.push('IMMEDIATE: Isolate filesystem and kill process');
    recommendations.push('Preserve memory dump for forensics');
    recommendations.push('Activate incident response playbook');
  } else if (score >= 55) {
    recommendations.push('Strongly consider filesystem isolation');
    recommendations.push('Begin evidence collection');
    recommendations.push('Alert SOC team lead');
  } else if (score >= 30) {
    recommendations.push('Increase monitoring granularity');
    recommendations.push('Prepare containment procedures');
  }

  const confidence = Math.min(score + 10, 99);

  return { threatScore: Math.min(score, 100), verdict, confidence, reasons, recommendations };
}

// Generate simulated metrics that evolve over time (for the kill-chain phases)
export function generateMetricsForStage(stageIndex: number): BehaviorMetrics {
  const progression = stageIndex / 7; // 0 to 1
  return {
    fileAccessRate: Math.round(5 + progression * 350 + Math.random() * 20),
    entropyGrowth: Math.min(progression * 1.1 + Math.random() * 0.1, 1),
    renameSpeed: Math.round(progression > 0.5 ? progression * 120 + Math.random() * 30 : Math.random() * 5),
    directoryTraversal: Math.round(progression * 35 + Math.random() * 5),
    cpuSpike: Math.round(20 + progression * 70 + Math.random() * 10),
    networkEgress: Math.round(progression > 0.3 ? progression * 800 : Math.random() * 50),
    registryModifications: Math.round(progression * 8),
    shadowCopyDeletion: progression > 0.6,
  };
}
