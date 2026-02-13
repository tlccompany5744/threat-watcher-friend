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

// Real system data that can be fed into the simulation
export interface RealSystemData {
  cpuCores: number;
  memoryUsageRatio: number;      // 0-1 (usedHeap / heapLimit)
  networkLatency: number;        // ms (RTT)
  networkDownlink: number;       // Mbps
  isOnline: boolean;
  resourceCount: number;         // loaded resources
  transferSizeKB: number;        // total transfer size in KB
  batteryLevel: number | null;   // 0-100 or null
  batteryCharging: boolean;
  pageLoadTime: number;          // ms
  screenPixels: number;          // width * height
  uptime: number;                // seconds since page load
}

// Generate metrics that blend REAL system telemetry with simulation progression
export function generateMetricsForStage(stageIndex: number, realData?: RealSystemData): BehaviorMetrics {
  const progression = stageIndex / 7; // 0 to 1

  if (!realData) {
    // Fallback to pure simulation if no real data available
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

  // === REAL-TIME SYSTEM-AWARE METRICS ===

  // File access rate: based on real resource count + progression acceleration
  const baseFileRate = realData.resourceCount * 0.5;
  const fileAccessRate = Math.round(baseFileRate + progression * 300 + Math.random() * 15);

  // Entropy growth: incorporates real memory pressure as an amplifier
  const memoryPressure = realData.memoryUsageRatio > 0 ? realData.memoryUsageRatio : 0.3;
  const entropyGrowth = Math.min(progression * (0.9 + memoryPressure * 0.3) + Math.random() * 0.08, 1);

  // Rename speed: scales with CPU cores (more cores = faster parallel renames)
  const coreMultiplier = Math.max(realData.cpuCores / 4, 1);
  const renameSpeed = Math.round(
    progression > 0.5
      ? progression * 80 * coreMultiplier + Math.random() * 25
      : Math.random() * 3 * coreMultiplier
  );

  // Directory traversal: modulated by real uptime (longer session = deeper traversal)
  const uptimeFactor = Math.min(realData.uptime / 120, 1.5); // caps at 1.5x after 2min
  const directoryTraversal = Math.round(progression * 30 * uptimeFactor + Math.random() * 5);

  // CPU spike: base from real core count, progression drives it up
  const cpuSpike = Math.round(
    (100 / realData.cpuCores) * 2 + progression * 65 + Math.random() * 10
  );

  // Network egress: uses real downlink as bandwidth ceiling
  const maxEgress = realData.networkDownlink * 125; // Mbps to KB/s approx
  const networkEgress = Math.round(
    progression > 0.3
      ? Math.min(progression * maxEgress, maxEgress) + (realData.isOnline ? 0 : -200)
      : Math.random() * 40
  );

  // Registry modifications: amplified if battery is low (stress indicator)
  const stressFactor = realData.batteryLevel !== null && realData.batteryLevel < 30 ? 1.5 : 1;
  const registryModifications = Math.round(progression * 8 * stressFactor);

  // Shadow copy deletion: triggers earlier if high latency (slower response)
  const latencyFactor = realData.networkLatency > 300 ? 0.5 : 0.6;
  const shadowCopyDeletion = progression > latencyFactor;

  return {
    fileAccessRate,
    entropyGrowth,
    renameSpeed,
    directoryTraversal,
    cpuSpike,
    networkEgress,
    registryModifications,
    shadowCopyDeletion,
  };
}
