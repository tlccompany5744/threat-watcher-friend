export interface ScoreMetrics {
  detectionTime: number;        // seconds from attack start to detection
  decisionTime: number;         // seconds to make containment decision
  decision: string;             // ISOLATE | KILL | MONITOR
  threatScoreAtDecision: number;
  filesEncryptedBeforeAction: number;
  totalFiles: number;
  correctDecisionMade: boolean;
  recoverySuccess: number;      // percentage
}

export interface ScoreResult {
  totalScore: number;
  maxScore: number;
  grade: string;
  analystLevel: string;
  breakdown: ScoreBreakdownItem[];
  feedback: string[];
}

export interface ScoreBreakdownItem {
  metric: string;
  score: number;
  maxScore: number;
  impact: 'positive' | 'negative' | 'neutral';
  detail: string;
}

export function calculateScore(metrics: ScoreMetrics): ScoreResult {
  const breakdown: ScoreBreakdownItem[] = [];
  const feedback: string[] = [];
  let totalScore = 0;
  const maxScore = 100;

  // 1. Detection Time (max 25 points)
  const detectionMax = 25;
  let detectionScore: number;
  if (metrics.detectionTime < 10) {
    detectionScore = 25;
    feedback.push('Lightning-fast detection — top-tier analyst reflexes.');
  } else if (metrics.detectionTime < 20) {
    detectionScore = 20;
    feedback.push('Good detection speed. Practice can improve this further.');
  } else if (metrics.detectionTime < 40) {
    detectionScore = 12;
    feedback.push('Detection was slow. In a real attack, significant damage occurs in this window.');
  } else {
    detectionScore = 5;
    feedback.push('⚠️ Very slow detection. Consider setting up automated alert thresholds.');
  }
  breakdown.push({
    metric: 'Detection Time',
    score: detectionScore,
    maxScore: detectionMax,
    impact: detectionScore > 15 ? 'positive' : 'negative',
    detail: `${metrics.detectionTime}s to detect the threat`,
  });
  totalScore += detectionScore;

  // 2. Decision Time (max 20 points)
  const decisionMax = 20;
  let decisionScore: number;
  if (metrics.decisionTime < 5) {
    decisionScore = 20;
  } else if (metrics.decisionTime < 15) {
    decisionScore = 15;
  } else if (metrics.decisionTime < 30) {
    decisionScore = 8;
  } else {
    decisionScore = 3;
    feedback.push('⚠️ Decision delay caused additional file loss.');
  }
  breakdown.push({
    metric: 'Decision Speed',
    score: decisionScore,
    maxScore: decisionMax,
    impact: decisionScore > 10 ? 'positive' : 'negative',
    detail: `${metrics.decisionTime}s to choose response`,
  });
  totalScore += decisionScore;

  // 3. Decision Quality (max 25 points)
  const qualityMax = 25;
  let qualityScore = 0;
  if (metrics.decision === 'ISOLATE' && metrics.threatScoreAtDecision > 60) {
    qualityScore = 25;
    feedback.push('✅ Optimal decision: Isolation at high threat level preserves evidence and stops spread.');
  } else if (metrics.decision === 'KILL' && metrics.threatScoreAtDecision > 60) {
    qualityScore = 18;
    feedback.push('Process kill is effective but destroys forensic memory state.');
  } else if (metrics.decision === 'MONITOR' && metrics.threatScoreAtDecision < 40) {
    qualityScore = 20;
    feedback.push('Reasonable to monitor at low threat levels.');
  } else if (metrics.decision === 'MONITOR' && metrics.threatScoreAtDecision > 60) {
    qualityScore = 3;
    feedback.push('❌ CRITICAL ERROR: Monitoring during active ransomware allows catastrophic data loss.');
  } else {
    qualityScore = 12;
  }
  breakdown.push({
    metric: 'Decision Quality',
    score: qualityScore,
    maxScore: qualityMax,
    impact: qualityScore > 15 ? 'positive' : 'negative',
    detail: `Chose "${metrics.decision}" at threat score ${metrics.threatScoreAtDecision}`,
  });
  totalScore += qualityScore;

  // 4. Data Saved (max 20 points)
  const dataSavedMax = 20;
  const savedRatio = 1 - (metrics.filesEncryptedBeforeAction / metrics.totalFiles);
  const dataSavedScore = Math.round(savedRatio * 20);
  breakdown.push({
    metric: 'Data Preserved',
    score: dataSavedScore,
    maxScore: dataSavedMax,
    impact: dataSavedScore > 12 ? 'positive' : 'negative',
    detail: `${Math.round(savedRatio * 100)}% of files saved (${metrics.totalFiles - metrics.filesEncryptedBeforeAction}/${metrics.totalFiles})`,
  });
  totalScore += dataSavedScore;

  // 5. Recovery Success (max 10 points)
  const recoveryMax = 10;
  const recoveryScore = Math.round((metrics.recoverySuccess / 100) * 10);
  breakdown.push({
    metric: 'Recovery Success',
    score: recoveryScore,
    maxScore: recoveryMax,
    impact: recoveryScore > 6 ? 'positive' : 'negative',
    detail: `${metrics.recoverySuccess}% recovery rate`,
  });
  totalScore += recoveryScore;

  // Grade
  let grade: string;
  let analystLevel: string;
  if (totalScore >= 90) { grade = 'A+'; analystLevel = 'Expert SOC Analyst'; }
  else if (totalScore >= 80) { grade = 'A'; analystLevel = 'Senior Analyst'; }
  else if (totalScore >= 70) { grade = 'B'; analystLevel = 'Intermediate Analyst'; }
  else if (totalScore >= 55) { grade = 'C'; analystLevel = 'Junior Analyst'; }
  else if (totalScore >= 40) { grade = 'D'; analystLevel = 'Trainee'; }
  else { grade = 'F'; analystLevel = 'Needs Training'; }

  return { totalScore, maxScore, grade, analystLevel, breakdown, feedback };
}

export function generateForensicsReport(
  metrics: ScoreMetrics,
  scoreResult: ScoreResult,
  killChainLog: string[],
  decisions: string[]
): string {
  return `
════════════════════════════════════════════════════════════════
              CYBER RANGE — INCIDENT FORENSICS REPORT
════════════════════════════════════════════════════════════════
Generated: ${new Date().toLocaleString()}
Simulation ID: SIM-${Date.now().toString(36).toUpperCase()}

════════════════════════════════════════════════════════════════
                      EXECUTIVE SUMMARY
════════════════════════════════════════════════════════════════
Incident Type:         Ransomware Simulation (Educational)
SOC Readiness Score:   ${scoreResult.totalScore}/${scoreResult.maxScore}
Grade:                 ${scoreResult.grade}
Analyst Level:         ${scoreResult.analystLevel}

════════════════════════════════════════════════════════════════
                      SCORE BREAKDOWN
════════════════════════════════════════════════════════════════
${scoreResult.breakdown.map(b => `${b.metric.padEnd(22)} ${b.score}/${b.maxScore}  ${b.impact === 'positive' ? '✅' : '⚠️'}  ${b.detail}`).join('\n')}

════════════════════════════════════════════════════════════════
                      ATTACK TIMELINE
════════════════════════════════════════════════════════════════
${killChainLog.map((log, i) => `[Phase ${i + 1}] ${log}`).join('\n')}

════════════════════════════════════════════════════════════════
                    OPERATOR DECISIONS
════════════════════════════════════════════════════════════════
${decisions.map((d, i) => `Decision ${i + 1}: ${d}`).join('\n')}

════════════════════════════════════════════════════════════════
                    KEY METRICS
════════════════════════════════════════════════════════════════
Detection Time:        ${metrics.detectionTime}s
Decision Time:         ${metrics.decisionTime}s
Response Strategy:     ${metrics.decision}
Threat Score at Decision: ${metrics.threatScoreAtDecision}/100
Files Encrypted:       ${metrics.filesEncryptedBeforeAction}/${metrics.totalFiles}
Recovery Rate:         ${metrics.recoverySuccess}%

════════════════════════════════════════════════════════════════
                      FEEDBACK
════════════════════════════════════════════════════════════════
${scoreResult.feedback.map(f => `• ${f}`).join('\n')}

════════════════════════════════════════════════════════════════
                    RECOMMENDATIONS
════════════════════════════════════════════════════════════════
1. ${scoreResult.totalScore < 70 ? 'Practice faster detection — set up automated alert thresholds' : 'Maintain current detection practices'}
2. ${metrics.decision === 'MONITOR' ? 'Avoid passive monitoring during confirmed attacks' : 'Decision-making quality is satisfactory'}
3. Implement the 3-2-1 backup strategy for real environments
4. Conduct quarterly tabletop exercises
5. Review and update incident response playbooks

════════════════════════════════════════════════════════════════
     This report was generated by CyberGuard Cyber Range
     For educational and training purposes only
════════════════════════════════════════════════════════════════
`;
}
