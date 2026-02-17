import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';

interface TerminalSequenceProps {
  phase: 'boot' | 'matrix';
}

const TerminalSequence = ({ phase }: TerminalSequenceProps) => {
  const [lines, setLines] = useState<string[]>([]);
  const [currentLineIndex, setCurrentLineIndex] = useState(0);

  const bootSequence = [
    '> CYBERGUARD DEFENSE SYSTEMS',
    '> Initializing kernel...',
    '> Loading security modules...',
    '> [OK] Firewall active',
    '> [OK] Intrusion detection online',
    '> [OK] Threat analysis engine ready',
    '> [OK] Neural network initialized',
    '> Connecting to global threat database...',
    '> WARNING: Unusual activity detected',
    '> Scanning network perimeter...',
  ];

  const matrixSequence = [
    '> ALERT: Multiple breach attempts detected',
    '> Source: Unknown',
    '> Protocol: Encrypted',
    '> Attempting to trace...',
    '> Decrypting hostile packets...',
    '> ████████████████ 100%',
    '> Identity revealed...',
  ];

  const sequence = phase === 'boot' ? bootSequence : matrixSequence;

  useEffect(() => {
    setLines([]);
    setCurrentLineIndex(0);
    
    const interval = setInterval(() => {
      setCurrentLineIndex((prev) => {
        if (prev < sequence.length) {
          setLines((prevLines) => [...prevLines, sequence[prev]]);
          return prev + 1;
        }
        clearInterval(interval);
        return prev;
      });
    }, phase === 'boot' ? 400 : 600);

    return () => clearInterval(interval);
  }, [phase]);

  return (
    <div className="w-full max-w-2xl mx-auto px-4">
      <div className="bg-background/90 backdrop-blur-sm border border-primary/30 rounded-lg p-6 font-mono text-left">
        {/* Terminal header */}
        <div className="flex items-center gap-2 mb-4 pb-4 border-b border-primary/20">
          <div className="w-3 h-3 rounded-full bg-destructive" />
          <div className="w-3 h-3 rounded-full bg-warning" />
          <div className="w-3 h-3 rounded-full bg-accent" />
          <span className="ml-4 text-muted-foreground text-sm">cyberguard@mainframe:~$</span>
        </div>

        {/* Terminal content */}
        <div className="space-y-1 min-h-[300px]">
          {lines.map((line, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.3 }}
              className={`text-sm md:text-base ${
                line.includes('[OK]') ? 'text-accent' :
                line.includes('WARNING') || line.includes('ALERT') ? 'text-destructive' :
                line.includes('████') ? 'text-primary animate-pulse' :
                'text-foreground/80'
              }`}
            >
              {line}
            </motion.div>
          ))}
          
          {/* Blinking cursor */}
          {currentLineIndex < sequence.length && (
            <motion.span
              animate={{ opacity: [1, 0] }}
              transition={{ duration: 0.5, repeat: Infinity }}
              className="inline-block w-2 h-4 bg-primary"
            />
          )}
        </div>

        {/* Progress bar */}
        <div className="mt-6 pt-4 border-t border-primary/20">
          <div className="flex justify-between text-xs text-muted-foreground mb-2">
            <span>System Initialization</span>
            <span>{Math.round((currentLineIndex / sequence.length) * 100)}%</span>
          </div>
          <div className="h-1 bg-muted rounded-full overflow-hidden">
            <motion.div
              className="h-full bg-gradient-to-r from-primary to-accent"
              initial={{ width: 0 }}
              animate={{ width: `${(currentLineIndex / sequence.length) * 100}%` }}
              transition={{ duration: 0.5 }}
            />
          </div>
        </div>
      </div>
    </div>
  );
};

export default TerminalSequence;
