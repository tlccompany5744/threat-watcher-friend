import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import MatrixRain from '@/components/MatrixRain';
import HackerAvatar from '@/components/intro/HackerAvatar';
import GlitchText from '@/components/intro/GlitchText';
import TerminalSequence from '@/components/intro/TerminalSequence';
import CyberGrid from '@/components/intro/CyberGrid';
import ParticleField from '@/components/intro/ParticleField';

type Phase = 'boot' | 'matrix' | 'hacker' | 'message' | 'reveal' | 'complete';

const IntroPage = () => {
  const [phase, setPhase] = useState<Phase>('boot');
  const [skipVisible, setSkipVisible] = useState(false);
  const navigate = useNavigate();

  const goToAuth = useCallback(() => {
    navigate('/auth');
  }, [navigate]);

  useEffect(() => {
    // Show skip button after 3 seconds
    const skipTimer = setTimeout(() => setSkipVisible(true), 3000);
    
    // Phase timings (total ~2.5 minutes)
    const timings: Record<Phase, number> = {
      boot: 8000,      // 8 seconds - boot sequence
      matrix: 15000,   // 15 seconds - matrix rain intensifies
      hacker: 40000,   // 40 seconds - hacker appears and types
      message: 35000,  // 35 seconds - main message reveal
      reveal: 20000,   // 20 seconds - final reveal
      complete: 0,
    };

    let totalDelay = 0;
    const phases: Phase[] = ['boot', 'matrix', 'hacker', 'message', 'reveal', 'complete'];
    
    const timers = phases.slice(1).map((nextPhase, index) => {
      totalDelay += timings[phases[index]];
      return setTimeout(() => setPhase(nextPhase), totalDelay);
    });

    // Navigate after all phases
    const navTimer = setTimeout(goToAuth, totalDelay + 2000);

    return () => {
      clearTimeout(skipTimer);
      clearTimeout(navTimer);
      timers.forEach(clearTimeout);
    };
  }, [goToAuth]);

  return (
    <div className="min-h-screen bg-background overflow-hidden relative">
      {/* Background layers */}
      <MatrixRain />
      <CyberGrid phase={phase} />
      <ParticleField phase={phase} />
      
      {/* Scanlines overlay */}
      <div className="absolute inset-0 pointer-events-none scanlines opacity-30" />
      
      {/* Vignette effect */}
      <div className="absolute inset-0 pointer-events-none bg-radial-vignette" />

      {/* Skip button */}
      <AnimatePresence>
        {skipVisible && phase !== 'complete' && (
          <motion.button
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={goToAuth}
            className="fixed top-6 right-6 z-50 px-4 py-2 border border-primary/50 bg-background/80 backdrop-blur-sm text-primary font-mono text-sm hover:bg-primary/20 hover:border-primary transition-all duration-300"
          >
            SKIP INTRO [ESC]
          </motion.button>
        )}
      </AnimatePresence>

      {/* Main content */}
      <div className="relative z-10 min-h-screen flex flex-col items-center justify-center">
        <AnimatePresence mode="wait">
          {/* Boot Phase */}
          {phase === 'boot' && (
            <motion.div
              key="boot"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0, scale: 0.9 }}
              className="text-center"
            >
              <TerminalSequence phase="boot" />
            </motion.div>
          )}

          {/* Matrix Phase */}
          {phase === 'matrix' && (
            <motion.div
              key="matrix"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="text-center"
            >
              <TerminalSequence phase="matrix" />
              <motion.div
                initial={{ scale: 0 }}
                animate={{ scale: [0, 1.2, 1] }}
                transition={{ delay: 5, duration: 1 }}
                className="mt-8"
              >
                <GlitchText text="SYSTEM BREACH DETECTED" className="text-destructive text-2xl md:text-4xl" />
              </motion.div>
            </motion.div>
          )}

          {/* Hacker Phase */}
          {phase === 'hacker' && (
            <motion.div
              key="hacker"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0, y: -50 }}
              className="w-full max-w-4xl px-4"
            >
              <HackerAvatar />
            </motion.div>
          )}

          {/* Message Phase */}
          {phase === 'message' && (
            <motion.div
              key="message"
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 1.5 }}
              transition={{ duration: 1 }}
              className="text-center px-4"
            >
              <motion.div
                initial={{ y: 50, opacity: 0 }}
                animate={{ y: 0, opacity: 1 }}
                transition={{ delay: 0.5, duration: 1 }}
              >
                <GlitchText 
                  text="LET'S BEAT" 
                  className="text-4xl md:text-7xl lg:text-9xl font-display font-black text-primary mb-4"
                  glitchIntensity="high"
                />
              </motion.div>
              <motion.div
                initial={{ y: 50, opacity: 0 }}
                animate={{ y: 0, opacity: 1 }}
                transition={{ delay: 2, duration: 1 }}
              >
                <GlitchText 
                  text="THE HACKERS" 
                  className="text-4xl md:text-7xl lg:text-9xl font-display font-black text-accent"
                  glitchIntensity="extreme"
                />
              </motion.div>
              
              <motion.div
                initial={{ scaleX: 0 }}
                animate={{ scaleX: 1 }}
                transition={{ delay: 4, duration: 2 }}
                className="h-1 bg-gradient-to-r from-transparent via-primary to-transparent mt-12"
              />
              
              <motion.p
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 6, duration: 1 }}
                className="text-muted-foreground font-mono text-lg md:text-xl mt-8"
              >
                &gt; Initializing CyberGuard Defense Systems...
              </motion.p>
            </motion.div>
          )}

          {/* Reveal Phase */}
          {phase === 'reveal' && (
            <motion.div
              key="reveal"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="text-center px-4"
            >
              <motion.div
                animate={{ 
                  scale: [1, 1.05, 1],
                  textShadow: [
                    '0 0 20px hsl(var(--primary))',
                    '0 0 60px hsl(var(--primary))',
                    '0 0 20px hsl(var(--primary))'
                  ]
                }}
                transition={{ duration: 2, repeat: Infinity }}
              >
                <h1 className="text-5xl md:text-8xl font-display font-black text-primary mb-8">
                  CYBERGUARD
                </h1>
              </motion.div>
              
              <motion.p
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 1 }}
                className="text-2xl md:text-4xl font-mono text-foreground mb-12"
              >
                DEFENSE SYSTEMS v2.0
              </motion.p>
              
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 2 }}
                className="flex items-center justify-center gap-4"
              >
                <div className="w-3 h-3 rounded-full bg-accent animate-pulse" />
                <span className="text-accent font-mono">SYSTEM READY</span>
              </motion.div>

              <motion.div
                initial={{ opacity: 0, y: 30 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 3 }}
                className="mt-12"
              >
                <button
                  onClick={goToAuth}
                  className="px-8 py-4 border-2 border-primary bg-primary/10 text-primary font-display text-xl tracking-wider hover:bg-primary hover:text-primary-foreground transition-all duration-300 animate-pulse"
                >
                  ENTER SYSTEM
                </button>
              </motion.div>
            </motion.div>
          )}

          {/* Complete - Auto redirect */}
          {phase === 'complete' && (
            <motion.div
              key="complete"
              initial={{ opacity: 1 }}
              animate={{ opacity: 0 }}
              transition={{ duration: 1 }}
              className="text-center"
            >
              <div className="text-primary font-mono text-xl">
                &gt; ACCESS GRANTED
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Keyboard listener for skip */}
      <KeyboardListener onEscape={goToAuth} />
    </div>
  );
};

const KeyboardListener = ({ onEscape }: { onEscape: () => void }) => {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onEscape();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onEscape]);
  
  return null;
};

export default IntroPage;
