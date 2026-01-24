import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { cn } from '@/lib/utils';

interface GlitchTextProps {
  text: string;
  className?: string;
  glitchIntensity?: 'low' | 'medium' | 'high' | 'extreme';
}

const GlitchText = ({ text, className, glitchIntensity = 'medium' }: GlitchTextProps) => {
  const [glitchActive, setGlitchActive] = useState(false);
  const [displayText, setDisplayText] = useState(text);

  const glitchChars = '!@#$%^&*()_+-=[]{}|;:,.<>?/~`01';
  
  const intensityConfig = {
    low: { frequency: 3000, duration: 100 },
    medium: { frequency: 2000, duration: 150 },
    high: { frequency: 1000, duration: 200 },
    extreme: { frequency: 500, duration: 300 },
  };

  useEffect(() => {
    const config = intensityConfig[glitchIntensity];
    
    const glitchInterval = setInterval(() => {
      setGlitchActive(true);
      
      // Create glitched text
      let iterations = 0;
      const maxIterations = 5;
      
      const scrambleInterval = setInterval(() => {
        if (iterations >= maxIterations) {
          setDisplayText(text);
          setGlitchActive(false);
          clearInterval(scrambleInterval);
          return;
        }
        
        setDisplayText(
          text
            .split('')
            .map((char, index) => {
              if (char === ' ') return ' ';
              if (Math.random() < 0.3) {
                return glitchChars[Math.floor(Math.random() * glitchChars.length)];
              }
              return char;
            })
            .join('')
        );
        
        iterations++;
      }, config.duration / maxIterations);
      
    }, config.frequency);

    return () => clearInterval(glitchInterval);
  }, [text, glitchIntensity]);

  return (
    <div className={cn('relative inline-block', className)}>
      {/* Main text */}
      <motion.span
        className="relative z-10"
        animate={glitchActive ? {
          x: [0, -2, 2, -1, 1, 0],
          y: [0, 1, -1, 0],
        } : {}}
        transition={{ duration: 0.1 }}
      >
        {displayText}
      </motion.span>
      
      {/* Glitch layers */}
      {glitchActive && (
        <>
          <motion.span
            className="absolute inset-0 text-destructive opacity-70"
            style={{ clipPath: 'polygon(0 0, 100% 0, 100% 45%, 0 45%)' }}
            animate={{ x: [-2, 2, -2] }}
            transition={{ duration: 0.1, repeat: 3 }}
          >
            {displayText}
          </motion.span>
          <motion.span
            className="absolute inset-0 text-accent opacity-70"
            style={{ clipPath: 'polygon(0 55%, 100% 55%, 100% 100%, 0 100%)' }}
            animate={{ x: [2, -2, 2] }}
            transition={{ duration: 0.1, repeat: 3 }}
          >
            {displayText}
          </motion.span>
        </>
      )}
      
      {/* Glow effect */}
      <span 
        className="absolute inset-0 blur-lg opacity-50 -z-10"
        aria-hidden="true"
      >
        {text}
      </span>
    </div>
  );
};

export default GlitchText;
