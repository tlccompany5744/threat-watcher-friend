import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';

const HackerAvatar = () => {
  const [currentLine, setCurrentLine] = useState(0);
  const [displayedText, setDisplayedText] = useState('');
  
  const hackerLines = [
    { text: "> Accessing secure network...", delay: 0 },
    { text: "> Bypassing firewall protocols...", delay: 3000 },
    { text: "> Encryption detected... Decrypting...", delay: 6000 },
    { text: "> Target acquired.", delay: 10000 },
    { text: "> But wait...", delay: 14000 },
    { text: "> You're not the enemy.", delay: 17000 },
    { text: "> You're here to protect.", delay: 20000 },
    { text: "> Together...", delay: 24000 },
    { text: "> WE WILL BEAT THEM.", delay: 28000 },
  ];

  useEffect(() => {
    const timers: NodeJS.Timeout[] = [];
    
    hackerLines.forEach((line, index) => {
      const timer = setTimeout(() => {
        setCurrentLine(index);
        // Typing effect
        let charIndex = 0;
        const typingInterval = setInterval(() => {
          if (charIndex <= line.text.length) {
            setDisplayedText(line.text.substring(0, charIndex));
            charIndex++;
          } else {
            clearInterval(typingInterval);
          }
        }, 50);
        timers.push(typingInterval as unknown as NodeJS.Timeout);
      }, line.delay);
      timers.push(timer);
    });

    return () => timers.forEach(clearTimeout);
  }, []);

  return (
    <div className="flex flex-col md:flex-row items-center gap-8 md:gap-12">
      {/* Hacker Avatar */}
      <motion.div
        initial={{ x: -100, opacity: 0 }}
        animate={{ x: 0, opacity: 1 }}
        transition={{ duration: 1, ease: "easeOut" }}
        className="relative"
      >
        {/* Glowing backdrop */}
        <div className="absolute inset-0 bg-primary/20 blur-3xl rounded-full scale-150" />
        
        {/* Avatar container */}
        <div className="relative w-48 h-48 md:w-64 md:h-64">
          {/* Outer ring */}
          <motion.div
            animate={{ rotate: 360 }}
            transition={{ duration: 20, repeat: Infinity, ease: "linear" }}
            className="absolute inset-0 border-2 border-dashed border-primary/50 rounded-full"
          />
          
          {/* Middle ring */}
          <motion.div
            animate={{ rotate: -360 }}
            transition={{ duration: 15, repeat: Infinity, ease: "linear" }}
            className="absolute inset-4 border border-accent/50 rounded-full"
          />
          
          {/* Inner glow */}
          <div className="absolute inset-8 bg-gradient-to-br from-primary/30 to-accent/30 rounded-full blur-xl" />
          
          {/* Hacker silhouette */}
          <div className="absolute inset-8 flex items-center justify-center">
            <motion.div
              animate={{ 
                scale: [1, 1.05, 1],
                opacity: [0.8, 1, 0.8]
              }}
              transition={{ duration: 2, repeat: Infinity }}
            >
              <svg
                viewBox="0 0 100 100"
                className="w-full h-full text-primary"
                fill="currentColor"
              >
                {/* Hooded figure */}
                <path d="M50 10 C30 10 20 30 20 45 C20 55 25 60 25 60 L25 85 C25 90 30 95 50 95 C70 95 75 90 75 85 L75 60 C75 60 80 55 80 45 C80 30 70 10 50 10 Z" 
                      fill="currentColor" 
                      opacity="0.9"
                />
                {/* Face shadow */}
                <ellipse cx="50" cy="45" rx="20" ry="22" fill="hsl(var(--background))" opacity="0.8" />
                {/* Glowing eyes */}
                <motion.ellipse 
                  cx="42" cy="42" rx="3" ry="2" 
                  fill="hsl(var(--accent))"
                  animate={{ opacity: [1, 0.5, 1] }}
                  transition={{ duration: 0.5, repeat: Infinity }}
                />
                <motion.ellipse 
                  cx="58" cy="42" rx="3" ry="2" 
                  fill="hsl(var(--accent))"
                  animate={{ opacity: [1, 0.5, 1] }}
                  transition={{ duration: 0.5, repeat: Infinity, delay: 0.25 }}
                />
                {/* Binary code falling from hood */}
                <text x="35" y="70" fontSize="4" fill="hsl(var(--primary))" opacity="0.5">01101</text>
                <text x="50" y="75" fontSize="4" fill="hsl(var(--primary))" opacity="0.5">10010</text>
              </svg>
            </motion.div>
          </div>

          {/* Floating binary particles */}
          {[...Array(8)].map((_, i) => (
            <motion.div
              key={i}
              className="absolute text-xs font-mono text-primary/60"
              style={{
                left: `${20 + Math.random() * 60}%`,
                top: `${20 + Math.random() * 60}%`,
              }}
              animate={{
                y: [-20, -40, -20],
                opacity: [0, 1, 0],
              }}
              transition={{
                duration: 3,
                repeat: Infinity,
                delay: i * 0.5,
              }}
            >
              {Math.random() > 0.5 ? '1' : '0'}
            </motion.div>
          ))}
        </div>
      </motion.div>

      {/* Terminal output */}
      <motion.div
        initial={{ x: 100, opacity: 0 }}
        animate={{ x: 0, opacity: 1 }}
        transition={{ duration: 1, ease: "easeOut", delay: 0.5 }}
        className="flex-1 max-w-xl"
      >
        <div className="bg-background/80 backdrop-blur-sm border border-primary/30 rounded-lg p-6 font-mono">
          {/* Terminal header */}
          <div className="flex items-center gap-2 mb-4 pb-4 border-b border-primary/20">
            <div className="w-3 h-3 rounded-full bg-destructive" />
            <div className="w-3 h-3 rounded-full bg-warning" />
            <div className="w-3 h-3 rounded-full bg-accent" />
            <span className="ml-4 text-muted-foreground text-sm">hacker@cyberguard:~$</span>
          </div>
          
          {/* Previous lines */}
          <div className="space-y-2 mb-4">
            {hackerLines.slice(0, currentLine).map((line, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 0.6, x: 0 }}
                className="text-muted-foreground text-sm md:text-base"
              >
                {line.text}
              </motion.div>
            ))}
          </div>
          
          {/* Current typing line */}
          <div className="text-primary text-base md:text-lg">
            {displayedText}
            <motion.span
              animate={{ opacity: [1, 0] }}
              transition={{ duration: 0.5, repeat: Infinity }}
              className="inline-block w-3 h-5 bg-primary ml-1 align-middle"
            />
          </div>
        </div>

        {/* Hacker name tag */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 2 }}
          className="mt-4 text-center"
        >
          <span className="text-accent font-display text-lg tracking-widest">
            [ GHOST_DEFENDER ]
          </span>
        </motion.div>
      </motion.div>
    </div>
  );
};

export default HackerAvatar;
