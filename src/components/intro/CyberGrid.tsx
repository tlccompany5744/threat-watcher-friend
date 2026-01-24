import { useEffect, useRef } from 'react';
import { motion } from 'framer-motion';

interface CyberGridProps {
  phase: string;
}

const CyberGrid = ({ phase }: CyberGridProps) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const resize = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    };
    resize();
    window.addEventListener('resize', resize);

    const gridSize = 50;
    let animationId: number;
    let time = 0;

    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      
      const intensity = phase === 'boot' ? 0.1 : 
                       phase === 'matrix' ? 0.2 : 
                       phase === 'hacker' ? 0.3 : 
                       phase === 'message' ? 0.4 : 0.5;

      // Draw grid lines
      ctx.strokeStyle = `hsla(180, 100%, 50%, ${intensity * 0.3})`;
      ctx.lineWidth = 1;

      // Horizontal lines
      for (let y = 0; y < canvas.height; y += gridSize) {
        const wave = Math.sin(time * 0.02 + y * 0.01) * 5;
        ctx.beginPath();
        ctx.moveTo(0, y + wave);
        ctx.lineTo(canvas.width, y + wave);
        ctx.stroke();
      }

      // Vertical lines
      for (let x = 0; x < canvas.width; x += gridSize) {
        const wave = Math.cos(time * 0.02 + x * 0.01) * 5;
        ctx.beginPath();
        ctx.moveTo(x + wave, 0);
        ctx.lineTo(x + wave, canvas.height);
        ctx.stroke();
      }

      // Draw intersection points with glow
      for (let x = 0; x < canvas.width; x += gridSize) {
        for (let y = 0; y < canvas.height; y += gridSize) {
          const distance = Math.sqrt(
            Math.pow(x - canvas.width / 2, 2) + 
            Math.pow(y - canvas.height / 2, 2)
          );
          const maxDistance = Math.sqrt(
            Math.pow(canvas.width / 2, 2) + 
            Math.pow(canvas.height / 2, 2)
          );
          const pulse = Math.sin(time * 0.05 - distance * 0.01) * 0.5 + 0.5;
          
          ctx.fillStyle = `hsla(180, 100%, 50%, ${intensity * pulse * (1 - distance / maxDistance)})`;
          ctx.beginPath();
          ctx.arc(x, y, 2, 0, Math.PI * 2);
          ctx.fill();
        }
      }

      // Draw scanning line
      const scanY = (time * 2) % canvas.height;
      const gradient = ctx.createLinearGradient(0, scanY - 50, 0, scanY + 50);
      gradient.addColorStop(0, 'transparent');
      gradient.addColorStop(0.5, `hsla(180, 100%, 50%, ${intensity})`);
      gradient.addColorStop(1, 'transparent');
      
      ctx.fillStyle = gradient;
      ctx.fillRect(0, scanY - 50, canvas.width, 100);

      time++;
      animationId = requestAnimationFrame(draw);
    };

    draw();

    return () => {
      window.removeEventListener('resize', resize);
      cancelAnimationFrame(animationId);
    };
  }, [phase]);

  return (
    <motion.canvas
      ref={canvasRef}
      className="fixed inset-0 pointer-events-none"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 2 }}
      style={{ zIndex: -1 }}
    />
  );
};

export default CyberGrid;
