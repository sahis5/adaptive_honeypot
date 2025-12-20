import React, { useEffect, useRef } from 'react';

// Simple pseudo-random noise for continents
// Returns 0..1
const simpleNoise = (x, y, z) => {
    let val = Math.sin(x * 3) + Math.sin(y * 3) + Math.sin(z * 3)
        + Math.cos(x * 7) + Math.cos(y * 7) + Math.cos(z * 7) * 0.5;
    return (val + 3) / 6; // Normalize roughly
};

const RetroGlobe = ({ isAlert = false }) => {
    const canvasRef = useRef(null);

    useEffect(() => {
        const canvas = canvasRef.current;
        const ctx = canvas.getContext('2d');

        // Handle HiDPI displays
        const dpr = window.devicePixelRatio || 1;
        const rect = canvas.parentElement.getBoundingClientRect();

        canvas.width = rect.width * dpr;
        canvas.height = rect.height * dpr;
        ctx.scale(dpr, dpr);

        const width = rect.width;
        const height = rect.height;

        // Globe params
        const GLOBE_RADIUS = Math.min(width, height) * 0.45;
        const TOTAL_POINTS = 1600; // More points for definition
        let rotation = 0;
        let particles = [];

        // Colors
        const COLOR_SAFE = '#3b82f6'; // Blue
        const COLOR_ALERT = '#ef4444'; // Red
        const COLOR_LAND_SAFE = '#60a5fa'; // Lighter blue for land
        const COLOR_LAND_ALERT = '#fca5a5'; // Lighter red for land

        // Generate points on sphere
        // Use Golden Section Spiral for even distribution, then filter by "noise" for continents
        const phi = Math.PI * (3 - Math.sqrt(5)); // golden angle

        for (let i = 0; i < TOTAL_POINTS; i++) {
            const y = 1 - (i / (TOTAL_POINTS - 1)) * 2; // y goes from 1 to -1
            const radius = Math.sqrt(1 - y * y);
            const theta = phi * i;

            const x = Math.cos(theta) * radius;
            const z = Math.sin(theta) * radius;

            // "Continent" Check using noise
            // We scale coordinates for noise frequency
            const noiseVal = simpleNoise(x * 2, y * 2, z * 2);

            // Threshold determines land vs ocean
            // We keep ocean points sparser, land points denser or just show land
            // Let's just show LAND points + a few spread out ocean points
            const isLand = noiseVal > 0.55;

            if (isLand || Math.random() > 0.96) { // Draw land + 4% of ocean dots
                particles.push({
                    x: x * GLOBE_RADIUS,
                    y: y * GLOBE_RADIUS,
                    z: z * GLOBE_RADIUS,
                    isLand
                });
            }
        }

        let animationId;

        const render = () => {
            ctx.clearRect(0, 0, width, height);

            rotation += 0.003; // Slower, majestic rotation

            const cx = width / 2;
            const cy = height / 2;

            const primaryColor = isAlert ? COLOR_ALERT : COLOR_SAFE;
            const landColor = isAlert ? COLOR_LAND_ALERT : COLOR_LAND_SAFE;

            // Sort z-index
            // We calculate rotated Z first to sort
            const projected = particles.map(p => {
                // Rotate around Y axis
                const x2 = p.x * Math.cos(rotation) - p.z * Math.sin(rotation);
                const z2 = p.x * Math.sin(rotation) + p.z * Math.cos(rotation);
                return { ...p, x2, z2 };
            });

            // Draw dashed globe outline (equator/meridian hints)
            ctx.strokeStyle = primaryColor;
            ctx.globalAlpha = 0.1;
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.arc(cx, cy, GLOBE_RADIUS, 0, Math.PI * 2);
            ctx.stroke();

            // Draw particles
            projected.forEach(p => {
                if (p.z2 > -GLOBE_RADIUS * 0.2) { // Show front/near-front only
                    const scale = 300 / (300 + p.z2); // Perspective
                    const x2d = (p.x2 * scale) + cx;
                    const y2d = (p.y * scale) + cy;

                    // Alpha fade for depth
                    // Map z2 from -Radius to +Radius -> 0.1 to 1.0
                    const alpha = ((p.z2 + GLOBE_RADIUS) / (GLOBE_RADIUS * 2)) * 0.9 + 0.1;
                    ctx.globalAlpha = alpha;

                    ctx.fillStyle = p.isLand ? landColor : primaryColor;

                    const size = p.isLand ? 1.5 : 1.0;
                    ctx.beginPath();
                    ctx.arc(x2d, y2d, size * scale, 0, Math.PI * 2);
                    ctx.fill();
                }
            });

            // Scanline sweep
            if (isAlert) {
                const time = Date.now() / 1000;
                const scanY = cy + Math.sin(time * 2) * GLOBE_RADIUS;
                ctx.strokeStyle = 'rgba(255, 50, 50, 0.5)';
                ctx.lineWidth = 2;
                ctx.beginPath();
                ctx.moveTo(cx - GLOBE_RADIUS, scanY);
                ctx.lineTo(cx + GLOBE_RADIUS, scanY);
                ctx.stroke();
            }

            ctx.globalAlpha = 1.0;
            animationId = requestAnimationFrame(render);
        };

        render();

        // Resize handler
        const handleResize = () => {
            const rect = canvas.parentElement.getBoundingClientRect();
            canvas.width = rect.width * dpr;
            canvas.height = rect.height * dpr;
            ctx.scale(dpr, dpr);
        };
        window.addEventListener('resize', handleResize);

        return () => {
            cancelAnimationFrame(animationId);
            window.removeEventListener('resize', handleResize);
        };
    }, [isAlert]);

    return (
        <div style={{ width: '100%', height: '100%', position: 'relative' }}>
            <canvas ref={canvasRef} style={{ display: 'block', width: '100%', height: '100%' }} />
            {/* Glare effect */}
            <div style={{
                position: 'absolute', top: 0, left: 0, right: 0, bottom: 0,
                background: 'radial-gradient(circle at 30% 30%, rgba(255,255,255,0.05) 0%, rgba(0,0,0,0) 60%)',
                pointerEvents: 'none'
            }}></div>
        </div>
    );
};

export default RetroGlobe;
