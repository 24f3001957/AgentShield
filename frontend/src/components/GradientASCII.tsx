import { useEffect, useRef } from "react";

/**
 * GradientASCII — animated ASCII gradient field used as the console backdrop.
 *
 * This is a self-contained canvas implementation of the component API used by
 * the AgentShield design brief (the upstream `GradientASCII` module is not part
 * of this repository). It stays decorative: `aria-hidden`, `pointer-events:
 * none`, capped DPR, throttled frames, paused when the tab is hidden, and a
 * single static frame when the user prefers reduced motion.
 */
export type GradientASCIIProps = {
  colors?: string[];
  shape?: "horizon" | "linear" | "radial";
  characters?: string;
  cellSize?: number;
  density?: number;
  glyphOpacity?: number;
  glow?: number;
  depthOfField?: number;
  flicker?: number;
  softness?: number;
  scale?: number;
  flow?: number;
  speed?: number;
  gradientOpacity?: number;
  grain?: number;
  variation?: number;
  mouseInteraction?: boolean;
  scrambleRadius?: number;
  clickEffect?: "none" | "wave";
  intro?: boolean;
  lightMode?: boolean;
  className?: string;
};

const DEFAULTS = {
  colors: ["#1e3fd8", "#f6f8ff", "#a5d8ff", "#38bdf8"],
  shape: "horizon" as const,
  characters: " =+xX0S8#@",
  cellSize: 18,
  density: 0.8,
  glyphOpacity: 0.55,
  glow: 0.2,
  depthOfField: 0,
  flicker: 0.2,
  softness: 0.5,
  scale: 1,
  flow: 0.5,
  speed: 1,
  gradientOpacity: 0.7,
  grain: 0.08,
  variation: 0,
  mouseInteraction: true,
  scrambleRadius: 0.1,
  clickEffect: "wave" as const,
  intro: true,
  lightMode: false,
};

type RGB = { r: number; g: number; b: number };

function parseColor(value: string): RGB {
  const hex = value.trim().replace("#", "");
  if (hex.length === 3) {
    return {
      r: parseInt(hex[0] + hex[0], 16),
      g: parseInt(hex[1] + hex[1], 16),
      b: parseInt(hex[2] + hex[2], 16),
    };
  }
  if (hex.length >= 6) {
    return {
      r: parseInt(hex.slice(0, 2), 16),
      g: parseInt(hex.slice(2, 4), 16),
      b: parseInt(hex.slice(4, 6), 16),
    };
  }
  return { r: 255, g: 255, b: 255 };
}

function rgb(color: RGB, alpha: number): string {
  return `rgba(${color.r}, ${color.g}, ${color.b}, ${alpha})`;
}

/** Deterministic per-cell noise so glyph placement is stable between frames. */
function hash(x: number, y: number): number {
  const n = Math.sin(x * 127.1 + y * 311.7) * 43758.5453;
  return n - Math.floor(n);
}

export default function GradientASCII({
  colors = DEFAULTS.colors,
  shape = DEFAULTS.shape,
  characters = DEFAULTS.characters,
  cellSize = DEFAULTS.cellSize,
  density = DEFAULTS.density,
  glyphOpacity = DEFAULTS.glyphOpacity,
  glow = DEFAULTS.glow,
  depthOfField = DEFAULTS.depthOfField,
  flicker = DEFAULTS.flicker,
  softness = DEFAULTS.softness,
  scale = DEFAULTS.scale,
  flow = DEFAULTS.flow,
  speed = DEFAULTS.speed,
  gradientOpacity = DEFAULTS.gradientOpacity,
  grain = DEFAULTS.grain,
  variation = DEFAULTS.variation,
  mouseInteraction = DEFAULTS.mouseInteraction,
  scrambleRadius = DEFAULTS.scrambleRadius,
  clickEffect = DEFAULTS.clickEffect,
  intro = DEFAULTS.intro,
  lightMode = DEFAULTS.lightMode,
  className = "",
}: GradientASCIIProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const propsRef = useRef({
    colors,
    shape,
    characters,
    cellSize,
    density,
    glyphOpacity,
    glow,
    depthOfField,
    flicker,
    softness,
    scale,
    flow,
    speed,
    gradientOpacity,
    grain,
    variation,
    mouseInteraction,
    scrambleRadius,
    clickEffect,
    intro,
    lightMode,
  });
  propsRef.current = {
    colors,
    shape,
    characters,
    cellSize,
    density,
    glyphOpacity,
    glow,
    depthOfField,
    flicker,
    softness,
    scale,
    flow,
    speed,
    gradientOpacity,
    grain,
    variation,
    mouseInteraction,
    scrambleRadius,
    clickEffect,
    intro,
    lightMode,
  };

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const context = canvas.getContext("2d");
    if (!context) return;

    const reduceQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
    const pointer = { x: -1e4, y: -1e4, active: false, rippleAt: -1e4, rippleX: 0, rippleY: 0 };
    let width = 0;
    let height = 0;
    let dpr = 1;
    let started = performance.now();
    let raf = 0;
    let lastDraw = 0;

    const resize = () => {
      const parent = canvas.parentElement;
      width = parent?.clientWidth ?? window.innerWidth;
      height = parent?.clientHeight ?? window.innerHeight;
      if (width <= 0 || height <= 0) return;
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      context.setTransform(dpr, 0, 0, dpr, 0, 0);
    };

    const draw = (now: number) => {
      const p = propsRef.current;
      const elapsed = (now - started) / 1000;
      const time = elapsed * p.speed;
      const glyphs = Array.from(p.characters);
      const palette = p.colors.map(parseColor);
      const base = palette[1] ?? { r: 255, g: 255, b: 255 };
      const accent = palette[2] ?? base;
      context.clearRect(0, 0, width, height);

      // Gradient wash.
      const gradient = context.createLinearGradient(0, 0, width * 0.35, height);
      gradient.addColorStop(0, rgb(palette[0] ?? base, p.gradientOpacity));
      gradient.addColorStop(0.55, rgb(palette[3] ?? accent, p.gradientOpacity * 0.55));
      gradient.addColorStop(1, rgb(palette[0] ?? base, p.gradientOpacity * 0.85));
      context.fillStyle = gradient;
      context.fillRect(0, 0, width, height);

      const cell = Math.max(8, p.cellSize);
      const columns = Math.ceil(width / cell) + 1;
      const rows = Math.ceil(height / cell) + 1;
      const fontSize = Math.max(8, Math.round(cell * 0.82));
      context.font = `${fontSize}px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace`;
      context.textAlign = "center";
      context.textBaseline = "middle";

      const introAlpha = p.intro ? Math.min(1, elapsed / 1.6) : 1;
      const rippleAge = (now - pointer.rippleAt) / 1000;
      const rippleRadius = rippleAge >= 0 && rippleAge < 1.1 ? rippleAge * Math.max(width, height) : -1;
      const scramble = p.scrambleRadius * Math.max(width, height);
      const horizon = height * 0.42;

      for (let row = 0; row < rows; row += 1) {
        const y = row * cell;
        const yNorm = y / Math.max(1, height);
        for (let column = 0; column < columns; column += 1) {
          const x = column * cell;
          const noise = hash(column * 0.73 + p.variation, row * 0.41);
          if (noise > p.density) continue;

          let value =
            Math.sin(x * 0.006 * p.scale + time * p.flow * 1.4) *
              Math.cos(y * 0.009 * p.scale - time * p.flow) *
              0.5 +
            0.5;
          value +=
            0.32 *
            Math.sin((x + y) * 0.0035 * p.scale + time * p.flow * 2.1 + noise * 2.4);
          if (p.shape === "horizon") {
            value += 0.55 * Math.exp(-Math.abs(y - horizon) / (height * 0.55));
          } else if (p.shape === "radial") {
            const dx = (x - width / 2) / (width * 0.5);
            const dy = (y - height / 2) / (height * 0.5);
            value += 0.5 * Math.max(0, 1 - Math.sqrt(dx * dx + dy * dy));
          }
          value += (noise - 0.5) * p.variation;
          value = Math.min(1, Math.max(0, value * (0.55 + p.softness * 0.45)));

          // Depth of field: dim cells away from the horizon band.
          const focus = 1 - p.depthOfField * Math.min(1, Math.abs(yNorm - 0.55) * 1.9);
          let alpha = p.glyphOpacity * (0.18 + value * 0.82) * focus;

          // Flicker + grain.
          if (p.flicker > 0) {
            const flick = Math.sin(time * (6 + noise * 9) + column * 0.6 + row);
            alpha *= 1 - p.flicker * 0.32 * (0.5 + 0.5 * flick);
          }
          if (p.grain > 0) alpha *= 1 - p.grain * (0.4 + noise * 0.6);

          // Pointer scramble and click ripple.
          if (p.mouseInteraction && pointer.active) {
            const dx = x - pointer.x;
            const dy = y - pointer.y;
            const distance = Math.sqrt(dx * dx + dy * dy);
            if (distance < scramble) {
              const boost = 1 - distance / scramble;
              alpha = Math.min(0.95, alpha + boost * 0.5);
              value = Math.min(1, value + boost * 0.65);
            }
          }
          if (p.clickEffect === "wave" && rippleRadius > 0) {
            const dx = x - pointer.rippleX;
            const dy = y - pointer.rippleY;
            const distance = Math.sqrt(dx * dx + dy * dy);
            if (Math.abs(distance - rippleRadius) < cell * 2.2) {
              alpha = Math.min(0.9, alpha + 0.35);
              value = Math.min(1, value + 0.4);
            }
          }

          alpha *= introAlpha;
          if (alpha < 0.015) continue;

          const index = Math.min(glyphs.length - 1, Math.floor(value * glyphs.length));
          const glyph = glyphs[index] ?? glyphs[0];
          const hot = value > 0.78;
          context.globalAlpha = alpha;
          context.fillStyle = hot ? rgb(accent, 1) : rgb(base, 1);
          context.shadowBlur = hot && p.glow > 0 ? p.glow * 18 : 0;
          context.shadowColor = rgb(accent, 0.85);
          context.fillText(glyph, x, y);
        }
      }
      context.globalAlpha = 1;
      context.shadowBlur = 0;
    };

    const loop = (now: number) => {
      raf = window.requestAnimationFrame(loop);
      if (document.hidden) return;
      // 24 fps is plenty for a decorative field and keeps laptops cool.
      if (now - lastDraw < 41) return;
      lastDraw = now;
      draw(now);
    };

    const restart = () => {
      window.cancelAnimationFrame(raf);
      started = performance.now();
      lastDraw = 0;
      if (reduceQuery.matches) {
        draw(performance.now());
        return;
      }
      raf = window.requestAnimationFrame(loop);
    };

    const onPointerMove = (event: PointerEvent) => {
      if (!propsRef.current.mouseInteraction) return;
      const rect = canvas.getBoundingClientRect();
      pointer.x = event.clientX - rect.left;
      pointer.y = event.clientY - rect.top;
      pointer.active = true;
    };
    const onPointerLeave = () => {
      pointer.active = false;
    };
    const onPointerDown = (event: PointerEvent) => {
      if (propsRef.current.clickEffect !== "wave") return;
      const rect = canvas.getBoundingClientRect();
      pointer.rippleX = event.clientX - rect.left;
      pointer.rippleY = event.clientY - rect.top;
      pointer.rippleAt = performance.now();
    };

    const onResize = () => {
      resize();
      if (reduceQuery.matches) draw(performance.now());
    };

    resize();
    restart();
    const parent = canvas.parentElement;
    const observer =
      typeof ResizeObserver === "undefined" ? null : new ResizeObserver(onResize);
    if (parent) observer?.observe(parent);
    window.addEventListener("resize", onResize);
    window.addEventListener("pointermove", onPointerMove, { passive: true });
    canvas.addEventListener("pointerleave", onPointerLeave);
    window.addEventListener("pointerdown", onPointerDown, { passive: true });
    reduceQuery.addEventListener?.("change", restart);
    const onVisibility = () => {
      if (!document.hidden) lastDraw = 0;
    };
    document.addEventListener("visibilitychange", onVisibility);

    return () => {
      window.cancelAnimationFrame(raf);
      observer?.disconnect();
      window.removeEventListener("resize", onResize);
      window.removeEventListener("pointermove", onPointerMove);
      canvas.removeEventListener("pointerleave", onPointerLeave);
      window.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("visibilitychange", onVisibility);
      reduceQuery.removeEventListener?.("change", restart);
    };
  }, []);

  return (
    <div className={`ascii-background ${className}`.trim()} aria-hidden="true">
      <canvas ref={canvasRef} className="ascii-canvas" />
    </div>
  );
}
