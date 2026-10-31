/**
 * ASCII plasma background.
 *
 * The runtime (loaded once from index.html) mounts a WebGL canvas into any
 * element carrying `data-aifx="ascii"`. The palette is tuned to the AgentShield
 * design tokens so the effect stays a background, not decoration over data.
 */
export function PlasmaBackground() {
  return (
    <div
      data-aifx="ascii"
      data-aifx-colors="#0d2a3a,#55d6be,#79afff"
      data-aifx-bg="#0b1020"
      data-aifx-speed="0.22"
      data-aifx-glow="0.3"
      data-aifx-contrast="1.05"
      data-aifx-scanlines="0.12"
      data-aifx-cell-size="15"
      className="absolute inset-0 -z-10 pointer-events-none"
      aria-hidden="true"
    />
  );
}
