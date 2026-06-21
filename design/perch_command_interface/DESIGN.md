---
name: Perch Command Interface
colors:
  surface: '#0b1326'
  surface-dim: '#0b1326'
  surface-bright: '#31394d'
  surface-container-lowest: '#060e20'
  surface-container-low: '#131b2e'
  surface-container: '#171f33'
  surface-container-high: '#222a3d'
  surface-container-highest: '#2d3449'
  on-surface: '#dae2fd'
  on-surface-variant: '#bdc8d1'
  inverse-surface: '#dae2fd'
  inverse-on-surface: '#283044'
  outline: '#87929a'
  outline-variant: '#3e484f'
  surface-tint: '#7bd0ff'
  primary: '#8ed5ff'
  on-primary: '#00354a'
  primary-container: '#38bdf8'
  on-primary-container: '#004965'
  inverse-primary: '#00668a'
  secondary: '#4de082'
  on-secondary: '#003919'
  secondary-container: '#00b55d'
  on-secondary-container: '#003e1c'
  tertiary: '#ffc42f'
  on-tertiary: '#402d00'
  tertiary-container: '#e1a800'
  on-tertiary-container: '#584000'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#c4e7ff'
  primary-fixed-dim: '#7bd0ff'
  on-primary-fixed: '#001e2c'
  on-primary-fixed-variant: '#004c69'
  secondary-fixed: '#6dfe9c'
  secondary-fixed-dim: '#4de082'
  on-secondary-fixed: '#00210c'
  on-secondary-fixed-variant: '#005227'
  tertiary-fixed: '#ffdf9f'
  tertiary-fixed-dim: '#f9bd22'
  on-tertiary-fixed: '#261a00'
  on-tertiary-fixed-variant: '#5c4300'
  background: '#0b1326'
  on-background: '#dae2fd'
  surface-variant: '#2d3449'
typography:
  headline-lg:
    fontFamily: Inter
    fontSize: 32px
    fontWeight: '600'
    lineHeight: 40px
    letterSpacing: -0.02em
  headline-md:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.01em
  body-md:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
  body-sm:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  code-md:
    fontFamily: JetBrains Mono
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  code-sm:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '500'
    lineHeight: 16px
  label-caps:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '700'
    lineHeight: 16px
    letterSpacing: 0.05em
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  unit: 4px
  gutter: 16px
  margin: 24px
  panel-padding: 20px
---

## Brand & Style

The design system is built on a "Terminal-Plus" aesthetic, merging the precision of a developer's CLI with the visual depth of a modern cloud orchestration platform. The brand personality is authoritative, technical, and vigilant, designed to evoke a sense of total system visibility and control.

The visual style utilizes **Glassmorphism** and **Minimalism** to manage density. Surfaces are deep and atmospheric, using translucent layers to maintain context in a multi-pane environment. Subtle organic metaphors—specifically branching structures—are integrated into the topology and navigation to reflect the "Perch" concept, where services "nest" within infrastructure. The emotional response should be one of "calm mastery" over complex distributed systems.

## Colors

The palette is optimized for long-duration monitoring in low-light environments.
- **Base Layers:** The primary canvas uses `#0F172A` (Background), with `#1E293B` (Surface) acting as the raised container level. 
- **Accents:** "Pulse Blue" (`#38BDF8`) is the primary interactive color, used for selection and active states. 
- **Semantics:** "Cyber Lime" (`#4ADE80`) indicates healthy uptime; "Action Orange" (`#FBBF24`) highlights configuration drift or warnings; "Red" (`#F87171`) is reserved for critical failures or exited processes.
- **Borders:** Subtle slate (`#334155`) defines structural boundaries without introducing visual noise.

## Typography

This design system employs a dual-typeface strategy to distinguish between UI orchestration and system data. 
- **Inter** is the primary sans-serif for navigation, headers, and descriptive text, providing high legibility at small scales. 
- **JetBrains Mono** is utilized for all "machine" data, including logs, YAML configurations, hashes, and status labels. 

Large headlines are condensed and slightly tracked in for a tighter, more "engineered" look. Labels for system metrics always use the mono font to signal their raw-data nature.

## Layout & Spacing

The layout follows a **Fluid Grid** model designed for high-density information display. It utilizes a multi-pane approach where secondary and tertiary panels can be toggled or resized.
- **Grid:** A 12-column grid system with 16px gutters.
- **Density:** Padding is kept tight (using 4px increments) to maximize the "Command Center" feel, allowing for more data visibility without clutter.
- **Responsiveness:** On mobile, the multi-pane layout collapses into a vertical stack, with the primary telemetry stream taking priority. On desktop, the sidebar is fixed at 240px, while content areas expand fluidly.

## Elevation & Depth

Hierarchy is established through **Tonal Layers** and **Glassmorphism** rather than traditional drop shadows.
- **Level 0 (Background):** Deepest slate, solid color.
- **Level 1 (Panels):** Translucent `#1E293B` with a 10px backdrop blur and a 1px solid border (`#334155`).
- **Level 2 (Popovers/Tooltips):** Slightly brighter surface with a subtle `Pulse Blue` inner glow to indicate focus.
- **Interaction:** Hovering over a service node triggers a "Health Ring"—a subtle, glowing outer stroke that pulses based on the service's heartbeat frequency.

## Shapes

The design system uses a **Soft** shape language (`0.25rem` standard radius). This avoids the extreme roundness of consumer apps, maintaining a professional, "tooled" appearance, while rounding just enough to soften the harshness of the dark terminal aesthetic. 
- **Standard UI elements:** 4px radius.
- **Status Badges & Chips:** 2px radius for a sharper, more technical feel.
- **Health Rings:** Perfectly circular elements for topology nodes to represent "perched" services.

## Components

- **Buttons:** Primary buttons are solid `Pulse Blue` with high-contrast dark text. Secondary buttons use a ghost style with the `334155` border and transparent background.
- **Status Badges:** High-contrast blocks using the semantic colors (Lime, Orange, Red). These always use **JetBrains Mono** for the text.
- **Cards/Panels:** Glassmorphic containers with a 1px border. Title bars of panels should have a subtle top-border in the primary accent color.
- **Logs:** Monospaced text against a `#0F172A` background, with syntax highlighting following the primary/secondary/tertiary color rules.
- **Input Fields:** Darker than the surface background, using a subtle blue bottom border on focus. No heavy outlines.
- **Topology Nodes:** Circular "Perch" icons. Each node is surrounded by a "Health Ring"—a 2px stroke that glows with the color corresponding to the service status.