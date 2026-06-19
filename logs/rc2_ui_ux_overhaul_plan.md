# ThreatLensAI RC2 — UI/UX Overhaul Plan

> **Scope:** Frontend polish, cross-page consistency, data science ↔ backend alignment  
> **Phase:** Sketch-up only — no code changes yet  
> **Date:** 2026-05-28  
> **Status:** Proposal

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Current State Audit](#2-current-state-audit)
3. [Category 1: Structural & Navigation](#3-category-1-structural--navigation)
4. [Category 2: Visual Hierarchy & Verdict Prominence](#4-category-2-visual-hierarchy--verdict-prominence)
5. [Category 3: Consistency Fixes](#5-category-3-consistency-fixes)
6. [Category 4: Data Science ↔ Backend Consistency](#6-category-4-data-science--backend-consistency)
7. [Category 5: Loading States & Micro-Interactions](#7-category-5-loading-states--micro-interactions)
8. [Category 6: Transitions & Animations](#8-category-6-transitions--animations)
9. [Category 7: Light Mode Decision](#9-category-7-light-mode-decision)
10. [Pre-Implementation Backup Strategy](#10-pre-implementation-backup-strategy)
11. [All-Inclusive Benchmarks](#11-all-inclusive-benchmarks)
12. [Priority Ranking & Effort Estimate](#12-priority-ranking--effort-estimate)
13. [File Change Manifest](#13-file-change-manifest)
14. [Pre-RC2 Final Cleanup Checklist](#14-pre-rc2-final-cleanup-checklist)
15. [Industry Reference Patterns](#15-industry-reference-patterns)

---

## 1. Executive Summary

The current frontend is **functional but inconsistent**. It renders data correctly but lacks the visual hierarchy and polish expected of a security tool. VirusTotal succeeds because it establishes a clear hierarchy: **verdict first, sources second, detail third**. ThreatLensAI currently inverts this — the verdict card looks identical to every other card on the page.

**Core problem:** All information is treated equally. The verdict, source cards, evidence, and metadata compete for attention on the same visual plane with the same `rounded-3xl border border-slate-800 bg-slate-900/70 p-6` styling.

**Goal:** Transform ThreatLensAI from a functional prototype into a polished, professional-looking threat intelligence tool that follows industry-standard UI patterns (VirusTotal, AbuseIPDB, Shodan).

**Total estimated effort:** 18–28 hours across 17 discrete changes.

---

## 2. Current State Audit

### 2.1 File Inventory

| File | Lines | Role |
|------|-------|------|
| `index.html` | 112 | Scan landing page |
| `results.html` | 38 | Scan results page |
| `details.html` | 38 | Record detail page |
| `ui.js` | 1,119 | Main rendering engine (all DOM templates) |
| `api.js` | 52 | HTTP client (fetch wrapper) |
| `search.js` | 28 | SPA navigation |
| `theme.js` | 46 | Dark/light mode toggle |
| `tailwind.css` | 81 | Custom CSS (animations, verdict gradients, backdrop) |
| **Total** | **1,414** | |

### 2.2 Color Palette in Use

| Role | Background | Text | Border |
|------|-----------|------|--------|
| Page body | `bg-slate-950` | `text-slate-100` | — |
| Cards | `bg-slate-900/70` | — | `border-slate-800` |
| Inner items | `bg-slate-900` | — | `border-slate-800` |
| Primary CTA | `bg-cyan-500` | `text-slate-950` | — |
| Secondary buttons | `bg-slate-800` | `text-white` | `border-slate-700` |
| Malicious | — | `text-red-300` | `border-red-500/30` |
| Suspicious | — | `text-amber-300` | `border-amber-500/30` |
| Clean | — | `text-emerald-300` | `border-emerald-500/30` |
| ML | — | `text-violet-300` | `border-violet-500/30` |

### 2.3 Inconsistencies Identified

| # | Issue | Severity |
|---|-------|----------|
| 1 | Headers differ across all 3 pages | High |
| 2 | Grid ratios differ (1.35fr vs 1.2fr sidebar) | Medium |
| 3 | Button padding inconsistent (py-2, py-3, px-4, px-6) | Medium |
| 4 | Card padding inconsistent (p-4, p-5, p-6) | Medium |
| 5 | Card border radius inconsistent (rounded-3xl, rounded-2xl, rounded-xl, rounded-lg, rounded) | Medium |
| 6 | Empty states inconsistent (p-6 vs p-10, left vs centered) | Low |
| 7 | Dual `modelHealthBar` div on results page | Low |
| 8 | Detail page "Back" button loses query context | Medium |
| 9 | Detection counters styled differently in verdict vs inline preview | Low |
| 10 | Source score bars always `bg-cyan-500` regardless of source type | Low |
| 11 | Light mode is completely broken for JS-rendered content | High |
| 12 | Dead CSS class `.card-shadow` | Low |
| 13 | Dead `data-api-base` attribute (would cause double `/api/api/`) | Medium |
| 14 | ML card missing left-border accent (API cards have it) | Low |
| 15 | Font size inconsistency in evidence text across pages | Low |

---

## 3. Category 1: Structural & Navigation

### 3.1 Standardize Headers Across All Pages

**Current state:**

| Page | "ThreatLensAI" | Right side | Title |
|------|----------------|------------|-------|
| `index.html` | Plain `<div>` (not a link) | Hardcoded "FastAPI + PostgreSQL" badge + theme toggle | Static text |
| `results.html` | `<a>` link to index | "New scan" link + theme toggle | Dynamic `<span>` |
| `details.html` | `<a>` link to index | "Back" link (loses query context) | Static "Record details" |

**Problem:** Users navigating between pages encounter different header layouts. The "FastAPI + PostgreSQL" badge is technical metadata irrelevant to end users. The brand name is a link on some pages but not others.

**Proposal:** Single header template across all pages:

```
┌─────────────────────────────────────────────────────┐
│ [Brand link]  ThreatLensAI       [Results] [theme]  │
│ [Subtitle — page-specific text]                     │
└─────────────────────────────────────────────────────┘
```

- Brand name: always an `<a href="./index.html">` link
- Right side: consistent navigation — `New scan` | `Results` | theme toggle
- Remove "FastAPI + PostgreSQL" badge entirely
- Subtitle changes per page but follows the same `<p class="text-sm text-slate-400">` pattern

**Effort:** 1–2 hours  
**Impact:** High — eliminates cross-page jarring

### 3.2 Fix Detail Page "Back" Button Query Loss

**Current state:** `details.html` header has `<a href="./results.html">Back</a>` — navigates without `?q=`, losing scan context. The breadcrumb "Results" link *does* preserve `?q={query}`.

**Problem:** Users lose their scan context when navigating back from a detail view.

**Proposal:** Replace the header "Back" button with a `Results` link that preserves `?q={query}`. Add a small inline query display in the header showing what was scanned (monospace, truncated at 40 chars). This matches VirusTotal's pattern where detail pages always show the scanned indicator prominently.

```html
<!-- Current -->
<a href="./results.html" class="...">Back</a>

<!-- Proposed -->
<a href="./results.html?q={query}" class="...">Results</a>
```

Also add the query to the detail page header subtitle:
```
Record details for <span class="font-mono text-cyan-300">{query_truncated}</span>
```

**Effort:** 30 minutes  
**Impact:** Medium — prevents user frustration

### 3.3 Unify Grid Ratios

**Current state:**
- Index page: `lg:grid-cols-[1.35fr_0.65fr]` (sidebar is 32.5% of viewport)
- Results page (JS-rendered): `lg:grid-cols-[1.2fr_0.8fr]` (sidebar is 40% of viewport)

**Problem:** The sidebar is wider on the results page than on the index page. This causes a jarring layout shift when navigating between pages.

**Proposal:** Unify to `lg:grid-cols-[1.3fr_0.7fr]` across all pages. The sidebar takes 30% at `lg`. This matches VirusTotal's pattern where the main content area dominates.

**Effort:** 15 minutes  
**Impact:** Low — prevents layout shift

### 3.4 Remove Dual Model Health Bar on Results Page

**Current state:** `results.html` HTML has `<div id="modelHealthBar">` at line 24, AND the JS-rendered `doScanFromQuery()` creates another `<div id="modelHealthBar">` inside `resultsShell`. The HTML one is never populated.

**Problem:** Dead HTML element. Risk of rendering into wrong container if IDs collide.

**Proposal:** Remove the HTML `<div id="modelHealthBar">` from `results.html` and `details.html`. Only the JS-rendered instance in the layout should exist.

**Effort:** 10 minutes  
**Impact:** Low — cleanup

### 3.5 Dead Code Cleanup

| Dead code | Location | Action |
|-----------|----------|--------|
| `.card-shadow` CSS class | `tailwind.css:16–18` | Remove — never referenced |
| `data-api-base` attribute | All 3 HTML `<body>` elements | Remove — `api.js` auto-detects localhost; this would cause double `/api/api/` if used |
| `src/modeling.py` | `data_science/src/` | Remove — 7-line legacy stub for deleted CodeBERT path |
| `src/evaluation.py` | `data_science/src/` | Remove — generic helpers not imported by any notebook |
| `04_overhaul.ipynb` | `data_science/notebooks/` | Remove empty shell or populate |

**Effort:** 1 hour  
**Impact:** Medium — reduces maintenance burden

---

## 4. Category 2: Visual Hierarchy & Verdict Prominence

### 4.1 Redesign Verdict Card (VirusTotal-Inspired)

**Current state:** The verdict card uses the same styling as every other card:
```
rounded-3xl border border-slate-800 bg-slate-900/70 p-6 shadow-2xl shadow-black/20
```

The verdict text is `text-sm font-semibold` — the same size as source card labels. The confidence bar is optional and uses a thin `h-2` track. There's no visual anchoring.

**Problem:** The most important element on the page (the verdict) has the same visual weight as a source card or sidebar widget. Users must *read* to find the verdict rather than *seeing* it instantly.

**Proposal:** Solid color header band — the single most visually dominant element on the page.

```
┌─────────────────────────────────────────────────┐
│ ████████████████████████████████████████████████│
│ █                                              █│
│ █   MALICIOUS                            8.5   █│ ← verdict + score (large)
│ █   ████████████████████████░░░░  85%          █│ ← confidence bar (full width)
│ █                                              █│
│ ████████████████████████████████████████████████│
│                                                 │
│  185.220.101.42                                 │ ← query (monospace, large)
│  12 sources analyzed                            │
│                                                 │
│  ┌──────┐ ┌──────┐ ┌──────┐                   │
│  │  8   │ │  2   │ │  2   │                   │ ← detection counters
│  │malic.│ │susp. │ │clean │                   │
│  └──────┘ └──────┘ └──────┘                   │
└─────────────────────────────────────────────────┘
```

**Specific changes:**

| Element | Current | Proposed |
|---------|---------|----------|
| Verdict background | `verdict-danger` gradient (red-900 to red-950) | Solid color band: `bg-red-600` (CRITICAL), `bg-orange-500` (HIGH), `bg-amber-500` (MEDIUM), `bg-slate-700` (LOW/IGNORE) |
| Band height | Auto (content-driven) | Fixed `min-h-32` to ensure visual presence |
| Verdict text | `text-sm font-semibold` inside a `rounded-full` pill | `text-4xl font-black text-white` — largest text element on page |
| Score display | Separate pill: `Score 8.5` | Inline with verdict: same line, `font-mono text-3xl` |
| Confidence bar | Optional, `h-2`, `bg-slate-700` track | Required, `h-3`, `bg-black/30` track, full width of band |
| Query text | `text-3xl font-bold text-white` (below verdict) | `font-mono text-lg text-slate-200` — secondary emphasis |
| Detection counters | `rounded-2xl border border-white/10 bg-black/15 p-4` | `rounded-xl bg-{color}-950/30 p-4` (remove border, use bg tint) |

**Color band mapping:**

| Risk Band | Band Color | Text Color |
|-----------|-----------|------------|
| CRITICAL | `bg-red-600` | `text-white` |
| HIGH | `bg-orange-500` | `text-white` |
| MEDIUM | `bg-amber-500` | `text-slate-950` |
| LOW | `bg-slate-600` | `text-white` |
| IGNORE | `bg-slate-700` | `text-slate-300` |

**For OTX/CVE (reference records):** Use `bg-slate-700` band with "Reference record" as the verdict text, no confidence bar.

**Effort:** 3–4 hours  
**Impact:** High — transforms first impression

### 4.2 Differentiate Source Cards by Type

**Current state:** All source cards share `rounded-2xl border-l-4 {color} border border-slate-800 bg-slate-900 p-4`. The only differentiator is the 4px left border color and the emoji icon. The ML card is missing the left border entirely.

**Problem:** Users must read the source type label to distinguish API, ML, heuristic, and network sources. Visual scanning is slow.

**Proposal:** Each source type gets a distinct background tint + stronger left border:

| Source Type | Background | Left Border | Icon Badge |
|-------------|-----------|-------------|------------|
| ML Prediction | `bg-violet-500/5` | `border-l-violet-500` (6px) | Violet circle |
| API (AbuseIPDB, VT, NVD, etc.) | `bg-cyan-500/5` | `border-l-cyan-500` (6px) | Cyan circle |
| Heuristic | `bg-amber-500/5` | `border-l-amber-500` (6px) | Amber circle |
| Network | `bg-emerald-500/5` | `border-l-emerald-500` (6px) | Emerald circle |

**Additional changes:**
- Remove the 1px `border border-slate-800` (the left border + bg tint is sufficient)
- Add `ring-1 ring-violet-500/10` to ML cards for emphasis
- Source score bars should use the source type color, not always `bg-cyan-500`
- ML card gets `border-l-6` to match API cards (currently missing left accent)

**Effort:** 2–3 hours  
**Impact:** Medium — improves scannability

### 4.3 Group Evidence by Type

**Current state:** Evidence items are a flat list with 1px type-colored borders. They look like generic list entries.

**Problem:** When 8+ evidence items render, they blend together. Users can't quickly see "how many API sources confirmed this" vs "how many heuristic signals."

**Proposal:** Group evidence into visually distinct clusters:

```
┌─ API Evidence (3) ──────────────────────────────┐
│  🔌 AbuseIPDB confidence score: 85               │
│  🔌 VirusTotal: 12/70 engines flagged            │
│  🔌 RDAP: Registrar age 2 years                  │
└──────────────────────────────────────────────────┘
┌─ ML Model Evidence (1) ─────────────────────────┐
│  🧠 XGBoost: MALICIOUS (confidence: 0.87)       │
└──────────────────────────────────────────────────┘
┌─ Heuristic Evidence (2) ────────────────────────┐
│  ⚙️ TLD .xyz flagged as high-risk                │
│  ⚙️ Domain entropy: 3.8 (high)                   │
└──────────────────────────────────────────────────┘
```

- Each group gets a colored header bar matching its type
- Group header shows count: "API Evidence (3)"
- Items within a group share a subtle background tint
- Empty groups are hidden (not shown with "No evidence" text)
- This matches VirusTotal's "Detections", "Details", "History" tab structure

**Effort:** 2–3 hours  
**Impact:** Medium — better information architecture

---

## 5. Category 3: Consistency Fixes

### 5.1 Button Sizing Standardization

**Current state:** Five different button patterns:

| Button | px | py | rounded |
|--------|----|----|---------|
| Scan (index) | 6 | 3 | 2xl |
| Scan again (results) | 4 | 3 | 2xl |
| Re-scan (detail) | 4 | 2 | 2xl |
| Download CSV | 4 | 3 | 2xl |
| New scan (detail) | 4 | 2 | 2xl |

**Proposal:** Two button tiers:

| Tier | Classes | Use |
|------|---------|-----|
| **Primary (CTA)** | `rounded-xl bg-cyan-500 px-5 py-2.5 text-sm font-semibold text-slate-950 hover:bg-cyan-400 transition-colors` | Scan, Re-scan, Scan again |
| **Secondary** | `rounded-xl border border-slate-700 bg-slate-800 px-4 py-2.5 text-sm text-slate-200 hover:bg-slate-700 transition-colors` | Download CSV, New scan, theme toggle |

Both tiers use `py-2.5` for vertical centering. Primary is slightly wider (`px-5`) to signal importance. Both use `rounded-xl` (not 2xl) for a more professional look.

### 5.2 Empty State Standardization

**Current state:** Six different empty state patterns with varying padding, text colors, and alignment.

**Proposal:** Single empty state component:

```html
<div class="rounded-xl border border-dashed border-slate-700 bg-slate-900/50 p-8 text-center">
  <p class="text-sm text-slate-500">{message}</p>
</div>
```

- Always `p-8`, always centered, always `text-slate-500 text-sm`
- Consistent across: no recent scans, no source breakdown, no query provided, scan errors
- Error states use `text-rose-400` instead of `text-slate-500`

### 5.3 Card Padding Unification

**Current state:** Cards use `p-4`, `p-5`, `p-6` with no apparent pattern.

**Proposal:**

| Card Level | Padding | Examples |
|------------|---------|----------|
| Main content cards | `p-6` | Verdict, source breakdown section, evidence section |
| Sidebar cards | `p-5` | Recent scans, tip of day, scan actions |
| Inner items | `p-4` | Source cards, evidence items, SHAP panel, inline preview |

### 5.4 Card Border Radius Unification

**Current state:** Mix of `rounded-3xl`, `rounded-2xl`, `rounded-xl`, `rounded-lg`, `rounded`.

**Proposal:**

| Element | Radius |
|---------|--------|
| Main cards | `rounded-2xl` |
| Inner items | `rounded-xl` |
| Pills/badges | `rounded-full` |
| Buttons | `rounded-xl` |

Remove `rounded-3xl` (too bubbly for a security tool) and `rounded` (too subtle). This matches the VirusTotal aesthetic — clean, professional, slight rounding but not cartoonish.

### 5.5 Detection Counter Unification

**Current state:**
- Verdict card: `rounded-2xl border border-white/10 bg-black/15 p-4` (bordered, spacious)
- Inline preview: `rounded-lg bg-red-950/40 px-2 py-1.5 text-red-300` (flat, compact)

**Proposal:** Same pattern, scaled:

| Location | Classes |
|----------|---------|
| Verdict card | `rounded-xl bg-{color}-950/30 p-4` |
| Inline preview | `rounded-lg bg-{color}-950/30 px-2 py-1` |

Both use `font-mono` for the count number to make numbers pop.

---

## 6. Category 4: Data Science ↔ Backend Consistency

### 6.1 Column Naming Convention Mismatch

**Current state:**

| Convention | Data Science `data/raw/` | Backend `data/` |
|-----------|-------------------------|-----------------|
| OTX | `snake_case` (`malicious_votes`) | `Title_Case` (`Malicious_Votes`) |
| CVE | `snake_case` (`cve_id`) | `camelCase` (`cveID`) — inconsistent |
| Domains | `snake_case` (`domain_length`) | `Title_Case` (`Domain_Length`) |
| IPs | `snake_case` (`tor_node`) | `Title_Case` (`Tor_Node`) |

**Additional mismatches:**
- Backend IPs have `Data_Source`, `Enrichment_Breakdown` columns not in data science raw
- Backend CVE has `cvss_v3_score`, `cvss_v3_vector` columns not in data science raw
- `unmodified_raw/` uses `TOR_Node` (all caps) while working `data/` uses `Tor_Node`

**Proposal:**
- **Standardize on Title_Case** for all backend-facing data (already the dominant convention)
- Fix CVE anomaly: `cveID` → `Cve_ID`, `vendorProject` → `Vendor_Project`
- Fix `TOR_Node` → `Tor_Node` in `unmodified_raw/`
- The `standardize_columns()` function in notebook 01 is a no-op for snake_case and should be removed
- Backend export endpoints should produce enriched CSVs that include `Data_Source`, `Enrichment_Breakdown`, `cvss_v3_score`, `cvss_v3_vector`

### 6.2 Orphan Artifact Cleanup

| Artifact | Status | Action |
|----------|--------|--------|
| `otx_ensemble_config.joblib` | Exists but never generated by current notebook | Verify if backend references it. If not, delete. |
| `otx_attackids_tfidf_ovr_logreg.joblib` | Referenced by `modeling_service.py:213` but doesn't exist | Either create from notebook or handle `None` gracefully |
| `src/modeling.py` | 7-line legacy stub for deleted CodeBERT path | Delete |
| `src/evaluation.py` | Generic helpers not imported by any notebook | Delete or integrate |

---

## 7. Category 5: Loading States & Micro-Interactions

### 7.1 Section-Specific Loading Skeletons

**Current state:** Single block of generic rounded rectangles. Users see the same pulsing shapes regardless of what's loading.

**Proposal:** Replace with section-specific skeletons that mirror actual content shape:

```
[Verdict skeleton]          [Sidebar skeleton]
┌──────────────────┐        ┌──────────────────┐
│ ████████████████ │        │ Recent scans     │
│ ██████████  8.5  │        │ ┌──────────────┐ │
│ █████████████░░░ │        │ │ ████ ████    │ │
│                  │        │ │ ████ ████    │ │
│ ┌────┐ ┌────┐   │        │ └──────────────┘ │
│ │ 8  │ │ 2  │   │        │ ┌──────────────┐ │
│ └────┘ └────┘   │        │ │ ████ ████    │ │
└──────────────────┘        │ └──────────────┘ │
                            └──────────────────┘
[Source breakdown]
┌──────────────────┐
│ Source breakdown │
│ ┌──────┐┌──────┐│
│ │ ████ ││ ████ ││
│ │ ████ ││ ████ ││
│ └──────┘└──────┘│
└──────────────────┘
```

- Each section has its own skeleton matching its final shape
- Add progress indicator: "Querying APIs... (3/11)" with animated dots
- Staggered fade-in: verdict loads first, then sources, then evidence
- Use `transition-opacity` for smooth reveal

### 7.2 Confidence Bar Entry Animation

**Current state:** Confidence bars use `transition-all` which animates width changes but has no initial animation.

**Proposal:** When the verdict card first renders, the confidence bar animates from 0% to its final width over 600ms with `ease-out` timing. This creates a "loading complete" visual cue.

```
transition-[width] duration-600 ease-out
```

### 7.3 Score Pill Color Coding

**Current state:** Scores displayed as plain text pills: `Score 8.5`. No visual indicator of severity.

**Proposal:** Background color based on value:

| Score Range | Classes |
|-------------|---------|
| ≥ 7.0 | `bg-red-500/10 text-red-300 ring-1 ring-red-500/20` |
| 4.0–6.9 | `bg-amber-500/10 text-amber-300 ring-1 ring-amber-500/20` |
| < 4.0 | `bg-emerald-500/10 text-emerald-300 ring-1 ring-emerald-500/20` |
| null | `bg-slate-800 text-slate-400` |

---

## 8. Category 6: Transitions & Animations

### 8.1 Animation Token System

**Current state:** Animation durations and easing functions are scattered across the codebase with no shared constants. Loading skeletons use CSS `animate-pulse` (1.5s), confidence bars use `transition-all duration-300`, score pills have no animation at all.

**Proposal:** Define a shared animation token system:

| Token | Value | Usage |
|-------|-------|-------|
| `duration-fast` | 150ms | Hover states, micro-interactions |
| `duration-normal` | 300ms | Confidence bar fill, score pill reveal |
| `duration-slow` | 600ms | Verdict card entrance, page section fade-in |
| `easing-default` | `ease-out` | Element entrance, bar fills |
| `easing-enter` | `cubic-bezier(0.16, 1, 0.3, 1)` | Staggered section entrance (overshoot) |
| `easing-exit` | `ease-in` | Element removal, error state shake |

- Applied via Tailwind utility classes: `transition-all duration-300 ease-out`
- Tokens are documented as CSS custom properties in `tailwind.css` for maintainability

### 8.2 `prefers-reduced-motion` Support

**Current state:** No accessibility consideration for motion preferences. Animations play unconditionally.

**Proposal:** Wrap all transitions in `@media (prefers-reduced-motion: no-preference)`:

```css
@media (prefers-reduced-motion: reduce) {
  .verdict-band, .skeleton, .confidence-bar {
    animation: none !important;
    transition: none !important;
  }
}
```

- All `animate-pulse` skeletons reduce to static grey blocks
- Confidence bars snap to final width instantly
- Entrance animations (fade-in, slide-up) skip to final state
- This is a WCAG 2.1 AA requirement (Success Criterion 2.3.3)

### 8.3 Per-Element Animation Catalog

**Proposal:** Define exactly what animates, when, and how:

| Element | Trigger | Animation | Duration | Easing |
|---------|---------|-----------|----------|--------|
| Verdict card | Page load | Fade-in + slide-up (20px) | 600ms | `ease-out` |
| Confidence bar | After verdict render | Width 0% → final % | 600ms | `ease-out` |
| Source cards (n) | Sequential delay (100ms each) | Fade-in + scale 0.98→1 | 400ms | `easing-enter` |
| Evidence groups | After source cards | Fade-in | 300ms | `ease-out` |
| Score pill | On render | Scale 0.8→1 + color tint | 300ms | `ease-out` |
| Error state | On API failure | Shake (translateX ±5px) | 300ms | `ease-in-out` |
| Skeleton → content | Loading complete | Opacity crossfade (0→1) | 200ms | `ease-out` |

- No animation chain exceeds 2s total to avoid perceived slowness
- Staggered delays are applied via inline `style="animation-delay: {n}ms"` in JS

### 8.4 Page Transition Strategy

**Current state:** Full page navigations (index → results → details) use standard browser navigation — no transition, no visual continuity.

**Proposal:**
- Replace with SPA-style navigation (already planned in Section 3.1 / fix page reload bug)
- On pushState: fade-out current page (150ms), render new route, fade-in (300ms)
- The query indicator passes through: "doubleclick.net" stays visible in header during transition
- No slide transitions (adds complexity, no security-tool value)

### 8.5 Error State & Exit Animations

**Current state:** Errors (500, timeout, rate limit) appear as static red text — no visual urgency difference from normal content.

**Proposal:**
- API errors: Card shake animation on the affected source card (not the whole page)
- Timeout: Pulse effect (opacity 1→0.7→1 over 1.5s) on the loading source card
- Rate limit: Subtle red border flash on the scan button
- No exit animations for removed elements (simplifies state management in vanilla JS)

**Effort:** 2–3 hours  
**Impact:** Medium — accessibility compliance + perceived performance

---

## 9. Category 7: Light Mode Decision

### 9.1 Current State

Light mode is **functionally broken**. `theme.js` only swaps `<body>` classes. All JS-rendered content uses hardcoded dark-mode classes (`bg-slate-900`, `text-white`, `border-slate-800`). Switching to light mode produces white text on white backgrounds.

### 9.2 Options

| Option | Effort | Risk | Recommendation |
|--------|--------|------|----------------|
| **A: Remove light mode** | 30 min | None | **Recommended** |
| B: Fix light mode properly | 2–3 hrs | High (40+ class changes, regression risk) | Not recommended |

**Rationale for removal:**
- ThreatLensAI is a security tool — dark mode is the industry standard (VirusTotal, AbuseIPDB, Shodan all default to dark)
- Light mode adds code complexity for zero practical value
- Every JS-rendered element would need `dark:` variants (`bg-slate-100 dark:bg-slate-900`, etc.)
- The fix is tedious, error-prone, and must be redone every time a new UI component is added

**If removing:** Delete `theme.js`, remove all `[data-theme-toggle]` buttons from HTML, remove `.light` class logic from `tailwind.css`. Save ~50 lines.

---

## 10. Pre-Implementation Backup Strategy

### 10.1 Rationale

The current plan edits ~250 lines across 7+ files with zero safety net. If any change breaks the frontend (e.g., the verdict card redesign introduces a DOM structure that `ui.js` can't render into), there is no quick rollback path. This section defines the backup procedure that must be executed **before any code changes** begin.

### 10.2 Git Snapshot

- Create a git tag or branch before any modifications:
  ```bash
  git checkout -b rc2-pre-ui-backup
  git tag -a rc2-pre-ui -m "Pre-RC2 UI backup snapshot"
  ```
- The tag serves as the definitive rollback point

### 10.3 "Clean" Backup Definition

Exclude from backup (these are generated or synced elsewhere):

| Path | Reason |
|------|--------|
| `__pycache__/` | Bytecode cache, auto-generated |
| `.venv/` or `venv/` | Virtual environment, recreate via `requirements.txt` |
| `.ipynb_checkpoints/` | Jupyter auto-save, no source value |
| `node_modules/` | NPM packages, recreate via `package.json` |
| `*.joblib` | ML artifacts, synced from `data_science/outputs/artifacts/` |

Include in backup (all files at risk of modification):

### 10.4 Snapshot Manifest

Files that will be modified, with current line counts:

| File | Lines | Risk Level |
|------|-------|------------|
| `frontend/assets/js/ui.js` | ~1,119 | **High** — major DOM restructuring |
| `frontend/index.html` | 112 | Medium — header, grid ratio changes |
| `frontend/results.html` | 38 | Low — model health bar removal |
| `frontend/details.html` | 38 | Low — back button, header |
| `frontend/assets/css/tailwind.css` | 81 | Low — dead class removal |
| `frontend/assets/js/theme.js` | 46 | Medium — deletion if removing light mode |

**Safe deletions** (no rollback needed):
- `data_science/src/modeling.py` — dead stub (7 lines)
- `data_science/src/evaluation.py` — orphaned helpers (40 lines)
- `data_science/notebooks/04_overhaul.ipynb` — empty shell

### 10.5 Rollback Procedure

```bash
# Full rollback to snapshot
git checkout rc2-pre-ui -- .

# Selective file restore (e.g., if only ui.js breaks)
git checkout rc2-pre-ui -- threat-lens-ai/frontend/assets/js/ui.js

# Diff review before committing rollback
git diff rc2-pre-ui -- threat-lens-ai/frontend/assets/js/ui.js
```

**Effort:** 30 minutes (one-time setup)  
**Impact:** **Critical** — safety net for all subsequent changes

---

## 11. All-Inclusive Benchmarks

**Current state:** The plan says "Transform ThreatLensAI from functional prototype to polished tool" but defines no quantifiable success criteria. This section establishes measurable benchmarks that must be verified before RC2 is considered complete.

### 11.1 Performance Benchmarks

| Metric | Target | Measurement Method | Notes |
|--------|--------|-------------------|-------|
| First Contentful Paint | < 1.5s | Chrome DevTools Performance tab | Local dev server; baseline with cold cache |
| Total JS bundle size | < 30KB | Get-ChildItem -Recurse *.js \| Measure-Object -Property Length -Sum | Currently ~1,245 lines across 4 files |
| CSS file size | < 5KB | Same method for `tailwind.css` | Tailwind CDN classes excluded (loaded remotely) |
| DOM node count (results page) | < 500 | `document.querySelectorAll('*').length` | After all sources rendered |
| Lighthouse Performance | > 90 | Chrome Lighthouse (local mode) | Hard on localhost; focus on code metrics instead |

### 11.2 Accessibility Benchmarks

| Criterion | Target | Verification |
|-----------|--------|-------------|
| `prefers-reduced-motion` | All animations respect it | Toggle OS accessibility setting, verify no motion |
| Keyboard navigation | All interactive elements reachable via Tab | Tab through scan form, results, detail page |
| Screen reader labels | All icons have `aria-label` or `sr-only` text | Check renderEvidence, renderSourceBreakdown output |
| Color contrast | WCAG 2.1 AA (4.5:1 normal, 3:1 large) | Check contrast-checker on verdict tags, pills, badges |
| Focus indicators | Visible focus ring on all interactive elements | Tab through page, verify `focus:ring-2` visible |

### 11.3 Consistency Benchmarks

| Criterion | Target | Verification |
|-----------|--------|-------------|
| Hardcoded dark-mode classes | **Zero** (if light mode removed) | Search for `bg-slate-900`/`text-white`/`border-slate-800` in ui.js |
| Button padding | Identical across all pages | Visual inspection of Scan, Re-scan, Download CSV |
| Card border radius | `rounded-2xl` on all main cards, `rounded-xl` on inner items | Visual inspection across all 3 pages |
| Empty states | One pattern (`p-8 centered text-slate-500`) | Check all empty state paths |

### 11.4 Visual Benchmarks

| Item | Method |
|------|--------|
| Before/after screenshot (index.html) | Screenshot current → screenshot modified → side-by-side |
| Before/after screenshot (results.html) | Same — verify verdict band, source grid, evidence groups |
| Before/after screenshot (details.html) | Same — verify timeline, re-scan button, metadata icons |
| Mobile layout (< 768px) | Chrome DevTools responsive mode — no horizontal scroll, stacks gracefully |
| Tablet layout (768-1024px) | Same — 2-column grid holds, no overlap |

### 11.5 Data Science Column Audit

| Check | Method |
|-------|--------|
| Backend CSVs use `Title_Case` | Check column headers in `backend/data/` |
| Data science raw CSVs use `snake_case` | Check column headers in `data_science/data/raw/` |
| Export endpoint produces `Title_Case` | `curl /model/export/ip \| head -1` |
| `unmodified_raw/` matches `data/` naming | Compare column headers; fix `TOR_Node` → `Tor_Node` |
| CVE columns consistent | No `cveID` or `vendorProject` — use `Cve_ID`, `Vendor_Project` |

**Effort:** 1–2 hours to verify  
**Impact:** **High** — prevents subjective "is it done?" debates

---

## 12. Priority Ranking & Effort Estimate

**Updated with new sections:**

| Priority | Item | Category | Effort | Impact |
|----------|------|----------|--------|--------|
| P0 | 4.1 — Verdict card redesign (solid color band) | Hierarchy | 3–4 hrs | **High** |
| P0 | 3.1 — Header standardization | Navigation | 1–2 hrs | **High** |
| P0 | 10 — Pre-implementation backup | Safety | 30 min | **Critical** |
| P1 | 4.2 — Source card type differentiation | Hierarchy | 2–3 hrs | **Medium** |
| P1 | 5.1–5.5 — Button/empty state/padding/radius unification | Consistency | 2–3 hrs | **Medium** |
| P1 | 3.5 — Dead code cleanup | Navigation | 1 hr | **Medium** |
| P2 | 4.3 — Evidence grouping by type | Hierarchy | 2–3 hrs | **Medium** |
| P2 | 7.1 — Section-specific loading skeletons | Micro-UX | 2–3 hrs | **Medium** |
| P2 | 6.1–6.2 — Column naming + artifact consistency | DS↔Backend | 2–4 hrs | **Medium** |
| P2 | 8 — Transitions & animations | Micro-UX | 2–3 hrs | **Medium** |
| P3 | 9 — Light mode removal | Cleanup | 30 min | **Low** |
| P3 | 3.2–3.4 — Back button, grid ratio, model health bar | Navigation | 1 hr | **Low** |
| P3 | 7.2–7.3 — Bar animation, score coloring | Micro-UX | 1 hr | **Low** |

**Total: 21–32 hours (previously 18–28)**

---

## 13. File Change Manifest

### Frontend Files

| File | Changes | Est. Lines Changed |
|------|---------|-------------------|
| `index.html` | Remove `data-api-base`, remove tech badge, standardize header, change grid ratio, change card radius | ~20 |
| `results.html` | Remove dead `modelHealthBar` div, remove `data-api-base`, standardize header, change grid ratio | ~15 |
| `details.html` | Remove `data-api-base`, fix Back button query loss, standardize header | ~15 |
| `tailwind.css` | Remove `.card-shadow`, remove `.verdict-*` gradient classes (if solid bands used) | ~20 |
| `theme.js` | Delete entirely (if removing light mode) | -46 |
| `ui.js` | Verdict card redesign, source card differentiation, evidence grouping, button/padding/radius unification, empty state standardization, loading skeleton enhancement, score coloring, remove light mode references | ~200 |
| `api.js` | Remove `data-api-base` fallback path | ~5 |

### Data Science Files

| File | Changes | Est. Lines Changed |
|------|---------|-------------------|
| `data_science/src/modeling.py` | Delete | -7 |
| `data_science/src/evaluation.py` | Delete or integrate | -40 |
| `data_science/notebooks/04_overhaul.ipynb` | Delete or populate | varies |

### Backend Files (Column Naming)

| File | Changes | Est. Lines Changed |
|------|---------|-------------------|
| Backend CSV files | Rename `cveID` → `Cve_ID`, `vendorProject` → `Vendor_Project` | ~5 per file |
| `unmodified_raw/` CSVs | Rename `TOR_Node` → `Tor_Node` | ~1 per file |

---

## 14. Pre-RC2 Final Cleanup Checklist

**Must pass 100% before marking RC2 complete.**

| # | Criterion | Verification Method |
|---|-----------|-------------------|
| 1 | Visual regression check | Manual side-by-side comparison of before/after screenshots for all 3 pages |
| 2 | JS console errors | Zero errors on index, results, and details pages (Chrome DevTools Console) |
| 3 | Cross-browser check | Chrome, Firefox, Edge — no layout breakage or JS failures |
| 4 | Responsive check | Mobile (< 768px), tablet (768–1024px), desktop (> 1024px) — no horizontal scroll |
| 5 | Light mode removal | No dangling `theme.js` references, no `[data-theme-toggle]` in HTML, no `.light` CSS |
| 6 | Dead code removal | No orphaned imports, no unused variables, no `data-api-base` attributes |
| 7 | Column naming audit | Zero mismatches between `backend/data/` (Title_Case) and `data_science/data/raw/` (snake_case) |
| 8 | Git status clean | `git status` shows only intended files modified; `__pycache__/`, `.joblib`, `.venv/` not tracked |
| 9 | Backup tag exists | `git tag -l rc2-pre-ui` returns the tag; rollback procedure documented and tested |
| 10 | All benchmark targets met | Section 11 benchmarks: bundle size < 30KB, contrast AA, keyboard nav, etc. |

**Any failure → fix root cause, re-verify. RC2 is complete only when all 10 criteria pass.**

---

## 15. Industry Reference Patterns

### VirusTotal Report Architecture

1. **Detection ratio as largest element** — "49 / 70" in giant text
2. **Colored header band** — red/orange/green background spanning full width
3. **Engine list in grid** — each engine is a row with icon + verdict + details
4. **Tabs for Details / Relations / History** — progressive disclosure
5. **Reanalyze button** prominent in header

### AbuseIPDB Report Architecture

1. **Abuse confidence score as circular gauge** — 0–100% with color coding
2. **Geographic + ISP info in sidebar** — metadata separated from verdict
3. **Recent reports as timeline** — chronological, expandable
4. **Category badges** — color-coded abuse categories (port scan, brute force, etc.)

### Shodan Report Architecture

1. **IP + ISP + OS as header** — identifier-first layout
2. **Service ports as expandable cards** — each port is a collapsible section
3. **Vulnerability list with CVSS scores** — severity-weighted
4. **History timeline** — when was this IP last seen, what changed

### Cybersecurity Dashboard Best Practices (2026)

- **Build for scanning, not reading** — users glance, they don't read
- **Critical metrics in top-left** — primary focus area
- **Group related data points** — compare at a glance
- **Use size/position/white space to signal importance** — not just color
- **Avoid color-only encoding** — pair with icons, labels, patterns
- **Role-aware design** — different views for different user types

---

*This plan is ready for review. Implementation should follow the priority ranking: P0 items first (verdict redesign + header standardization), then P1 polish, then P2 enhancements, then P3 cleanup.*
