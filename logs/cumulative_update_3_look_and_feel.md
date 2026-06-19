# Cumulative Update 3 — Look-and-Feel Improvement Plan

> **Scope:** Visual fixes identified from screenshots + Dark/Light Mode implementation  
> **Date:** 2026-05-29  
> **Status:** Proposal  
> **Prerequisite:** RC2 UI/UX Overhaul complete

---

## Table of Contents

1. [Screenshot Analysis](#1-screenshot-analysis)
2. [Issue 1: Verdict Band Color Not Applying](#2-issue-1-verdict-band-color-not-applying)
3. [Issue 2: Dark / Light Mode Toggle](#3-issue-2-dark--light-mode-toggle)
4. [Issue 3: Source Card Visual Refinements](#4-issue-3-source-card-visual-refinements)
5. [Issue 4: Confidence Bar Visibility](#5-issue-4-confidence-bar-visibility)
6. [Issue 5: Minor Visual Polish](#6-issue-5-minor-visual-polish)
7. [Implementation Order](#7-implementation-order)
8. [File Change Manifest](#8-file-change-manifest)
9. [Verification](#9-verification)

---

## 1. Screenshot Analysis

Five screenshots were reviewed from `logs/visual_logs_issue/`. Here is what each reveals:

### Screenshot 1: IP Source Breakdown (3 sources)

**What works:**
- Source cards have left-border accent (cyan for API)
- Verdict badges are opaque and readable (SUSPICIOUS in orange, MALICIOUS in red, INFORMATIONAL in gray)
- Score bars render correctly with cyan fill
- Confidence labels display (MEDIUM, LOW)

**Issues found:**
- Source card backgrounds are very dark — the `bg-cyan-500/5` tint is nearly invisible on `bg-slate-950`
- "Dataset engines" label in top-right of section header is misleading — these are live API sources, not dataset engines
- Score bar for RDAP shows 0.0 with no fill — acceptable but the bar track is barely visible

### Screenshot 2: CVE Source Breakdown (1 source)

**What works:**
- "Reference" badge renders correctly in gray
- CVE note text is readable

**Issues found:**
- CVE card uses `bg-slate-900` (no tint) — correct per plan but visually flat
- Long note text wraps awkwardly — no line-clamp or truncation

### Screenshot 3: DOMAIN Source Breakdown (1 source)

**What works:**
- VirusTotal card with SUSPICIOUS badge in orange
- Score 2.0 with partial cyan bar

**Issues found:**
- Same background tint invisibility as Screenshot 1

### Screenshot 4: Verdict Card — MALICIOUS 4.8

**What works:**
- Score pill "Score 4.8" renders in orange (correct)
- Detection counters: MALICIOUS 2, SUSPICIOUS 1, CLEAN 0 with colored backgrounds
- "1 sources analyzed" at bottom
- Query "hal-cert.com" in monospace

**Issues found:**
- **CRITICAL: Verdict band is `bg-slate-700` (dark gray) instead of `bg-red-600` (red)**
  - Root cause: `riskBandBgClass(riskBand)` returns `bg-slate-700` when `riskBand` is empty string `""`
  - Empty string `""` is falsy in JS, but `riskBandBgClass("")` returns `"bg-slate-700"` (the default), which is truthy
  - So `riskBandBgClass("") || verdictBandClass("MALICIOUS")` evaluates to `"bg-slate-700"` — the fallback never fires
  - The band should be red for MALICIOUS, orange for SUSPICIOUS, green for CLEAN
- **Confidence bar is missing** — `calibrated_confidence` is null/undefined in the API response
- The "Score 4.8" pill uses `scorePillClass(4.8)` which returns `bg-amber-600 text-slate-950` — correct

### Screenshot 5: Model Health Panel (expanded)

**What works:**
- 5/5 models active indicator with green text
- Color-coded F1 scores: red for <0.50, green for ≥0.80
- Expanded details show Loaded, F1, Samples, Trained date per model
- All 5 models loaded with checkmarks

**Issues found:**
- `ip_logreg_model` shows no F1 score — the detail row just shows "Loaded: ✅" without F1
- "1 sources: DOMAIN(✅)" at bottom — the sources consulted line is correct but the checkmark emoji is raw

---

## 2. Issue 1: Verdict Band Color Not Applying

### Root Cause

In `ui.js:158`:
```js
var bandColor = isOtxCve ? "bg-slate-700" : riskBandBgClass(riskBand) || verdictBandClass(data.verdict);
```

`riskBandBgClass("")` returns `"bg-slate-700"` (the default case at line 141). Since `"bg-slate-700"` is a truthy string, the `||` fallback to `verdictBandClass(data.verdict)` never fires. The band always gets `bg-slate-700` when `risk_band` is empty.

### Fix

Change the condition to explicitly check if `riskBand` has a value:

```js
var bandColor = isOtxCve
  ? "bg-slate-700"
  : (riskBand ? riskBandBgClass(riskBand) : verdictBandClass(data.verdict));
```

This ensures:
- OTX/CVE → always `bg-slate-700` (reference record gray)
- Has risk_band → use risk band color (CRITICAL=red, HIGH=orange, MEDIUM=amber, LOW=slate-600)
- No risk_band → fall back to verdict color (MALICIOUS=red, SUSPICIOUS=orange, CLEAN=emerald)

### Effort: 5 minutes

---

## 3. Issue 2: Dark / Light Mode Toggle

### Current State

- `theme.js` was deleted in RC2
- No toggle button exists in any page header
- `<html class="dark">` is hardcoded
- `tailwind.css` has an inert `html.light { color-scheme: light; }` stub
- All JS-rendered content uses hardcoded dark-mode classes

### Decision

The user explicitly requested dark/light mode. This contradicts the RC2 plan recommendation to remove it. **Implementing it properly.**

### Architecture

Since all UI is vanilla JS with Tailwind CDN (no build step, no `dark:` variants in templates), the approach is:

1. **Add `dark` class toggle on `<html>`** — Tailwind CDN supports `darkMode: 'class'`
2. **Use Tailwind `dark:` variants** on all JS-rendered elements
3. **Persist choice in `localStorage`**
4. **Respect `prefers-color-scheme`** as default

### Implementation

#### Step 1: Configure Tailwind for class-based dark mode

In all 3 HTML pages, update the inline `tailwind.config`:

```js
tailwind.config = {
  darkMode: 'class',
  theme: {
    extend: {
      boxShadow: {
        glow: "0 0 0 1px rgba(148, 163, 184, 0.12), 0 16px 40px rgba(0, 0, 0, 0.35)"
      }
    }
  }
}
```

#### Step 2: Create `theme.js` (new file)

```js
(function () {
  function getPreferredTheme() {
    var saved = localStorage.getItem("threatlens_theme");
    if (saved) return saved;
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  function applyTheme(theme) {
    var html = document.documentElement;
    if (theme === "dark") {
      html.classList.add("dark");
      html.classList.remove("light");
    } else {
      html.classList.add("light");
      html.classList.remove("dark");
    }
    localStorage.setItem("threatlens_theme", theme);
    syncButtons(theme);
  }

  function syncButtons(theme) {
    document.querySelectorAll("[data-theme-toggle]").forEach(function (btn) {
      btn.textContent = theme === "dark" ? "☀️ Light" : "🌙 Dark";
      btn.setAttribute("aria-pressed", theme === "dark");
    });
  }

  function init() {
    var theme = getPreferredTheme();
    applyTheme(theme);

    document.addEventListener("click", function (e) {
      var btn = e.target.closest("[data-theme-toggle]");
      if (!btn) return;
      var current = document.documentElement.classList.contains("dark") ? "dark" : "light";
      applyTheme(current === "dark" ? "light" : "dark");
    });
  }

  window.ThreatLensTheme = { init: init, applyTheme: applyTheme };
})();
```

#### Step 3: Add toggle button to all 3 page headers

In each HTML `<header>`, add inside the `<div class="flex items-center gap-3">`:

```html
<button data-theme-toggle class="rounded-xl border border-slate-700 bg-slate-800 px-4 py-2 text-sm text-white hover:bg-slate-700">☀️ Light</button>
```

#### Step 4: Add `dark:` variants to `ui.js` templates

The key insight: we need a **theme-aware helper** that returns both light and dark classes. Create a helper function:

```js
function themed(lightClasses, darkClasses) {
  var isDark = document.documentElement.classList.contains("dark");
  return isDark ? darkClasses : lightClasses;
}
```

Then apply to every JS-rendered element. The mapping:

| Element | Dark (current) | Light (new) |
|---------|---------------|-------------|
| Page body | `bg-slate-950 text-slate-100` | `bg-slate-50 text-slate-900` |
| Cards | `bg-slate-900/70 border-slate-800` | `bg-white border-slate-200` |
| Inner items | `bg-slate-900 border-slate-800` | `bg-slate-50 border-slate-200` |
| Text primary | `text-white` | `text-slate-900` |
| Text secondary | `text-slate-300` | `text-slate-600` |
| Text muted | `text-slate-500` | `text-slate-400` |
| Code/mono | `bg-slate-950 text-slate-300` | `bg-slate-100 text-slate-700` |
| Input area | `bg-slate-950` | `bg-white` |

**Approach:** Instead of modifying every template string (200+ changes), use a **CSS custom property strategy**:

```css
:root {
  --bg-page: #020617;          /* slate-950 */
  --bg-card: rgba(15, 23, 42, 0.7);  /* slate-900/70 */
  --bg-card-solid: #0f172a;    /* slate-900 */
  --bg-inner: #0f172a;
  --border-card: #1e293b;      /* slate-800 */
  --text-primary: #f1f5f9;     /* slate-100 */
  --text-heading: #ffffff;
  --text-secondary: #cbd5e1;   /* slate-300 */
  --text-muted: #64748b;       /* slate-500 */
  --bg-code: #020617;
}

html.light {
  --bg-page: #f8fafc;          /* slate-50 */
  --bg-card: rgba(255, 255, 255, 0.9);
  --bg-card-solid: #ffffff;
  --bg-inner: #f8fafc;
  --border-card: #e2e8f0;      /* slate-200 */
  --text-primary: #0f172a;     /* slate-900 */
  --text-heading: #0f172a;
  --text-secondary: #475569;   /* slate-600 */
  --text-muted: #94a3b8;       /* slate-400 */
  --bg-code: #f1f5f9;
}
```

Then replace hardcoded Tailwind classes in `ui.js` with CSS variable references:

```js
// Before:
'<div class="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">'

// After:
'<div class="rounded-2xl border p-5" style="border-color: var(--border-card); background: var(--bg-card);">'
```

This is **fewer changes** than adding `dark:` variants to every template string, and it works with both class-based and media-query-based dark mode.

#### Step 5: Update `tailwind.css`

```css
:root {
  color-scheme: dark;
  --bg-page: #020617;
  --bg-card: rgba(15, 23, 42, 0.7);
  --bg-card-solid: #0f172a;
  --bg-inner: #0f172a;
  --border-card: #1e293b;
  --text-primary: #f1f5f9;
  --text-heading: #ffffff;
  --text-secondary: #cbd5e1;
  --text-muted: #64748b;
  --bg-code: #020617;
  --bg-input: #020617;
}

html.light {
  color-scheme: light;
  --bg-page: #f8fafc;
  --bg-card: rgba(255, 255, 255, 0.9);
  --bg-card-solid: #ffffff;
  --bg-inner: #f8fafc;
  --border-card: #e2e8f0;
  --text-primary: #0f172a;
  --text-heading: #0f172a;
  --text-secondary: #475569;
  --text-muted: #94a3b8;
  --bg-code: #f1f5f9;
  --bg-input: #ffffff;
}

body {
  background: var(--bg-page);
  color: var(--text-primary);
  transition: background-color 0.2s ease, color 0.2s ease;
}
```

### Effort: 4–6 hours

---

## 4. Issue 3: Source Card Visual Refinements

### Problem

The `bg-cyan-500/5` background tints are invisible on the dark background. The cards look flat and undifferentiated.

### Fix

Increase tint opacity from `/5` to `/10`:

```js
// Before (ui.js:289):
var bgTint = st === "ML_PREDICTION" ? "bg-violet-500/5" : st === "API" ? "bg-cyan-500/5" : ...;

// After:
var bgTint = st === "ML_PREDICTION" ? "bg-violet-500/10" : st === "API" ? "bg-cyan-500/10" : ...;
```

Also update the evidence group backgrounds:

```js
// Before (ui.js:454):
var typeColors = { api: "border-cyan-500/20 bg-cyan-500/5", ... };

// After:
var typeColors = { api: "border-cyan-500/20 bg-cyan-500/10", ... };
```

### Effort: 15 minutes

---

## 5. Issue 4: Confidence Bar Visibility

### Problem

The confidence bar in the verdict card only renders when `calibrated_confidence` is present in the API response. When it's null, the bar is completely absent — users see verdict + score but no confidence indicator.

### Fix

Add a **fallback confidence display** when `calibrated_confidence` is null:

```js
// After line 192 (the calConf conditional block), add:
(calConf === null || calConf === undefined) && !isOtxCve
  ? '<div class="mt-4">'
  +   '<div class="flex items-center gap-2 text-xs text-white/50">'
  +     '<span>Confidence: </span>'
  +     '<span class="rounded-full bg-black/30 px-2 py-0.5">' + escapeHtml(data.confidence || "N/A") + '</span>'
  +   '</div>'
  + '</div>'
  : ''
```

This shows a text-based confidence label when the calibrated bar isn't available, so the verdict card never looks empty.

### Effort: 15 minutes

---

## 6. Issue 5: Minor Visual Polish

### 6a. "Dataset engines" label — rename to "Data sources"

The label "Dataset engines" in the source breakdown section header is misleading. These are live API sources, not dataset engines.

```js
// ui.js:1130
'<span class="text-xs text-slate-500">Dataset engines</span>'

// Change to:
'<span class="text-xs text-slate-500">Data sources</span>'
```

### 6b. Source card note truncation

Long notes (like the CVE description in Screenshot 2) wrap awkwardly. Add line-clamp:

```js
// ui.js:305
'<div class="mt-3 text-sm text-slate-300">' + escapeHtml(item.note || ...) + '</div>'

// Change to:
'<div class="mt-3 text-sm text-slate-300 line-clamp-3">' + escapeHtml(item.note || ...) + '</div>'
```

Add to `tailwind.css`:
```css
.line-clamp-3 {
  display: -webkit-box;
  -webkit-line-clamp: 3;
  -webkit-box-orient: vertical;
  overflow: hidden;
}
```

### 6c. `ip_logreg_model` missing F1 in details

The model health details panel shows "Loaded: ✅" without F1 for `ip_logreg_model`. This is a backend issue — the `/model/status` endpoint doesn't return `f1_score` for that model. Not a frontend fix.

### Effort: 30 minutes

---

## 7. Implementation Order

| Phase | Task | Effort | Dependencies |
|-------|------|--------|-------------|
| 1 | Fix verdict band color logic (Issue 1) | 5 min | None |
| 2 | Source card tint opacity fix (Issue 3) | 15 min | None |
| 3 | Confidence bar fallback (Issue 4) | 15 min | None |
| 4 | Minor polish: label rename, line-clamp (Issue 5) | 30 min | None |
| 5 | Dark/Light mode: CSS variables + theme.js (Issue 2) | 4–6 hrs | Phases 1-4 done first |

**Total estimated effort: 5–7 hours**

Phase 5 is the bulk of the work. Phases 1-4 are quick wins that should be done first to avoid merge conflicts with the CSS variable refactor.

---

## 8. File Change Manifest

| File | Changes | Est. Lines Changed |
|------|---------|-------------------|
| `ui.js` | Fix `riskBandBgClass` condition (line 158), bump tint opacity (line 289, 454), add confidence fallback, truncate notes, rename label | ~15 |
| `tailwind.css` | Add CSS custom properties for dark/light, add `.line-clamp-3`, update `body` background | ~40 |
| `theme.js` | **New file** — dark/light toggle logic | ~30 |
| `index.html` | Add `darkMode: 'class'` to Tailwind config, add theme toggle button, load `theme.js` | ~5 |
| `results.html` | Same as index.html | ~5 |
| `details.html` | Same as index.html | ~5 |

---

## 9. Verification

| # | Criterion | Method |
|---|-----------|--------|
| 1 | Verdict band is red for MALICIOUS, orange for SUSPICIOUS, green for CLEAN | Visual: scan a known malicious IP |
| 2 | Verdict band is gray for OTX/CVE (reference records) | Visual: scan a CVE |
| 3 | Dark mode: all cards, text, borders render correctly | Toggle to dark, check all 3 pages |
| 4 | Light mode: all cards, text, borders render correctly | Toggle to light, check all 3 pages |
| 5 | Theme persists across page reload | Set dark, reload, verify still dark |
| 6 | Theme respects OS preference on first visit | Clear localStorage, check `prefers-color-scheme` |
| 7 | Source card tints are visible | Visual: compare before/after on source breakdown |
| 8 | Confidence bar shows when `calibrated_confidence` is present | API response check |
| 9 | Confidence text fallback shows when bar is absent | Visual: scan without calibrated data |
| 10 | "Data sources" label replaces "Dataset engines" | Visual: source breakdown header |
| 11 | Long notes truncated to 3 lines | Visual: CVE source card |
| 12 | Contrast ratios pass in both themes | Run benchmark script in light mode |

---

*This plan is ready for review. Phases 1-4 are quick fixes. Phase 5 (dark/light mode) is the substantial effort.*
