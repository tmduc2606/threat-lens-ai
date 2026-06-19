# Cumulative Update 4 — Source Card Polish & Light Mode Consistency

**Date:** 2026-05-29 (final)  
**Scope:** Fix UI/UX issues from visual audit of `logs/visual_logs_issue/` screenshots  
**Status:** All 18 items DONE (including badge overflow, vertical spacing, grid responsiveness)

---

## 1. Implementation Progress — What's DONE

Screenshots in `logs/visual_logs_issue/{night,light}/` across 5 scan types:
- `hal-cert.com` (DOMAIN — 1 source)
- `113.141.73.248` (IP — 3 sources)
- `CVE-2026-9950` (CVE — 1 source, Reference record)
- `nexus-posta.com` (DOMAIN — 1 source, CLEAN)
- `172.233.115.32` (IP — 2 sources)

### Confirmed Done (code + screenshot evidence)

| # | Item | File/Line | Evidence |
|---|------|-----------|----------|
| 1 | Model Health unwrap (index page) | `ui.js:930-931` | `resp.models \|\| resp` — screenshots show "5/5 active" on index |
| 2 | Model Health unwrap (detail page) | `ui.js:1256-1258` | Same fix applied |
| 3 | Card padding `p-5` | `ui.js:300` | Cards visibly have 20px internal padding |
| 4 | Card ring `ring-1 ring-slate-800/30` | `ui.js:300` | Ring visible in dark mode, light override in CSS |
| 5 | Header flex-wrap `items-start flex-wrap` | `ui.js:301` | Badge + source type don't overlap |
| 6 | Badge `shrink-0` | `ui.js:311` | Badge stays compact on long names |
| 7 | Note `title` attribute (hover tooltip) | `ui.js:313` | `title="..."` present in code |
| 8 | Score bar `h-3` (12px) | `ui.js:317-318` | Bars clearly visible in all screenshots |
| 9 | Score bar track `bg-slate-800/70` | `ui.js:317` | Track visible in dark, light override in CSS |
| 10 | Confidence separator `border-t` | `ui.js:323` | `mt-3 pt-3 border-t border-slate-800/50` |
| 11 | ML card `p-5 ring-slate-800/30` | `ui.js:356` | Consistent with source cards |
| 12 | Dynamic grid cols (1 vs 2) | `ui.js:284-285` | Single-source scans use `md:grid-cols-1` |
| 13 | CI text `text-white/90` | `ui.js:185` | Better contrast on verdict band |
| 14 | Tip card `tip-card` class | `ui.js:492` | Class added to container |
| 15 | Light mode source card tints | `tailwind.css:96-99` | 4 tint overrides present |
| 16 | Light mode ring/scorebar/border overrides | `tailwind.css:100-102` | All 3 overrides present |
| 17 | Light mode tip-card bg | `tailwind.css:105` | `#f1f5f9` bg + `#e2e8f0` border |

---

## 2. Remaining Issue — Source Breakdown Card Grid Responsiveness

### Problem Statement

When 2+ source cards appear in the Source Breakdown section, the cards **do not behave responsively**:
- Cards in the same row have **unequal heights** (shorter card leaves dead space below)
- With 3 sources, the **3rd card breaks to a new row alone** creating asymmetric layout
- The overall section feels "mentally broken" — tight spacing, unbalanced visual weight

### Root Cause Analysis

The grid at `ui.js:284-285` uses `md:grid-cols-2` but lacks:

1. **`items-stretch`** — Cards in the same row don't equalize height. The AbuseIPDB card with a long note is taller than the RDAP card, leaving dead space below the shorter card.

2. **Responsive column count for 3+ items** — When 3 API items exist (AbuseIPDB + VirusTotal + RDAP), all go into a `md:grid-cols-2` grid. Row 1 has 2 cards, row 2 has 1 card alone. On a `lg:grid-cols-[1.3fr_0.7fr]` layout at 1280px, the left column is ~768px — three cards at ~240px each + gaps would fit in 3 columns.

3. **`min-w-0`** missing on cards — Content can force cards wider than the column width.

### Screenshot Evidence

| Screenshot | Sources | Layout Problem |
|------------|---------|----------------|
| Night `{B8A5A89D}` IP 113.141.73.248 | 3 (AbuseIPDB + VirusTotal + RDAP) | Row 1: 2 cards side by side. Row 2: RDAP alone — shorter card, dead space above it |
| Light `{212BA95E}` IP 172.233.115.32 | 2 (AbuseIPDB + RDAP) | Side by side but height mismatch — AbuseIPDB taller, dead space below RDAP |
| Night `{EBF10A05}` IP 113.141.73.248 | 3 (scroll view) | Same 2+1 layout, RDAP card visibly shorter than AbuseIPDB/VirusTotal row |

### Fix

**File:** `ui.js`

#### renderSourceBreakdown() — lines 284-285

Current:
```javascript
+ (apiHtml ? '<div class="mt-3 grid gap-3 ' + (apiItems.length === 1 ? 'md:grid-cols-1' : 'md:grid-cols-2') + ' animate-slideUp stagger-1">' + apiHtml + "</div>" : "")
+ (otherHtml ? '<div class="mt-3 grid gap-3 ' + (otherItems.length === 1 ? 'md:grid-cols-1' : 'md:grid-cols-2') + ' animate-slideUp stagger-2">' + otherHtml + "</div>" : "");
```

Replace with:
```javascript
+ (apiHtml ? '<div class="mt-3 grid gap-3 items-stretch ' + (apiItems.length === 1 ? 'md:grid-cols-1' : apiItems.length === 2 ? 'md:grid-cols-2' : 'md:grid-cols-2 lg:grid-cols-3') + ' animate-slideUp stagger-1">' + apiHtml + "</div>" : "")
+ (otherHtml ? '<div class="mt-3 grid gap-3 items-stretch ' + (otherItems.length === 1 ? 'md:grid-cols-1' : otherItems.length === 2 ? 'md:grid-cols-2' : 'md:grid-cols-2 lg:grid-cols-3') + ' animate-slideUp stagger-2">' + otherHtml + "</div>" : "");
```

#### renderSourceCard() — line 300

Replace `min-w-0` with `overflow-hidden` (min-w-0 caused badge text to overflow card on narrow columns). Add `truncate` on text elements inside the left side. Increase vertical spacing:
```javascript
+ '<div class="rounded-2xl border-l-4 overflow-hidden ' + sourceBorderClass(st) + ' ' + bgTint + ' p-5 ring-1 ring-slate-800/30">'
```

Changes inside `renderSourceCard()`:
- Card container: `min-w-0` → `overflow-hidden` (prevents badge overflow without constraining min-width)
- Left side wrapper: add `min-w-0` on the `<div class="flex items-center gap-2">` and `<div>` children
- Source type text: add `truncate` class
- Engine text: add `truncate` class  
- Note spacing: `mt-3` → `mt-4`
- Score section spacing: `mt-3` → `mt-4`
- Confidence separator: `mt-3 pt-3` → `mt-4 pt-3`

#### renderMlCard() — line 356

Same fixes — `min-w-0` → `overflow-hidden`, header gets `flex-wrap` + `items-start`, engine badge gets `shrink-0`, summary gets `truncate`, all `mt-3` gaps → `mt-4`:
```javascript
+ '<div class="rounded-2xl border-l-4 overflow-hidden ' + sourceBorderClass(st) + ' bg-violet-500/5 p-5 ring-1 ring-slate-800/30">'
```

---

## 3. Summary of Changes Applied

| File | Line | Change |
|------|------|--------|
| `ui.js` | 284 | Add `items-stretch` + 3-col grid for 3+ items: `(apiItems.length === 1 ? 'md:grid-cols-1' : apiItems.length === 2 ? 'md:grid-cols-2' : 'md:grid-cols-2 lg:grid-cols-3')` |
| `ui.js` | 285 | Same pattern for `otherHtml` |
| `ui.js` | 300 | `min-w-0` → `overflow-hidden` on card; left side gets `min-w-0` + `truncate` |
| `ui.js` | 301 | Header `items-center` → `items-start` + `flex-wrap` |
| `ui.js` | 305-306 | `truncate` on source type and engine text |
| `ui.js` | 311 | `shrink-0` on badges |
| `ui.js` | 313 | note `mt-3` → `mt-4` |
| `ui.js` | 314 | score section `mt-3` → `mt-4` |
| `ui.js` | 323 | confidence `mt-3 pt-3` → `mt-4 pt-3` |
| `ui.js` | 356 | `min-w-0` → `overflow-hidden` on ML card; header `items-start flex-wrap`; engine `shrink-0`; summary `truncate` |
| `ui.js` | 369,380,386 | ML card `mt-3` → `mt-4` |

**Total changes:** ~18 line edits across `renderSourceCard()` and `renderMlCard()`

---

## 4. Verification (5 criteria)

| # | Criterion | Test |
|---|-----------|------|
| 1 | 3-source IP scan: all 3 cards in one row on 1280px+ | Visual: no card breaks to new row alone |
| 2 | 2-source IP scan: cards equal height in same row | Visual: no dead space below shorter card |
| 3 | 1-source domain scan: single column, no empty space | Visual: card fills full width |
| 4 | Cards have adequate vertical spacing (`mt-4` between sections) | Visual: note, score bar, confidence have distinct separation |
| 5 | Badge text never overflows card boundary | Visual: "INFORMATIONAL" fits inside card on all viewport sizes |
