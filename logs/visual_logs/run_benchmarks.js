const puppeteer = require('puppeteer');
const fs = require('fs');
const path = require('path');

const BASE = 'http://localhost:8000';
const PAGES = {
  'index': `${BASE}/index.html`,
  'results': `${BASE}/results.html?q=185.220.101.42`,
  'details': `${BASE}/details.html?type=IP&value=185.220.101.42`,
};

const LOG_DIR = path.resolve(__dirname);
const results = {};

function getContrastColor(bgRgb, fgRgb) {
  // Calculate relative luminance
  const toLinear = c => {
    c = c / 255;
    return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
  };
  const luminance = rgb => 0.2126 * toLinear(rgb[0]) + 0.7152 * toLinear(rgb[1]) + 0.0722 * toLinear(rgb[2]);
  const l1 = luminance(bgRgb);
  const l2 = luminance(fgRgb);
  const lighter = Math.max(l1, l2);
  const darker = Math.min(l1, l2);
  return (lighter + 0.05) / (darker + 0.05);
}

async function run() {
  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });

  for (const [name, url] of Object.entries(PAGES)) {
    console.log(`\n=== Auditing ${name} ===`);
    const page = await browser.newPage();
    page.setViewport({ width: 1280, height: 900 });

    const consoleErrors = [];
    const networkErrors = [];
    page.on('console', msg => {
      if (msg.type() === 'error') consoleErrors.push(msg.text());
    });
    page.on('pageerror', err => consoleErrors.push(err.message));
    page.on('response', resp => {
      if (resp.status() >= 400) networkErrors.push(`${resp.status()} ${resp.url()}`);
    });

    try {
      await page.goto(url, { waitUntil: 'networkidle0', timeout: 15000 });
    } catch (e) {
      console.log(`  Navigation warning: ${e.message}`);
    }

    // Screenshot
    const screenshotPath = path.join(LOG_DIR, `screenshot_${name}.png`);
    await page.screenshot({ path: screenshotPath, fullPage: true });
    console.log(`  Screenshot saved: screenshot_${name}.png`);

    // DOM node count
    const domCount = await page.evaluate(() => document.querySelectorAll('*').length);
    console.log(`  DOM node count: ${domCount}`);

    // Check console errors
    const pageErrors = await page.evaluate(() => {
      return window.__capturedErrors || [];
    });
    console.log(`  Console errors: ${consoleErrors.length}`);
    if (consoleErrors.length > 0) {
      console.log(`    ${consoleErrors.slice(0, 5).join('\n    ')}`);
    }

    // Check contrast ratios on sampled text elements
    const contrastRatios = await page.evaluate(() => {
      function luminance(r, g, b) {
        const c = v => { v = v / 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
        return 0.2126 * c(r) + 0.7152 * c(g) + 0.0722 * c(b);
      }
      function ratio(c1, c2) {
        const l1 = luminance(c1[0], c1[1], c1[2]);
        const l2 = luminance(c2[0], c2[1], c2[2]);
        return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
      }
      const parseRgb = s => s.replace(/[^\d,]/g, '').split(',').map(Number);
      const failed = [];
      const els = document.querySelectorAll('h1, h2, h3, p, span, a, button, label');
      for (let i = 0; i < Math.min(els.length, 30); i++) {
        const el = els[i];
        const text = el.textContent.trim();
        if (!text || text.length < 2) continue;
        const style = window.getComputedStyle(el);
        const color = style.color;
        const bg = style.backgroundColor;
        if (color === 'rgba(0, 0, 0, 0)' || bg === 'rgba(0, 0, 0, 0)') continue;
        if (!color.startsWith('rgb')) continue;
        const fg = parseRgb(color);
        const bg2 = parseRgb(bg);
        const r = ratio(fg, bg2);
        const fontSize = parseFloat(style.fontSize);
        const isSmall = fontSize < 18;
        const required = isSmall ? 4.5 : 3.0;
        if (r < required) failed.push({ text: text.slice(0, 35), ratio: r.toFixed(2), required, fontSize: fontSize + 'px' });
      }
      return { totalChecked: Math.min(els.length, 30), passed: Math.min(els.length, 30) - failed.length, failures: failed };
    });
    console.log(`  Contrast: ${contrastRatios.passed}/${contrastRatios.totalChecked} passed`);
    if (contrastRatios.failures.length > 0) {
      contrastRatios.failures.forEach(f => console.log(`    FAIL: "${f.text}" ratio=${f.ratio} need ≥${f.required} (${f.fontSize})`));
    }

    // Tab navigation test
    const tabCount = await page.evaluate(() => {
      const focusable = document.querySelectorAll(
        'a[href], button, input, textarea, select, [tabindex]:not([tabindex="-1"])'
      );
      return focusable.length;
    });
    console.log(`  Focusable elements (tab stops): ${tabCount}`);

    // Page load performance
    const perf = await page.evaluate(() => {
      const p = performance.getEntriesByType('navigation')[0];
      return {
        domContentLoaded: p ? Math.round(p.domContentLoadedEventEnd) : null,
        loadComplete: p ? Math.round(p.loadEventEnd) : null,
      };
    });
    console.log(`  DOMContentLoaded: ${perf.domContentLoaded}ms`);
    console.log(`  Load complete: ${perf.loadComplete}ms`);

    results[name] = {
      domCount,
      consoleErrors: consoleErrors.length,
      networkErrors: networkErrors,
      tabCount,
      perf,
      contrastPassed: contrastRatios.passed,
      contrastTotal: contrastRatios.totalChecked,
      contrastFailures: contrastRatios.failures,
    };

    await page.close();
  }

  await browser.close();

  // Summary
  console.log('\n========================================');
  console.log('BENCHMARK RESULTS SUMMARY');
  console.log('========================================');
  for (const [name, r] of Object.entries(results)) {
    console.log(`\n${name}:`);
    console.log(`  DOM nodes: ${r.domCount} (target < 500)`);
    console.log(`  Console errors: ${r.consoleErrors}`);
    if (r.networkErrors.length) {
      r.networkErrors.forEach(e => console.log(`  Network error: ${e}`));
    }
    console.log(`  Tab stops: ${r.tabCount}`);
    console.log(`  Contrast: ${r.contrastPassed}/${r.contrastTotal} passed`);
    if (r.contrastFailures.length) {
      r.contrastFailures.forEach(f => console.log(`    FAIL: "${f.text}" ratio=${f.ratio} need >${f.required}`));
    }
    console.log(`  DOMContentLoaded: ${r.perf.domContentLoaded}ms`);
    console.log(`  Load complete: ${r.perf.loadComplete}ms`);
  }

  // Write results to JSON
  fs.writeFileSync(path.join(LOG_DIR, 'benchmark_results.json'), JSON.stringify(results, null, 2));
  console.log('\nResults written to benchmark_results.json');
}

run().catch(err => {
  console.error('Benchmark failed:', err);
  process.exit(1);
});
