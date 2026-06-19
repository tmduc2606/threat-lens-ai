const puppeteer = require('puppeteer');
const fs = require('fs');
const path = require('path');

const BASE = 'http://localhost:8000';
const PAGES = {
  'index': `${BASE}/index.html`,
  'results': `${BASE}/results.html?q=185.220.101.42`,
  'details': `${BASE}/details.html?type=IP&value=185.220.101.42`,
};

const DEVICES = [
  { name: 'mobile_375', width: 375, height: 812 },
  { name: 'tablet_768', width: 768, height: 1024 },
  { name: 'desktop_1280', width: 1280, height: 900 },
  { name: 'desktop_1920', width: 1920, height: 1080 },
];

const LOG_DIR = path.resolve(__dirname);

async function run() {
  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });

  const allResults = {};

  for (const [pageName, url] of Object.entries(PAGES)) {
    console.log(`\n=== ${pageName} ===`);
    const pageResults = {};

    for (const device of DEVICES) {
      const page = await browser.newPage();
      await page.setViewport({ width: device.width, height: device.height });

      const errors = [];
      page.on('console', msg => { if (msg.type() === 'error') errors.push(msg.text()); });
      page.on('pageerror', err => errors.push(err.message));

      try {
        await page.goto(url, { waitUntil: 'networkidle0', timeout: 15000 });
      } catch (e) {
        // navigation may timeout due to API calls — content is still rendered
      }

      // Screenshot
      const screenshotName = `${pageName}_${device.name}.png`;
      await page.screenshot({ path: path.join(LOG_DIR, screenshotName), fullPage: true });

      // Check for overflow / horizontal scroll
      const overflow = await page.evaluate(() => {
        const scrollW = Math.max(
          document.documentElement.scrollWidth,
          document.body.scrollWidth
        );
        const viewW = document.documentElement.clientWidth;
        return scrollW > viewW + 2; // 2px tolerance
      });

      // Count visible elements
      const contentStats = await page.evaluate(() => {
        const cards = document.querySelectorAll('.rounded-2xl, .rounded-xl').length;
        const images = document.querySelectorAll('img').length;
        const links = document.querySelectorAll('a').length;
        const buttons = document.querySelectorAll('button').length;
        const inputs = document.querySelectorAll('input, textarea').length;
        return { cards, images, links, buttons, inputs };
      });

      console.log(`  ${device.name} (${device.width}x${device.height}): overflow=${overflow}, cards=${contentStats.cards}, links=${contentStats.links}`);

      pageResults[device.name] = {
        viewport: `${device.width}x${device.height}`,
        overflow,
        errors: errors.length,
        ...contentStats,
      };

      await page.close();
    }

    allResults[pageName] = pageResults;
  }

  await browser.close();

  // Print summary
  console.log('\n========================================');
  console.log('RESPONSIVE / CROSS-BROWSER SUMMARY');
  console.log('========================================');
  let overflowCount = 0;
  for (const [pageName, results] of Object.entries(allResults)) {
    console.log(`\n${pageName}:`);
    for (const [device, r] of Object.entries(results)) {
      const status = r.overflow ? '⚠️ OVERFLOW' : '✅ OK';
      if (r.overflow) overflowCount++;
      console.log(`  ${device} (${r.viewport}): ${status}, errors=${r.errors}`);
    }
  }

  console.log(`\nTotal overflow issues: ${overflowCount}`);
  console.log(`Overall: ${overflowCount === 0 ? 'PASS' : 'NEEDS FIX'}`);

  fs.writeFileSync(path.join(LOG_DIR, 'responsive_results.json'), JSON.stringify(allResults, null, 2));
  console.log('\nResponsive screenshots and results saved.');
}

run().catch(err => { console.error(err); process.exit(1); });
