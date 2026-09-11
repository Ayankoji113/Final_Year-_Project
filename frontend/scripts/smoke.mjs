/**
 * Browser smoke test for the console.
 *
 * Loads every route against a running dev server and a running gateway, and
 * fails on any uncaught exception, console error, or failed request. It exists
 * because `tsc` and `vite build` both pass on a page that throws the moment it
 * renders, and a security console that silently shows nothing is worse than one
 * that does not build.
 *
 *   node scripts/smoke.mjs [baseUrl]
 */
import { chromium } from 'playwright'

const BASE = process.argv[2] || 'http://localhost:5173'

const ROUTES = [
  ['Overview', '#/'],
  ['Live Traffic', '#/live'],
  ['Threats', '#/threats'],
  ['Investigation', '#/investigate'],
  ['ML Intelligence', '#/ml'],
  ['Request Logs', '#/logs'],
  ['System Health', '#/health'],
  ['Configuration', '#/config'],
]

// React dev warnings are noise here; anything else on console.error is not.
const IGNORE = [/Download the React DevTools/i, /Recharts.*defaultProps/i]

const browser = await chromium.launch({ channel: 'chrome' })
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } })

let failures = 0
const problems = []

page.on('console', (msg) => {
  if (msg.type() !== 'error') return
  const text = msg.text()
  if (IGNORE.some((re) => re.test(text))) return
  problems.push(`console.error: ${text}`)
})
page.on('pageerror', (err) => problems.push(`pageerror: ${err.message}`))
// ERR_ABORTED is expected and correct: every poller cancels its in-flight
// request on unmount, and StrictMode's double-mount aborts the first of each
// pair. Only a genuine transport failure is a problem.
page.on('requestfailed', (req) => {
  const err = req.failure()?.errorText ?? ''
  if (err.includes('ERR_ABORTED')) return
  problems.push(`requestfailed: ${req.url()} ${err}`)
})
page.on('response', (res) => {
  if (res.status() >= 400) problems.push(`HTTP ${res.status()} ${res.url()}`)
})

for (const [name, hash] of ROUTES) {
  problems.length = 0
  await page.goto(`${BASE}/${hash}`, { waitUntil: 'networkidle' })
  // Give the first poll of each provider time to land and render.
  await page.waitForTimeout(1500)

  const heading = await page.locator('header h1').first().textContent()
  const bodyText = (await page.locator('main').innerText()).trim()

  const ok = problems.length === 0 && bodyText.length > 80
  if (!ok) failures += 1

  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name.padEnd(16)} heading="${heading}" chars=${bodyText.length}`)
  for (const p of problems) console.log(`        ${p}`)
}

// One targeted check of the thing this console exists to get right: an L1 rule
// block and an ML verdict must not be presented the same way.
await page.goto(`${BASE}/#/threats`, { waitUntil: 'networkidle' })
await page.waitForTimeout(1500)
const threatsText = await page.locator('main').innerText()
for (const phrase of ['L1 Security Rule', 'ML Detection', 'Would block']) {
  const present = threatsText.includes(phrase)
  console.log(`${present ? 'PASS' : 'WARN'}  Threats page distinguishes "${phrase}"`)
}

await browser.close()
process.exit(failures > 0 ? 1 : 0)
