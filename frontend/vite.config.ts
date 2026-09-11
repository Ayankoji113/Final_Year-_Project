import path from 'node:path'
import { fileURLToPath } from 'node:url'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig } from 'vite'
import { microapiData } from './plugins/microapiData'

const here = path.dirname(fileURLToPath(import.meta.url))
const srcDir = process.env.MICROAPI_SRC || path.resolve(here, '..', 'src')

/**
 * The gateway sends no CORS headers - deliberately, it is a reverse proxy for
 * an API, not for a browser app. Rather than add middleware to it, the console
 * is served same-origin and /__guard is proxied here, so the deployed gateway
 * is byte-for-byte the one that was audited.
 */
const gateway = process.env.GATEWAY_URL || 'http://127.0.0.1:5000'

const proxy = {
  '/__guard': {
    target: gateway,
    changeOrigin: true,
    // A dashboard must not stall behind an unresponsive gateway; surface the
    // failure to the UI instead so it can render its "unreachable" state.
    timeout: 8000,
  },
  // Used only by the deliberate, operator-triggered backend probe on the
  // System Health page. It is a real proxied request and is logged as one.
  '/__probe': {
    target: gateway,
    changeOrigin: true,
    timeout: 8000,
    rewrite: (p: string) => p.replace(/^\/__probe/, ''),
  },
}

export default defineConfig({
  root: here,
  plugins: [react(), tailwindcss(), microapiData({ srcDir })],
  server: { port: 5173, strictPort: false, proxy },
  preview: { port: 4173, strictPort: false, proxy },
  build: { outDir: 'dist', sourcemap: true },
})
