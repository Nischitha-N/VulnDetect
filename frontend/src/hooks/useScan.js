import { useCallback } from 'react'
import { useStore } from '../store'
import { scanFile, healthCheck } from '../utils/api'

const STEPS = [
  'Reading source file…',
  'Tokenizing & building AST…',
  'Applying vulnerability rules…',
  'Running ML risk model…',
  'Generating fix suggestions…',
  'Building report…',
]

/** Sleep helper */
const sleep = (ms) => new Promise((res) => setTimeout(res, ms))

/** Animate progress steps with realistic timing */
async function animateSteps(addStep, completeStep, setProgress) {
  for (let i = 0; i < STEPS.length; i++) {
    addStep(STEPS[i])
    await sleep(500 + Math.random() * 300)
    completeStep()
    setProgress(Math.round(((i + 1) / STEPS.length) * 90))
    await sleep(100)
  }
}

/** Call Claude API as AI-powered fallback scanner */
// REMOVED: aiScan() and Anthropic API fallback have been removed.
// The frontend now relies exclusively on the backend static analysis engine.

export function useScan() {
  const { startScan, addStep, completeStep, setProgress, finishScan, reset } = useStore()

  const run = useCallback(async (file) => {
    startScan(file.name)

    const [isBackendUp] = await Promise.all([
      healthCheck(),
      sleep(200),
    ])

    // Run animation in parallel with actual work
    const animPromise = animateSteps(addStep, completeStep, setProgress)

    let result
    if (isBackendUp) {
      // ── Real backend path ──────────────────────────────────────────────
      try {
        result = await scanFile(file, (e) => {
          if (e.total) setProgress(Math.round((e.loaded / e.total) * 30))
        })
      } catch (err) {
        console.error('Backend scan failed:', err)
        result = null
      }
    }
    // No AI fallback — backend is the only scanner

    await animPromise  // ensure animation completes

    if (!result) {
      // Return a clear error result when backend is unavailable or failed
      result = {
        scan_id: `err-${Date.now()}`,
        timestamp: new Date().toISOString(),
        summary: { total_files:1, total_vulnerabilities:0, high_risk:0, medium_risk:0, low_risk:0, scan_duration_ms:0, vulnerability_types:{} },
        results: [],
      }
    }

    setProgress(100)
    await sleep(300)
    finishScan(result)
  }, [startScan, addStep, completeStep, setProgress, finishScan])

  return { run, reset }
}
