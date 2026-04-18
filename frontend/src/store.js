import { create } from 'zustand'

export const useStore = create((set, get) => ({
  // ── Scan state ──────────────────────────────────────────────────────────
  screen: 'upload',          // 'upload' | 'scanning' | 'results'
  scanResults: null,
  scanHistory: [],

  // ── Scan progress ───────────────────────────────────────────────────────
  progress: 0,
  progressSteps: [],
  currentStep: '',

  // ── Filter ──────────────────────────────────────────────────────────────
  activeFilter: 'ALL',

  // ── Actions ─────────────────────────────────────────────────────────────
  setScreen: (screen) => set({ screen }),

  startScan: (filename) => set({
    screen: 'scanning',
    progress: 0,
    progressSteps: [],
    currentStep: `Scanning ${filename}...`,
  }),

  addStep: (step, done = false) => set((s) => ({
    progressSteps: [...s.progressSteps, { label: step, done }],
    currentStep: step,
  })),

  completeStep: () => set((s) => {
    const steps = [...s.progressSteps]
    const last = steps.findIndex(st => !st.done)
    if (last !== -1) steps[last] = { ...steps[last], done: true }
    return { progressSteps: steps }
  }),

  setProgress: (progress) => set({ progress }),

  finishScan: (results) => set((s) => ({
    screen: 'results',
    scanResults: results,
    scanHistory: [
      {
        scan_id: results.scan_id,
        filename: results.results[0]?.file ?? 'unknown',
        timestamp: results.timestamp,
        total_vulnerabilities: results.summary.total_vulnerabilities,
        high_risk: results.summary.high_risk,
      },
      ...s.scanHistory.slice(0, 9),
    ],
    progress: 100,
  })),

  setFilter: (filter) => set({ activeFilter: filter }),

  reset: () => set({
    screen: 'upload',
    scanResults: null,
    progress: 0,
    progressSteps: [],
    currentStep: '',
    activeFilter: 'ALL',
  }),
}))
