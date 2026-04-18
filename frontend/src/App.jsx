import { AnimatePresence } from 'framer-motion'
import { useStore } from './store'
import { useScan } from './hooks/useScan'
import { DEMO_DATA } from './utils/demoData'

import Header from './components/Header'
import Sidebar from './components/Sidebar'
import UploadScreen from './components/UploadScreen'
import ScanScreen from './components/ScanScreen'
import ResultsScreen from './components/ResultsScreen'

export default function App() {
  const { screen, finishScan, startScan, addStep, completeStep, setProgress } = useStore()
  const { run } = useScan()

  async function loadDemo(key) {
    const data = DEMO_DATA[key]
    startScan(data.results[0].file)

    const steps = [
      'Reading source file…',
      'Tokenizing & building AST…',
      'Applying vulnerability rules…',
      'Running ML risk model…',
      'Generating fix suggestions…',
      'Building report…',
    ]

    for (let i = 0; i < steps.length; i++) {
      addStep(steps[i])
      await new Promise(r => setTimeout(r, 450 + Math.random() * 250))
      completeStep()
      setProgress(Math.round(((i + 1) / steps.length) * 95))
    }

    await new Promise(r => setTimeout(r, 300))
    finishScan(data)
  }

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100vh' }}>
      <Header />
      <div style={{ display:'flex', flex:1, overflow:'hidden' }}>
        <Sidebar onLoadDemo={loadDemo} />
        <div style={{ flex:1, overflowY:'auto' }}>
          <AnimatePresence mode="wait">
            {screen === 'upload'   && <UploadScreen key="upload" onLoadDemo={loadDemo} />}
            {screen === 'scanning' && <ScanScreen   key="scanning" />}
            {screen === 'results'  && <ResultsScreen key="results" />}
          </AnimatePresence>
        </div>
      </div>
    </div>
  )
}
