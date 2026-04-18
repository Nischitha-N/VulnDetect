import { motion, AnimatePresence } from 'framer-motion'
import { useStore } from '../store'

function ScanRing({ size, color, duration, reverse }) {
  return (
    <motion.div
      style={{
        position:'absolute', inset: size,
        borderRadius:'50%',
        border:'2px solid transparent',
        borderTopColor: color,
      }}
      animate={{ rotate: reverse ? -360 : 360 }}
      transition={{ duration, repeat:Infinity, ease:'linear' }}
    />
  )
}

export default function ScanScreen() {
  const { progressSteps, progress, currentStep } = useStore()

  return (
    <div style={{
      display:'flex', flexDirection:'column', alignItems:'center',
      justifyContent:'center', minHeight:'calc(100vh - 61px)',
      padding:40, gap:28,
    }}>
      {/* Animated rings */}
      <div style={{ position:'relative', width:120, height:120 }}>
        <ScanRing size={0}  color="var(--accent)"     duration={1.4} />
        <ScanRing size={12} color="var(--risk-teal)"  duration={1.9} reverse />
        <ScanRing size={24} color="rgba(79,143,255,0.3)" duration={2.4} />
        <div style={{
          position:'absolute', inset:36,
          background:'var(--bg-tertiary)',
          borderRadius:'50%',
          display:'flex', alignItems:'center', justifyContent:'center',
          fontSize:22,
        }}>🔍</div>
      </div>

      {/* Title */}
      <div style={{ textAlign:'center' }}>
        <div style={{ fontSize:20, fontWeight:700, letterSpacing:'-0.02em', marginBottom:6 }}>
          Analyzing Code
        </div>
        <div style={{ fontSize:13, color:'var(--text-secondary)' }}>
          {currentStep || 'Initializing…'}
        </div>
      </div>

      {/* Progress bar */}
      <div style={{
        width:'100%', maxWidth:460,
        background:'var(--bg-tertiary)',
        borderRadius:6, height:4, overflow:'hidden',
      }}>
        <motion.div
          style={{ height:'100%', background:'linear-gradient(90deg, var(--accent), var(--risk-teal))', borderRadius:6 }}
          animate={{ width: `${progress}%` }}
          transition={{ duration:0.4, ease:'easeOut' }}
        />
      </div>

      {/* Step list */}
      <div style={{ width:'100%', maxWidth:460, display:'flex', flexDirection:'column', gap:6, maxHeight:220, overflowY:'auto' }}>
        <AnimatePresence>
          {progressSteps.map((step, i) => (
            <motion.div
              key={i}
              initial={{ opacity:0, y:8 }}
              animate={{ opacity:1, y:0 }}
              style={{
                display:'flex', alignItems:'center', gap:10,
                fontFamily:"'JetBrains Mono',monospace", fontSize:12,
                color: step.done ? 'var(--risk-low)' : 'var(--accent)',
              }}
            >
              <span style={{
                width:6, height:6, borderRadius:'50%',
                background:'currentColor', flexShrink:0,
              }} />
              {step.label}
              {step.done && <span style={{ marginLeft:'auto', fontSize:11 }}>✓</span>}
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </div>
  )
}
