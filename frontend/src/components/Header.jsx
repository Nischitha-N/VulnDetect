import { motion } from 'framer-motion'
import { useEffect, useState } from 'react'
import { useStore } from '../store'
import { healthCheck } from '../utils/api'

export default function Header() {
  const { screen, reset } = useStore()
  const [backendUp, setBackendUp] = useState(null)

  useEffect(() => {
    healthCheck().then(setBackendUp)
    const id = setInterval(() => healthCheck().then(setBackendUp), 10_000)
    return () => clearInterval(id)
  }, [])

  return (
    <header style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '14px 28px',
      borderBottom: '1px solid var(--border-dim)',
      background: 'var(--bg-primary)',
      position: 'sticky',
      top: 0,
      zIndex: 100,
    }}>
      {/* Logo */}
      <motion.div
        style={{ display:'flex', alignItems:'center', gap:10 }}
        initial={{ opacity: 0, x: -12 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ duration: 0.4 }}
      >
        <div style={{
          width: 30, height: 30,
          background: 'linear-gradient(135deg, #4f8fff, #2d5ccc)',
          borderRadius: 7,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 16,
        }}>🛡</div>
        <span style={{ fontSize: 15, fontWeight: 700, letterSpacing: '-0.02em' }}>
          VulnDetect
        </span>
        <span style={{
          fontSize: 10,
          fontFamily: "'JetBrains Mono', monospace",
          background: 'rgba(79,143,255,0.15)',
          color: 'var(--accent)',
          border: '1px solid rgba(79,143,255,0.3)',
          borderRadius: 4,
          padding: '2px 7px',
          letterSpacing: '0.05em',
        }}>ML + Static</span>
      </motion.div>

      {/* Right controls */}
      <div style={{ display:'flex', gap:10, alignItems:'center' }}>
        {/* Backend status */}
        <div style={{
          display:'flex', alignItems:'center', gap:6,
          fontSize: 11,
          fontFamily: "'JetBrains Mono', monospace",
          color: 'var(--text-muted)',
          background: 'var(--bg-tertiary)',
          border: '1px solid var(--border-dim)',
          borderRadius: 5,
          padding: '5px 10px',
        }}>
          <span style={{
            width: 6, height: 6, borderRadius: '50%',
            background: backendUp === null ? 'var(--text-muted)'
              : backendUp ? 'var(--risk-low)' : 'var(--risk-high)',
            display: 'inline-block',
            animation: 'pulse 2s infinite',
          }} />
          {backendUp === null ? 'connecting…' : backendUp ? 'backend online' : 'demo mode'}
        </div>

        {screen !== 'upload' && (
          <motion.button
            onClick={reset}
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            style={{
              padding: '7px 14px',
              borderRadius: 7,
              border: '1px solid var(--border-subtle)',
              background: 'transparent',
              color: 'var(--text-secondary)',
              fontSize: 12,
              fontFamily: "'Syne', sans-serif",
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'all 0.15s',
            }}
            whileHover={{ background: 'var(--bg-elevated)', color: 'var(--text-primary)' }}
          >
            ⬆ New Scan
          </motion.button>
        )}
      </div>
    </header>
  )
}
