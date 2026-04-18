import { motion } from 'framer-motion'
import { useStore } from '../store'

function NavItem({ icon, label, active, onClick }) {
  return (
    <motion.div
      onClick={onClick}
      whileHover={{ x: 2 }}
      style={{
        display: 'flex', alignItems: 'center', gap: 9,
        padding: '9px 12px',
        borderRadius: 7,
        fontSize: 13.5,
        fontWeight: 500,
        color: active ? 'var(--accent)' : 'var(--text-secondary)',
        background: active ? 'rgba(79,143,255,0.10)' : 'transparent',
        border: `1px solid ${active ? 'rgba(79,143,255,0.2)' : 'transparent'}`,
        cursor: 'pointer',
        transition: 'all 0.15s',
        userSelect: 'none',
      }}
    >
      <span style={{ fontSize:14, width:18, textAlign:'center' }}>{icon}</span>
      {label}
    </motion.div>
  )
}

function RecentScan({ item, onClick }) {
  return (
    <motion.div
      onClick={onClick}
      whileHover={{ x: 2 }}
      style={{
        background: 'var(--bg-tertiary)',
        border: '1px solid var(--border-dim)',
        borderRadius: 7,
        padding: '9px 12px',
        fontSize: 12,
        cursor: 'pointer',
        transition: 'all 0.15s',
        marginTop: 2,
      }}
    >
      <div style={{ color:'var(--text-primary)', fontWeight:600, fontFamily:"'JetBrains Mono',monospace", fontSize:11, marginBottom:4 }}>
        {item.filename}
      </div>
      <div style={{ display:'flex', gap:8, color:'var(--text-muted)', fontSize:11 }}>
        <span style={{ color:'var(--risk-critical)' }}>{item.total_vulnerabilities} vulns</span>
        <span>{item.high_risk} critical/high</span>
      </div>
    </motion.div>
  )
}

export default function Sidebar({ onLoadDemo }) {
  const { screen, scanHistory, setScreen } = useStore()

  const DEMOS = [
    { label: 'vulnerable_app.c', sub: '7 vulns · Critical', key: 'demo1' },
    { label: 'string_utils.cpp', sub: '3 vulns · High',     key: 'demo2' },
    { label: 'auth_handler.c',   sub: '5 vulns · Critical', key: 'demo3' },
  ]

  return (
    <nav style={{
      width: 256, minWidth: 256,
      borderRight: '1px solid var(--border-dim)',
      padding: '18px 14px',
      display: 'flex', flexDirection: 'column', gap: 4,
      overflowY: 'auto',
    }}>
      {/* Nav */}
      <div style={{ fontSize:10, fontFamily:"'JetBrains Mono',monospace", color:'var(--text-muted)', letterSpacing:'0.12em', textTransform:'uppercase', padding:'6px 8px 4px' }}>
        Navigation
      </div>
      <NavItem icon="⬆" label="Upload & Scan"  active={screen==='upload'}  onClick={() => setScreen('upload')} />
      <NavItem icon="◉" label="Results"         active={screen==='results'} onClick={() => screen==='results' && setScreen('results')} />

      {/* Demo scans */}
      <div style={{ fontSize:10, fontFamily:"'JetBrains Mono',monospace", color:'var(--text-muted)', letterSpacing:'0.12em', textTransform:'uppercase', padding:'14px 8px 4px' }}>
        Try a Demo
      </div>
      {DEMOS.map(d => (
        <motion.div
          key={d.key}
          onClick={() => onLoadDemo(d.key)}
          whileHover={{ x: 2 }}
          style={{
            background: 'var(--bg-tertiary)',
            border: '1px solid var(--border-dim)',
            borderRadius: 7,
            padding: '9px 12px',
            cursor: 'pointer',
            transition: 'all 0.15s',
            marginTop: 2,
          }}
        >
          <div style={{ color:'var(--text-primary)', fontWeight:600, fontFamily:"'JetBrains Mono',monospace", fontSize:11, marginBottom:3 }}>
            {d.label}
          </div>
          <div style={{ color:'var(--risk-critical)', fontSize:11 }}>{d.sub}</div>
        </motion.div>
      ))}

      {/* Scan history */}
      {scanHistory.length > 0 && <>
        <div style={{ fontSize:10, fontFamily:"'JetBrains Mono',monospace", color:'var(--text-muted)', letterSpacing:'0.12em', textTransform:'uppercase', padding:'14px 8px 4px' }}>
          Scan History
        </div>
        {scanHistory.map(item => (
          <RecentScan key={item.scan_id} item={item} onClick={() => {}} />
        ))}
      </>}
    </nav>
  )
}
