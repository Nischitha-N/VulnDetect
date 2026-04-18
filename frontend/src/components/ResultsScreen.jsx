import { useMemo, useState } from 'react'
import { motion } from 'framer-motion'
import { useStore } from '../store'
import VulnCard from './VulnCard'
import Charts from './Charts'

function MetricCard({ label, value, color, sub }) {
  return (
    <div style={{
      background:'var(--bg-secondary)', border:'1px solid var(--border-dim)',
      borderRadius:10, padding:'16px 18px', transition:'border-color 0.2s',
    }}>
      <div style={{ fontSize:11, fontFamily:"'JetBrains Mono',monospace", color:'var(--text-muted)', letterSpacing:'0.06em', textTransform:'uppercase', marginBottom:8 }}>
        {label}
      </div>
      <div style={{ fontSize:26, fontWeight:700, letterSpacing:'-0.03em', color: color || 'var(--text-primary)' }}>
        {value}
      </div>
      {sub && <div style={{ fontSize:11, color:'var(--text-muted)', marginTop:4 }}>{sub}</div>}
    </div>
  )
}

const FILTERS = ['ALL','CRITICAL','HIGH','MEDIUM','LOW']

export default function ResultsScreen() {
  const { scanResults } = useStore()
  const [activeFilter, setActiveFilter] = useState('ALL')

  const { results, summary } = scanResults

  const filtered = useMemo(() =>
    activeFilter === 'ALL' ? results : results.filter(r => r.severity === activeFilter),
    [results, activeFilter]
  )

  const filename = results[0]?.file ?? 'Scan Results'

  return (
    <motion.div
      initial={{ opacity:0 }}
      animate={{ opacity:1 }}
      transition={{ duration:0.35 }}
      style={{ padding:'28px 32px' }}
    >
      {/* Header */}
      <div style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between', marginBottom:24 }}>
        <div>
          <div style={{ fontSize:20, fontWeight:700, letterSpacing:'-0.02em' }}>{filename}</div>
          <div style={{ fontSize:12, color:'var(--text-secondary)', fontFamily:"'JetBrains Mono',monospace", marginTop:4 }}>
            {summary.total_files} file{summary.total_files !== 1 ? 's' : ''} · {results.length} vulnerabilities · {summary.scan_duration_ms}ms
          </div>
        </div>
      </div>

      {/* Summary metrics */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:12, marginBottom:24 }}>
        <MetricCard
          label="Total Vulns"
          value={results.length}
          color={results.length > 5 ? 'var(--risk-critical)' : 'var(--risk-high)'}
          sub={`${summary.total_files} file scanned`}
        />
        <MetricCard
          label="Critical / High"
          value={summary.high_risk}
          color="var(--risk-critical)"
          sub="immediate action needed"
        />
        <MetricCard
          label="Medium Risk"
          value={summary.medium_risk}
          color="var(--risk-medium)"
          sub="review recommended"
        />
        <MetricCard
          label="Low Risk"
          value={summary.low_risk}
          color="var(--risk-low)"
          sub="informational"
        />
      </div>

      {/* Charts */}
      {results.length > 0 && <Charts results={results} />}

      {/* Filter pills */}
      <div style={{ display:'flex', gap:8, marginBottom:16, flexWrap:'wrap', alignItems:'center' }}>
        {FILTERS.map(f => {
          const count = f === 'ALL' ? results.length : results.filter(r => r.severity === f).length
          return (
            <button
              key={f}
              onClick={() => setActiveFilter(f)}
              style={{
                fontSize:12, padding:'5px 12px', borderRadius:6,
                border:`1px solid ${activeFilter===f ? 'rgba(79,143,255,0.35)' : 'var(--border-subtle)'}`,
                background: activeFilter===f ? 'rgba(79,143,255,0.15)' : 'transparent',
                color: activeFilter===f ? 'var(--accent)' : 'var(--text-secondary)',
                cursor:'pointer', fontFamily:"'Syne',sans-serif", fontWeight:500,
                transition:'all 0.15s',
              }}
            >
              {f} ({count})
            </button>
          )
        })}
        <span style={{ marginLeft:'auto', fontSize:12, color:'var(--text-muted)', fontFamily:"'JetBrains Mono',monospace" }}>
          {filtered.length} results
        </span>
      </div>

      {/* Vulnerability cards */}
      {results.length === 0 ? (
        <div style={{ textAlign:'center', padding:'60px 0', color:'var(--text-muted)' }}>
          <div style={{ fontSize:32, marginBottom:12 }}>✅</div>
          <div style={{ fontSize:16, fontWeight:600, marginBottom:6 }}>No vulnerabilities detected</div>
          <div style={{ fontSize:13 }}>The code appears to be safe from common vulnerability patterns.</div>
        </div>
      ) : (
        <div style={{ display:'flex', flexDirection:'column', gap:12 }}>
          {filtered.map((r, i) => (
            <VulnCard key={`${r.file}-${r.line}-${i}`} result={r} index={i} />
          ))}
        </div>
      )}
    </motion.div>
  )
}
