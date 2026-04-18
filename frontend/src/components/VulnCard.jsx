import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'

const SEV_STYLES = {
  CRITICAL: { bg:'rgba(255,77,77,0.12)',  color:'var(--risk-critical)', border:'rgba(255,77,77,0.3)' },
  HIGH:     { bg:'rgba(255,140,66,0.12)', color:'var(--risk-high)',     border:'rgba(255,140,66,0.3)' },
  MEDIUM:   { bg:'rgba(255,212,59,0.10)', color:'var(--risk-medium)',   border:'rgba(255,212,59,0.25)' },
  LOW:      { bg:'rgba(74,222,128,0.08)', color:'var(--risk-low)',      border:'rgba(74,222,128,0.2)' },
}

function riskColor(score) {
  if (score >= 0.85) return 'var(--risk-critical)'
  if (score >= 0.65) return 'var(--risk-high)'
  if (score >= 0.40) return 'var(--risk-medium)'
  return 'var(--risk-low)'
}

function CodeSnippet({ snippet, vulnLine }) {
  if (!snippet) return null
  const lines = snippet.split('\n')
  return (
    <div style={{
      background:'var(--bg-primary)', border:'1px solid var(--border-dim)',
      borderRadius:6, padding:'10px 14px', fontFamily:"'JetBrains Mono',monospace",
      fontSize:12, lineHeight:1.8, overflowX:'auto', whiteSpace:'pre',
    }}>
      {lines.map((line, i) => {
        const match = line.match(/^(\d+):\s*(.*)/)
        if (!match) return <span key={i} style={{ display:'block' }}>{line}</span>
        const no = parseInt(match[1])
        const code = match[2]
        const isVuln = no === vulnLine
        return (
          <span key={i} style={{
            display:'block',
            background: isVuln ? 'rgba(255,77,77,0.10)' : 'transparent',
            borderLeft: isVuln ? '2px solid var(--risk-critical)' : '2px solid transparent',
            paddingLeft: 6, marginLeft: -6,
          }}>
            <span style={{ color:'var(--text-muted)', userSelect:'none', display:'inline-block', width:28 }}>{no}</span>
            <span style={{ color: isVuln ? '#fca5a5' : 'var(--text-primary)' }}>{code}</span>
          </span>
        )
      })}
    </div>
  )
}

export default function VulnCard({ result, index }) {
  const [open, setOpen] = useState(false)
  const sev = SEV_STYLES[result.severity] || SEV_STYLES.LOW

  return (
    <motion.div
      initial={{ opacity:0, y:12 }}
      animate={{ opacity:1, y:0 }}
      transition={{ duration:0.3, delay: index * 0.05 }}
      style={{
        background:'var(--bg-secondary)',
        border:'1px solid var(--border-dim)',
        borderRadius:10,
        overflow:'hidden',
        transition:'border-color 0.2s',
      }}
      whileHover={{ borderColor:'var(--border-subtle)' }}
    >
      {/* Header row — click to expand */}
      <div
        onClick={() => setOpen(o => !o)}
        style={{
          display:'flex', alignItems:'center', gap:12,
          padding:'14px 18px', cursor:'pointer',
        }}
      >
        {/* Severity badge */}
        <span style={{
          fontSize:10, fontFamily:"'JetBrains Mono',monospace", fontWeight:600,
          padding:'3px 8px', borderRadius:4, letterSpacing:'0.06em', flexShrink:0,
          background: sev.bg, color: sev.color, border:`1px solid ${sev.border}`,
        }}>
          {result.severity}
        </span>

        {/* Type + location */}
        <div style={{ flex:1, minWidth:0 }}>
          <div style={{ fontSize:13.5, fontWeight:600, whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis' }}>
            {result.vulnerability}
          </div>
          <div style={{ fontSize:11.5, color:'var(--text-secondary)', fontFamily:"'JetBrains Mono',monospace", marginTop:2 }}>
            {result.file}:{result.line}
          </div>
        </div>

        {/* Risk bar */}
        <div style={{ width:80, flexShrink:0 }}>
          <div style={{ fontSize:10, color:'var(--text-muted)', fontFamily:"'JetBrains Mono',monospace", textAlign:'right', marginBottom:4 }}>
            {Math.round(result.risk_score * 100)}%
          </div>
          <div style={{ height:4, background:'var(--bg-elevated)', borderRadius:2, overflow:'hidden' }}>
            <motion.div
              style={{ height:'100%', borderRadius:2, background: riskColor(result.risk_score) }}
              initial={{ width:0 }}
              animate={{ width: `${result.risk_score * 100}%` }}
              transition={{ duration:0.6, delay: index*0.05 + 0.3, ease:'easeOut' }}
            />
          </div>
        </div>

        {/* Chevron */}
        <motion.span
          animate={{ rotate: open ? 90 : 0 }}
          transition={{ duration:0.2 }}
          style={{ color:'var(--text-muted)', fontSize:12, flexShrink:0 }}
        >▶</motion.span>
      </div>

      {/* Expandable body */}
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height:0, opacity:0 }}
            animate={{ height:'auto', opacity:1 }}
            exit={{ height:0, opacity:0 }}
            transition={{ duration:0.25 }}
            style={{ borderTop:'1px solid var(--border-dim)', overflow:'hidden' }}
          >
            <div style={{ padding:'16px 18px', display:'flex', flexDirection:'column', gap:14 }}>
              {/* Code snippet */}
              {result.code_snippet && (
                <div>
                  <div style={{ fontSize:10, fontFamily:"'JetBrains Mono',monospace", color:'var(--text-muted)', letterSpacing:'0.1em', textTransform:'uppercase', marginBottom:6 }}>
                    Code Snippet
                  </div>
                  <CodeSnippet snippet={result.code_snippet} vulnLine={result.line} />
                </div>
              )}

              {/* Explanation */}
              <div>
                <div style={{ fontSize:10, fontFamily:"'JetBrains Mono',monospace", color:'var(--text-muted)', letterSpacing:'0.1em', textTransform:'uppercase', marginBottom:6 }}>
                  Explanation
                </div>
                <div style={{ fontSize:13, color:'var(--text-secondary)', lineHeight:1.65 }}>
                  {result.explanation}
                </div>
              </div>

              {/* Fix */}
              <div>
                <div style={{ fontSize:10, fontFamily:"'JetBrains Mono',monospace", color:'var(--text-muted)', letterSpacing:'0.1em', textTransform:'uppercase', marginBottom:6 }}>
                  Fix Suggestion
                </div>
                <div style={{
                  background:'rgba(74,222,128,0.07)', border:'1px solid rgba(74,222,128,0.18)',
                  borderRadius:6, padding:'10px 14px', fontSize:12.5, color:'#86efac', lineHeight:1.65,
                }}>
                  ✓ {result.fix}
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}
