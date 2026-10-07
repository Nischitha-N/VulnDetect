import { useMemo, useState } from 'react'
import { motion } from 'framer-motion'
import { useStore } from '../store'
import { getSarifExport } from '../utils/api'
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

const SEV_FILTERS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
const STATUS_FILTERS = ['ALL_STATUS', 'CONFIRMED', 'LIKELY', 'NEEDS_REVIEW']

export default function ResultsScreen() {
  const { scanResults } = useStore()
  const [activeFilter, setActiveFilter] = useState('ALL')
  const [activeStatus, setActiveStatus] = useState('ALL_STATUS')
  const [exporting, setExporting] = useState(false)

  const { results, summary, scan_id } = scanResults

  const filtered = useMemo(() => {
    return results.filter(r => {
      const matchSev = activeFilter === 'ALL' || r.severity === activeFilter
      const rStatus = r.analysis_status || 'LIKELY'
      const matchStatus = activeStatus === 'ALL_STATUS' || rStatus === activeStatus
      return matchSev && matchStatus
    })
  }, [results, activeFilter, activeStatus])

  const confirmedCount = results.filter(r => (r.analysis_status || 'LIKELY') === 'CONFIRMED').length
  const likelyCount = results.filter(r => (r.analysis_status || 'LIKELY') === 'LIKELY').length
  const needsReviewCount = results.filter(r => r.analysis_status === 'NEEDS_REVIEW').length


  const handleExportSarif = async () => {
    try {
      setExporting(true)
      let sarifData
      if (scan_id) {
        sarifData = await getSarifExport(scan_id)
      } else {
        // Fallback construct simple SARIF blob
        sarifData = {
          version: "2.1.0",
          $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
          runs: [{
            tool: { driver: { name: "VulnDetect", version: "2.0.0", rules: [] } },
            results: results.map(r => ({
              ruleId: r.rule_id || "VULN",
              level: r.severity === 'CRITICAL' || r.severity === 'HIGH' ? 'error' : 'warning',
              message: { text: r.explanation || r.vulnerability },
              locations: [{
                physicalLocation: {
                  artifactLocation: { uri: r.file },
                  region: { startLine: r.line }
                }
              }]
            }))
          }]
        }
      }
      const blob = new Blob([JSON.stringify(sarifData, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `vulndetect-report-${scan_id || 'export'}.sarif`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      console.error('Failed to export SARIF:', e)
    } finally {
      setExporting(false)
    }
  }

  const handleExportHtml = () => {
    const htmlContent = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>VulnDetect Security Audit Report - ${filename}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 40px; color: #1e293b; background: #fff; line-height: 1.5; }
    h1 { font-size: 24px; margin-bottom: 4px; color: #0f172a; }
    .subtitle { color: #64748b; font-size: 14px; margin-bottom: 24px; }
    .metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }
    .metric-card { border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; background: #f8fafc; }
    .metric-val { font-size: 28px; font-weight: bold; color: #0f172a; }
    .metric-label { font-size: 12px; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 4px; }
    .vuln-item { border: 1px solid #e2e8f0; border-radius: 8px; padding: 18px; margin-bottom: 16px; page-break-inside: avoid; }
    .badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
    .badge-critical { background: #fee2e2; color: #991b1b; }
    .badge-high { background: #ffedd5; color: #9a3412; }
    .badge-medium { background: #fef3c7; color: #92400e; }
    .badge-low { background: #f1f5f9; color: #475569; }
    .code-box { background: #0f172a; color: #f8fafc; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 12px; margin: 10px 0; overflow-x: auto; white-space: pre-wrap; }
    .remedy { background: #f0fdf4; border-left: 4px solid #22c55e; padding: 10px 14px; font-size: 13px; color: #166534; border-radius: 0 4px 4px 0; margin-top: 10px; }
    @media print { body { margin: 20px; } .no-print { display: none !important; } }
  </style>
</head>
<body>
  <div style="display:flex; justify-content:space-between; align-items:center; border-bottom: 2px solid #e2e8f0; padding-bottom: 16px; margin-bottom: 20px;">
    <div>
      <h1>VulnDetect Security Audit Report</h1>
      <div class="subtitle">Target: <b>${filename}</b> &bull; Scanned: ${new Date().toLocaleString()} &bull; Total Files: ${summary.total_files}</div>
    </div>
    <div style="text-align:right;">
      <span style="font-size:12px; color:#64748b; font-family:monospace;">Engine: Multi-Layer AST + Taint + IPA</span>
    </div>
  </div>
  <div class="metrics">
    <div class="metric-card"><div class="metric-label">Total Findings</div><div class="metric-val">${results.length}</div></div>
    <div class="metric-card"><div class="metric-label">Critical / High</div><div class="metric-val" style="color: #dc2626">${summary.high_risk}</div></div>
    <div class="metric-card"><div class="metric-label">Medium Risk</div><div class="metric-val" style="color: #d97706">${summary.medium_risk}</div></div>
    <div class="metric-card"><div class="metric-label">Low / Clean</div><div class="metric-val">${summary.low_risk}</div></div>
  </div>
  <h2 style="font-size:18px; margin-bottom:16px;">Vulnerability Findings (${results.length})</h2>
  ${results.map(r => `
    <div class="vuln-item">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
        <div>
          <span class="badge badge-${(r.severity || 'low').toLowerCase()}">${r.severity}</span>
          <span style="font-weight:bold; font-size:15px; margin-left:8px;">${r.vulnerability}</span>
          <span style="color:#64748b; font-size:13px; margin-left:8px;">[${r.rule_id || 'RULE'}] ${r.cwe}</span>
        </div>
        <div style="font-size:13px; color:#475569; font-family:monospace;">${r.file}:${r.line}</div>
      </div>
      <p style="margin:8px 0; font-size:14px; color:#334155;">${r.explanation || ''}</p>
      ${r.code_snippet ? `<div class="code-box">${r.code_snippet.replace(/</g, '&lt;')}</div>` : ''}
      ${r.fix ? `<div class="remedy"><b>Recommended Fix:</b> ${r.fix}</div>` : ''}
    </div>
  `).join('')}
</body>
</html>`
    const blob = new Blob([htmlContent], { type: 'text/html' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `vulndetect-report-${scan_id || 'export'}.html`
    a.click()
    URL.revokeObjectURL(url)
  }

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
            {summary.total_files} file{summary.total_files !== 1 ? 's' : ''} · {results.length} vulnerabilities · {summary.scan_duration_ms}ms · Engine: AST + Taint + Multi-Layer
          </div>
        </div>
        <div style={{ display:'flex', gap:10 }}>
          <button
            onClick={() => window.print()}
            style={{
              display:'flex', alignItems:'center', gap:6,
              fontSize:12, fontFamily:"'JetBrains Mono',monospace", fontWeight:600,
              padding:'8px 14px', borderRadius:7,
              background:'var(--bg-secondary)', border:'1px solid var(--border-dim)',
              color:'var(--text-secondary)', cursor:'pointer', transition:'all 0.15s',
            }}
          >
            🖨️ Print / PDF
          </button>
          <button
            onClick={handleExportHtml}
            style={{
              display:'flex', alignItems:'center', gap:6,
              fontSize:12, fontFamily:"'JetBrains Mono',monospace", fontWeight:600,
              padding:'8px 14px', borderRadius:7,
              background:'rgba(34,197,94,0.12)', border:'1px solid rgba(34,197,94,0.35)',
              color:'#22c55e', cursor:'pointer', transition:'all 0.15s',
            }}
          >
            📄 Export HTML
          </button>
          <button
            onClick={handleExportSarif}
            disabled={exporting}
            style={{
              display:'flex', alignItems:'center', gap:6,
              fontSize:12, fontFamily:"'JetBrains Mono',monospace", fontWeight:600,
              padding:'8px 14px', borderRadius:7,
              background:'rgba(79,143,255,0.12)', border:'1px solid rgba(79,143,255,0.35)',
              color:'var(--accent)', cursor:'pointer', transition:'all 0.15s',
            }}
          >
            📋 {exporting ? 'Exporting...' : 'Export SARIF v2.1'}
          </button>
        </div>
      </div>

      {/* Summary metrics */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:12, marginBottom:24 }}>
        <MetricCard
          label="Total Findings"
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

      {/* Status & Severity Filter pills */}
      <div style={{ display:'flex', flexDirection:'column', gap:10, marginBottom:20 }}>
        {/* Certainty Status Selector */}
        <div style={{ display:'flex', gap:8, alignItems:'center', flexWrap:'wrap' }}>
          <span style={{ fontSize:11, fontFamily:"'JetBrains Mono',monospace", color:'var(--text-muted)', textTransform:'uppercase', marginRight:4 }}>
            Certainty:
          </span>
          <button
            onClick={() => setActiveStatus('ALL_STATUS')}
            style={{
              fontSize:11, padding:'4px 10px', borderRadius:6,
              border:`1px solid ${activeStatus==='ALL_STATUS' ? 'rgba(79,143,255,0.4)' : 'var(--border-dim)'}`,
              background: activeStatus==='ALL_STATUS' ? 'rgba(79,143,255,0.15)' : 'transparent',
              color: activeStatus==='ALL_STATUS' ? 'var(--accent)' : 'var(--text-secondary)',
              cursor:'pointer', fontFamily:"'JetBrains Mono',monospace", fontWeight:600,
            }}
          >
            ALL STATES ({results.length})
          </button>
          <button
            onClick={() => setActiveStatus('CONFIRMED')}
            style={{
              fontSize:11, padding:'4px 10px', borderRadius:6,
              border:`1px solid ${activeStatus==='CONFIRMED' ? 'rgba(239,68,68,0.4)' : 'var(--border-dim)'}`,
              background: activeStatus==='CONFIRMED' ? 'rgba(239,68,68,0.15)' : 'transparent',
              color: activeStatus==='CONFIRMED' ? '#f87171' : 'var(--text-secondary)',
              cursor:'pointer', fontFamily:"'JetBrains Mono',monospace", fontWeight:600,
            }}
          >
            🔒 CONFIRMED ({confirmedCount})
          </button>
          <button
            onClick={() => setActiveStatus('LIKELY')}
            style={{
              fontSize:11, padding:'4px 10px', borderRadius:6,
              border:`1px solid ${activeStatus==='LIKELY' ? 'rgba(245,158,11,0.4)' : 'var(--border-dim)'}`,
              background: activeStatus==='LIKELY' ? 'rgba(245,158,11,0.15)' : 'transparent',
              color: activeStatus==='LIKELY' ? '#fbbf24' : 'var(--text-secondary)',
              cursor:'pointer', fontFamily:"'JetBrains Mono',monospace", fontWeight:600,
            }}
          >
            ⚡ LIKELY ({likelyCount})
          </button>
          <button
            onClick={() => setActiveStatus('NEEDS_REVIEW')}
            style={{
              fontSize:11, padding:'4px 10px', borderRadius:6,
              border:`1px solid ${activeStatus==='NEEDS_REVIEW' ? 'rgba(56,189,248,0.4)' : 'var(--border-dim)'}`,
              background: activeStatus==='NEEDS_REVIEW' ? 'rgba(56,189,248,0.15)' : 'transparent',
              color: activeStatus==='NEEDS_REVIEW' ? '#38bdf8' : 'var(--text-secondary)',
              cursor:'pointer', fontFamily:"'JetBrains Mono',monospace", fontWeight:600,
            }}
          >
            🔍 NEEDS REVIEW ({needsReviewCount})
          </button>
        </div>

        {/* Severity Selector */}
        <div style={{ display:'flex', gap:8, alignItems:'center', flexWrap:'wrap' }}>
          <span style={{ fontSize:11, fontFamily:"'JetBrains Mono',monospace", color:'var(--text-muted)', textTransform:'uppercase', marginRight:4 }}>
            Severity:
          </span>
          {SEV_FILTERS.map(f => {
            const count = f === 'ALL' ? results.length : results.filter(r => r.severity === f).length
            return (
              <button
                key={f}
                onClick={() => setActiveFilter(f)}
                style={{
                  fontSize:11, padding:'4px 10px', borderRadius:6,
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
            Showing {filtered.length} of {results.length} findings
          </span>
        </div>
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

