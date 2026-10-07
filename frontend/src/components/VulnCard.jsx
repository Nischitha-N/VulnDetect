import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'

const SEV_STYLES = {
  CRITICAL: { bg:'rgba(255,77,77,0.14)',  color:'var(--risk-critical)', border:'rgba(255,77,77,0.35)' },
  HIGH:     { bg:'rgba(255,140,66,0.14)', color:'var(--risk-high)',     border:'rgba(255,140,66,0.35)' },
  MEDIUM:   { bg:'rgba(255,212,59,0.12)', color:'var(--risk-medium)',   border:'rgba(255,212,59,0.3)' },
  LOW:      { bg:'rgba(74,222,128,0.10)', color:'var(--risk-low)',      border:'rgba(74,222,128,0.25)' },
}

const SOURCE_BADGES = {
  multi_analyzer: { label: 'MULTI-LAYER', bg: 'rgba(168,85,247,0.20)', color: '#c084fc', border: 'rgba(168,85,247,0.45)' },
  ast:            { label: 'AST-SYNTAX',  bg: 'rgba(59,130,246,0.18)', color: '#60a5fa', border: 'rgba(59,130,246,0.4)' },
  taint:          { label: 'TAINT-FLOW',  bg: 'rgba(236,72,153,0.18)', color: '#f472b6', border: 'rgba(236,72,153,0.4)' },
  range:          { label: 'RANGE-BOUNDS',bg: 'rgba(14,165,233,0.20)', color: '#38bdf8', border: 'rgba(14,165,233,0.45)' },
  cfg:            { label: 'CFG-PATH',    bg: 'rgba(139,92,246,0.20)', color: '#a78bfa', border: 'rgba(139,92,246,0.45)' },
  ipa:            { label: 'IPA-SUMMARY', bg: 'rgba(245,158,11,0.20)', color: '#fbbf24', border: 'rgba(245,158,11,0.45)' },
  cpp:            { label: 'CPP-SEMANTICS',bg:'rgba(16,185,129,0.20)', color: '#34d399', border: 'rgba(16,185,129,0.45)' },
  dataflow:       { label: 'DATAFLOW',    bg: 'rgba(20,184,166,0.18)', color: '#2dd4bf', border: 'rgba(20,184,166,0.4)' },
  regex:          { label: 'REGEX-RULE',  bg: 'rgba(148,163,184,0.15)',color: '#94a3b8', border: 'rgba(148,163,184,0.3)' },
  ml:             { label: 'ML-SCORED',   bg: 'rgba(234,179,8,0.18)',  color: '#facc15', border: 'rgba(234,179,8,0.4)' },
  llm:            { label: 'LLM-ASSISTED',bg: 'rgba(99,102,241,0.18)', color: '#818cf8', border: 'rgba(99,102,241,0.4)' },
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
      borderRadius:8, padding:'14px 18px', fontFamily:"'JetBrains Mono',monospace",
      fontSize:14.5, lineHeight:1.9, overflowX:'auto', whiteSpace:'pre',
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
            background: isVuln ? 'rgba(255,77,77,0.18)' : 'transparent',
            borderLeft: isVuln ? '4px solid var(--risk-critical)' : '4px solid transparent',
            paddingLeft: 10, marginLeft: -10,
          }}>
            <span style={{ color:'var(--text-muted)', userSelect:'none', display:'inline-block', width:38, fontSize:13.5 }}>{no}</span>
            <span style={{ color: isVuln ? '#fecaca' : '#f1f5f9', fontWeight: isVuln ? 600 : 400 }}>{code}</span>
          </span>
        )
      })}
    </div>
  )
}

function DataflowTrace({ steps }) {
  if (!steps || steps.length === 0) return null
  const stepColors = {
    SOURCE: { color: '#f87171', bg: 'rgba(248,113,113,0.18)' },
    PROPAGATION: { color: '#fbbf24', bg: 'rgba(251,191,36,0.18)' },
    SANITIZER: { color: '#34d399', bg: 'rgba(52,211,153,0.18)' },
    SINK: { color: '#ef4444', bg: 'rgba(239,68,68,0.25)' },
  }

  return (
    <div>
      <div style={{ fontSize:13, fontFamily:"'JetBrains Mono',monospace", color:'#cbd5e1', letterSpacing:'0.08em', textTransform:'uppercase', fontWeight:700, marginBottom:8 }}>
        Data-Flow & Taint Propagation Path
      </div>
      <div style={{
        display:'flex', flexDirection:'column', gap:10,
        background:'var(--bg-primary)', border:'1px solid var(--border-dim)',
        borderRadius:8, padding:'16px 18px',
      }}>
        {steps.map((st, idx) => {
          const cfg = stepColors[st.step_type] || stepColors.PROPAGATION
          return (
            <div key={idx} style={{ display:'flex', alignItems:'flex-start', gap:12, fontSize:14.5 }}>
              <span style={{
                fontSize:12, fontFamily:"'JetBrains Mono',monospace", fontWeight:700,
                padding:'4px 9px', borderRadius:5, background: cfg.bg, color: cfg.color, flexShrink:0,
                marginTop:1,
              }}>
                {st.step_type}
              </span>
              <div style={{ flex:1, minWidth:0, lineHeight:1.7 }}>
                <span style={{ fontFamily:"'JetBrains Mono',monospace", fontWeight:700, color:'#94a3b8', marginRight:8 }}>
                  L{st.line}:
                </span>
                <span style={{ color:'#f1f5f9', fontWeight:500 }}>{st.description}</span>
                {st.code && (
                  <div style={{
                    marginTop:7, fontFamily:"'JetBrains Mono',monospace", fontSize:13.5,
                    color:'#f8fafc', background:'rgba(255,255,255,0.06)', border:'1px solid rgba(255,255,255,0.12)',
                    padding:'6px 12px', borderRadius:6, overflowX:'auto',
                  }}>
                    {st.code.trim()}
                  </div>
                )}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function EvidenceList({ evidence }) {
  if (!evidence || evidence.length === 0) return null
  return (
    <div>
      <div style={{ fontSize:13, fontFamily:"'JetBrains Mono',monospace", color:'#cbd5e1', letterSpacing:'0.08em', textTransform:'uppercase', fontWeight:700, marginBottom:8 }}>
        Multi-Analyzer Evidence ({evidence.length} Source{evidence.length !== 1 ? 's' : ''})
      </div>
      <div style={{ display:'flex', flexDirection:'column', gap:8 }}>
        {evidence.map((ev, i) => {
          const badge = SOURCE_BADGES[ev.analyzer_source] || SOURCE_BADGES.regex
          return (
            <div key={i} style={{
              display:'flex', alignItems:'center', gap:12,
              background:'var(--bg-primary)', border:'1px solid var(--border-dim)',
              borderRadius:8, padding:'12px 16px', fontSize:14.5,
            }}>
              <span style={{
                fontSize:12, fontFamily:"'JetBrains Mono',monospace", fontWeight:700,
                padding:'4px 9px', borderRadius:5, background: badge.bg, color: badge.color,
                border:`1px solid ${badge.border}`, flexShrink:0,
              }}>
                {badge.label}
              </span>
              <span style={{ color:'#f1f5f9', flex:1, lineHeight:1.6 }}>
                {ev.description}
              </span>
              <span style={{ fontSize:13, fontFamily:"'JetBrains Mono',monospace", color:'#cbd5e1', flexShrink:0, fontWeight:700 }}>
                {Math.round((ev.confidence || 0) * 100)}% conf
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

const STATUS_STYLES = {
  CONFIRMED:    { label: 'CONFIRMED',    bg: 'rgba(239,68,68,0.22)', color: '#f87171', border: 'rgba(239,68,68,0.5)', icon: '🔒' },
  LIKELY:       { label: 'LIKELY',       bg: 'rgba(245,158,11,0.22)', color: '#fbbf24', border: 'rgba(245,158,11,0.5)', icon: '⚡' },
  NEEDS_REVIEW: { label: 'NEEDS REVIEW', bg: 'rgba(56,189,248,0.22)', color: '#38bdf8', border: 'rgba(56,189,248,0.5)', icon: '🔍' },
}

function LimitationsBox({ limitations, unknowns, assumptions }) {
  const hasContent = (limitations && limitations.length > 0) || (unknowns && unknowns.length > 0) || (assumptions && assumptions.length > 0)
  if (!hasContent) return null

  return (
    <div style={{
      background: 'rgba(56,189,248,0.09)',
      border: '1px solid rgba(56,189,248,0.35)',
      borderRadius: 10,
      padding: '16px 20px',
      fontSize: 14.5,
    }}>
      <div style={{ display:'flex', alignItems:'center', gap:8, color: '#38bdf8', fontWeight:700, fontSize:14.5, letterSpacing:'0.05em', textTransform:'uppercase', marginBottom:12 }}>
        <span>⚠️</span> Analysis Limitations & Unknowns
      </div>

      {limitations && limitations.length > 0 && (
        <div style={{ marginBottom:14 }}>
          <div style={{ fontSize:12.5, fontFamily:"'JetBrains Mono',monospace", color:'#93c5fd', fontWeight:700, marginBottom:6, letterSpacing:'0.04em' }}>
            WHY STATIC PROOF IS INCOMPLETE:
          </div>
          <ul style={{ paddingLeft:22, color:'#f1f5f9', lineHeight:1.8, fontSize:14.5 }}>
            {limitations.map((lim, idx) => (
              <li key={idx} style={{ marginBottom:5 }}>{lim}</li>
            ))}
          </ul>
        </div>
      )}

      {unknowns && unknowns.length > 0 && (
        <div style={{ marginBottom:14 }}>
          <div style={{ fontSize:12.5, fontFamily:"'JetBrains Mono',monospace", color:'#93c5fd', fontWeight:700, marginBottom:6, letterSpacing:'0.04em' }}>
            UNOBSERVED RUNTIME / EXTERNAL FACTORS:
          </div>
          <ul style={{ paddingLeft:22, color:'#f1f5f9', lineHeight:1.8, fontSize:14.5 }}>
            {unknowns.map((u, idx) => (
              <li key={idx} style={{ marginBottom:5 }}>{u}</li>
            ))}
          </ul>
        </div>
      )}

      {assumptions && assumptions.length > 0 && (
        <div>
          <div style={{ fontSize:12.5, fontFamily:"'JetBrains Mono',monospace", color:'#cbd5e1', fontWeight:700, marginBottom:6, letterSpacing:'0.04em' }}>
            ANALYZER WORKING ASSUMPTIONS:
          </div>
          <ul style={{ paddingLeft:22, color:'#e2e8f0', lineHeight:1.7, fontSize:14 }}>
            {assumptions.map((a, idx) => (
              <li key={idx} style={{ marginBottom:4 }}>{a}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

function ManualVerificationList({ steps }) {
  if (!steps || steps.length === 0) return null
  return (
    <div>
      <div style={{ fontSize:13, fontFamily:"'JetBrains Mono',monospace", color:'#cbd5e1', letterSpacing:'0.08em', textTransform:'uppercase', fontWeight:700, marginBottom:8 }}>
        Recommended Manual Verification Checklist
      </div>
      <div style={{
        background: 'var(--bg-primary)',
        border: '1px solid var(--border-dim)',
        borderRadius: 8,
        padding: '14px 18px',
        display: 'flex',
        flexDirection: 'column',
        gap: 10,
      }}>
        {steps.map((st, i) => (
          <div key={i} style={{ display:'flex', alignItems:'flex-start', gap:12, fontSize:14.5, color:'#f1f5f9', lineHeight:1.7 }}>
            <span style={{ color:'var(--accent)', flexShrink:0, marginTop:1, fontWeight:700, fontSize:16 }}>☐</span>
            <span>{st}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function LLMAssessmentBox({ assessment }) {
  if (!assessment || !assessment.reviewed) return null

  const verdictStyles = {
    likely_vulnerable: { label: 'Likely Vulnerable', color: '#f87171', bg: 'rgba(248,113,113,0.18)' },
    likely_benign:     { label: 'Likely Benign / Guarded', color: '#4ade80', bg: 'rgba(74,222,128,0.18)' },
    inconclusive:      { label: 'Inconclusive / Incomplete Context', color: '#38bdf8', bg: 'rgba(56,189,248,0.18)' },
  }
  const v = verdictStyles[assessment.verdict] || verdictStyles.inconclusive

  return (
    <div style={{
      background: 'rgba(168,85,247,0.09)',
      border: '1px solid rgba(168,85,247,0.35)',
      borderRadius: 10,
      padding: '16px 20px',
      fontSize: 14.5,
    }}>
      <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:12 }}>
        <div style={{ display:'flex', alignItems:'center', gap:8, color: '#c084fc', fontWeight:700, fontSize:14.5, letterSpacing:'0.05em', textTransform:'uppercase' }}>
          <span>🤖</span> AI Ambiguity Review
        </div>
        <span style={{
          fontSize:12, fontFamily:"'JetBrains Mono',monospace", fontWeight:700,
          padding:'4px 10px', borderRadius:5, background: v.bg, color: v.color,
        }}>
          {v.label}
        </span>
      </div>

      <div style={{ color:'#f1f5f9', lineHeight:1.8, marginBottom:12, fontSize:14.5 }}>
        {assessment.raw_explanation}
      </div>

      {assessment.supporting_evidence && assessment.supporting_evidence.length > 0 && (
        <div style={{ marginTop:10 }}>
          <span style={{ fontSize:12.5, fontFamily:"'JetBrains Mono',monospace", color:'#f87171', fontWeight:700 }}>
            SUPPORTING EVIDENCE:
          </span>
          <ul style={{ paddingLeft:22, color:'#fca5a5', marginTop:5, lineHeight:1.7, fontSize:14 }}>
            {assessment.supporting_evidence.map((s, idx) => <li key={idx} style={{ marginBottom:4 }}>{s}</li>)}
          </ul>
        </div>
      )}

      {assessment.contradicting_evidence && assessment.contradicting_evidence.length > 0 && (
        <div style={{ marginTop:10 }}>
          <span style={{ fontSize:12.5, fontFamily:"'JetBrains Mono',monospace", color:'#4ade80', fontWeight:700 }}>
            CONTRADICTING / MITIGATING FACTORS:
          </span>
          <ul style={{ paddingLeft:22, color:'#86efac', marginTop:5, lineHeight:1.7, fontSize:14 }}>
            {assessment.contradicting_evidence.map((c, idx) => <li key={idx} style={{ marginBottom:4 }}>{c}</li>)}
          </ul>
        </div>
      )}
    </div>
  )
}

function MLVerificationBox({ metadata, cwe }) {
  const ml = metadata?.ml_verification || (metadata?.ml_verification_score !== undefined ? {
    status: metadata?.ml_verification_status || 'VERIFIED',
    ml_verification_score: metadata?.ml_verification_score,
    ml_predicted_valid: metadata?.ml_predicted_valid,
    ml_model: metadata?.ml_model || 'RandomForest',
  } : null)

  const isSupported = ml && ml.status === 'VERIFIED' && ml.ml_verification_score !== null && ml.ml_verification_score !== undefined

  return (
    <div>
      <div style={{ fontSize:13, fontFamily:"'JetBrains Mono',monospace", color:'#cbd5e1', letterSpacing:'0.08em', textTransform:'uppercase', fontWeight:700, marginBottom:8 }}>
        ML Verification (Auxiliary Triage)
      </div>
      <div style={{
        background: 'var(--bg-primary)',
        border: '1px solid var(--border-dim)',
        borderRadius: 8,
        padding: '12px 18px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: 10,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ fontSize: 13.5, color: '#f1f5f9', fontWeight: 600 }}>
            P(True Vulnerability | Static Evidence)
          </span>
          {ml?.ml_model && (
            <span style={{
              fontSize: 11,
              fontFamily: "'JetBrains Mono',monospace",
              color: '#94a3b8',
              background: 'rgba(255,255,255,0.05)',
              padding: '2px 6px',
              borderRadius: 4,
            }}>
              {ml.ml_model}
            </span>
          )}
        </div>

        {isSupported ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span style={{
              fontSize: 15,
              fontFamily: "'JetBrains Mono',monospace",
              fontWeight: 700,
              color: ml.ml_verification_score >= 0.50 ? '#4ade80' : '#fbbf24',
            }}>
              {Math.round(ml.ml_verification_score * 100)}%
            </span>
            <span style={{
              fontSize: 12,
              fontFamily: "'JetBrains Mono',monospace",
              fontWeight: 600,
              padding: '3px 8px',
              borderRadius: 4,
              background: ml.ml_predicted_valid ? 'rgba(74,222,128,0.15)' : 'rgba(251,191,36,0.15)',
              color: ml.ml_predicted_valid ? '#86efac' : '#fde047',
              border: `1px solid ${ml.ml_predicted_valid ? 'rgba(74,222,128,0.35)' : 'rgba(251,191,36,0.35)'}`,
            }}>
              {ml.ml_predicted_valid ? 'Likely genuine vulnerability' : 'Potential false positive'}
            </span>
          </div>
        ) : (
          <span style={{ fontSize: 12.5, fontFamily: "'JetBrains Mono',monospace", color: '#94a3b8' }}>
            Not available for this CWE
          </span>
        )}
      </div>
    </div>
  )
}

export default function VulnCard({ result, index }) {
  const [open, setOpen] = useState(false)
  const sev = SEV_STYLES[result.severity] || SEV_STYLES.LOW
  const srcBadge = SOURCE_BADGES[result.analyzer_source] || (result.evidence && result.evidence.length > 1 ? SOURCE_BADGES.multi_analyzer : SOURCE_BADGES.regex)
  const statusBadge = STATUS_STYLES[result.analysis_status] || STATUS_STYLES.LIKELY

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
          padding:'16px 20px', cursor:'pointer', flexWrap:'nowrap',
        }}
      >
        {/* Severity badge */}
        <span style={{
          fontSize:12, fontFamily:"'JetBrains Mono',monospace", fontWeight:700,
          padding:'5px 10px', borderRadius:5, letterSpacing:'0.05em', flexShrink:0,
          background: sev.bg, color: sev.color, border:`1px solid ${sev.border}`,
        }}>
          {result.severity}
        </span>

        {/* Certainty Status badge */}
        <span style={{
          fontSize:11.5, fontFamily:"'JetBrains Mono',monospace", fontWeight:700,
          padding:'5px 9px', borderRadius:5, letterSpacing:'0.04em', flexShrink:0,
          background: statusBadge.bg, color: statusBadge.color, border:`1px solid ${statusBadge.border}`,
        }}>
          {statusBadge.icon} {statusBadge.label}
        </span>

        {/* Analyzer Source badge */}
        <span style={{
          fontSize:11.5, fontFamily:"'JetBrains Mono',monospace", fontWeight:600,
          padding:'5px 9px', borderRadius:5, letterSpacing:'0.04em', flexShrink:0,
          background: srcBadge.bg, color: srcBadge.color, border:`1px solid ${srcBadge.border}`,
        }}>
          {srcBadge.label}
        </span>

        {/* CWE badge if available */}
        {result.cwe && (
          <span style={{
            fontSize:12, fontFamily:"'JetBrains Mono',monospace", fontWeight:600,
            padding:'4px 8px', borderRadius:5, background:'rgba(255,255,255,0.08)',
            color:'#e2e8f0', border:'1px solid var(--border-subtle)', flexShrink:0,
          }}>
            {result.cwe}
          </span>
        )}

        {/* Type + location */}
        <div style={{ flex:1, minWidth:0, marginLeft:4 }}>
          <div style={{ fontSize:16, fontWeight:700, whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis', color:'#f8fafc' }}>
            {result.vulnerability}
          </div>
          <div style={{ fontSize:13.5, color:'#94a3b8', fontFamily:"'JetBrains Mono',monospace", marginTop:3 }}>
            {result.file}:{result.line}
          </div>
        </div>

        {/* Risk bar */}
        <div style={{ width:85, flexShrink:0 }}>
          <div style={{ fontSize:13, color:'#cbd5e1', fontFamily:"'JetBrains Mono',monospace", textAlign:'right', marginBottom:4, fontWeight:700 }}>
            {Math.round(result.risk_score * 100)}%
          </div>
          <div style={{ height:6, background:'var(--bg-elevated)', borderRadius:3, overflow:'hidden' }}>
            <motion.div
              style={{ height:'100%', borderRadius:3, background: riskColor(result.risk_score) }}
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
          style={{ color:'var(--text-muted)', fontSize:14, flexShrink:0, marginLeft:6 }}
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
            <div style={{ padding:'22px 24px', display:'flex', flexDirection:'column', gap:20 }}>
              {/* Code snippet */}
              {result.code_snippet && (
                <div>
                  <div style={{ fontSize:13, fontFamily:"'JetBrains Mono',monospace", color:'#cbd5e1', letterSpacing:'0.08em', textTransform:'uppercase', fontWeight:700, marginBottom:8 }}>
                    Code Snippet
                  </div>
                  <CodeSnippet snippet={result.code_snippet} vulnLine={result.line} />
                </div>
              )}

              {/* Limitations & Assumptions Callout */}
              <LimitationsBox
                limitations={result.analysis_limitations}
                unknowns={result.unknowns}
                assumptions={result.assumptions}
              />

              {/* Dataflow trace */}
              {result.dataflow_path && result.dataflow_path.length > 0 && (
                <DataflowTrace steps={result.dataflow_path} />
              )}

              {/* Evidence breakdown */}
              {result.evidence && result.evidence.length > 0 && (
                <EvidenceList evidence={result.evidence} />
              )}

              {/* ML Finding Verification (Auxiliary Triage) */}
              <MLVerificationBox metadata={result.metadata} cwe={result.cwe} />

              {/* LLM Ambiguity Review */}
              {result.llm_assessment && (
                <LLMAssessmentBox assessment={result.llm_assessment} />
              )}

              {/* Manual Verification Checklist */}
              {result.recommended_manual_verification && (
                <ManualVerificationList steps={result.recommended_manual_verification} />
              )}

              {/* Explanation */}
              <div>
                <div style={{ fontSize:13, fontFamily:"'JetBrains Mono',monospace", color:'#cbd5e1', letterSpacing:'0.08em', textTransform:'uppercase', fontWeight:700, marginBottom:8 }}>
                  Finding Explanation
                </div>
                <div style={{ fontSize:15, color:'#f1f5f9', lineHeight:1.8, background:'var(--bg-primary)', padding:'14px 18px', borderRadius:8, border:'1px solid var(--border-dim)' }}>
                  {result.explanation}
                </div>
              </div>

              {/* Fix */}
              <div>
                <div style={{ fontSize:13, fontFamily:"'JetBrains Mono',monospace", color:'#cbd5e1', letterSpacing:'0.08em', textTransform:'uppercase', fontWeight:700, marginBottom:8 }}>
                  Remediation Suggestion
                </div>
                <div style={{
                  background:'rgba(74,222,128,0.12)', border:'1px solid rgba(74,222,128,0.35)',
                  borderRadius:8, padding:'14px 18px', fontSize:14.5, color:'#86efac', lineHeight:1.75,
                }}>
                  <span style={{ fontWeight:700, marginRight:8 }}>✓</span>
                  {result.fix}
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}
