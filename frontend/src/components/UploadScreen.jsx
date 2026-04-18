import { useCallback } from 'react'
import { useDropzone } from 'react-dropzone'
import { motion } from 'framer-motion'
import { useScan } from '../hooks/useScan'

const ACCEPTED = {
  'text/x-c': ['.c', '.h'],
  'text/x-c++': ['.cpp', '.cc', '.cxx', '.hpp'],
  'application/zip': ['.zip'],
}

const DEMO_CARDS = [
  {
    key: 'demo1',
    title: 'vulnerable_app.c',
    desc: 'gets(), strcpy(), sprintf() — 7 classic buffer overflow vulnerabilities',
    tag: '7 CRITICAL',
  },
  {
    key: 'demo2',
    title: 'string_utils.cpp',
    desc: 'strcat(), unchecked malloc(), double free — memory management issues',
    tag: '3 HIGH',
  },
  {
    key: 'demo3',
    title: 'auth_handler.c',
    desc: 'system(), printf format string, scanf %s — authentication bypass risks',
    tag: '5 CRITICAL',
  },
]

export default function UploadScreen({ onLoadDemo }) {
  const { run } = useScan()

  const onDrop = useCallback((accepted) => {
    if (accepted[0]) run(accepted[0])
  }, [run])

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: ACCEPTED,
    maxFiles: 1,
  })

  return (
    <div style={{
      display:'flex', flexDirection:'column', alignItems:'center',
      justifyContent:'center', minHeight:'calc(100vh - 61px)',
      padding:'40px 24px', gap: 28,
    }}>
      {/* Hero text */}
      <motion.div
        initial={{ opacity:0, y:16 }}
        animate={{ opacity:1, y:0 }}
        transition={{ duration:0.5 }}
        style={{ textAlign:'center', maxWidth: 520 }}
      >
        <h1 style={{
          fontSize: 34, fontWeight: 800, letterSpacing: '-0.03em',
          marginBottom: 10,
          background: 'linear-gradient(135deg, #e8eaf0 30%, #6b7aa0)',
          WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
        }}>
          Detect Code Vulnerabilities
        </h1>
        <p style={{ fontSize: 14, color: 'var(--text-secondary)', lineHeight: 1.7 }}>
          Upload C or C++ source files for AI-powered vulnerability detection using
          static analysis and machine learning. Get risk scores, explanations, and fix suggestions.
        </p>
      </motion.div>

      {/* Drop zone */}
      <motion.div
        {...getRootProps()}
        initial={{ opacity:0, y:12 }}
        animate={{ opacity:1, y:0 }}
        transition={{ duration:0.5, delay:0.1 }}
        style={{
          width: '100%', maxWidth: 540,
          border: `2px dashed ${isDragActive ? 'var(--accent)' : 'var(--border-subtle)'}`,
          borderRadius: 16,
          padding: '48px 32px',
          textAlign: 'center',
          cursor: 'pointer',
          background: isDragActive ? 'rgba(79,143,255,0.06)' : 'var(--bg-secondary)',
          transition: 'all 0.2s',
          position: 'relative',
          overflow: 'hidden',
        }}
      >
        {/* Subtle top glow */}
        <div style={{
          position:'absolute', inset:0,
          background:'radial-gradient(ellipse at 50% 0%, rgba(79,143,255,0.07) 0%, transparent 70%)',
          pointerEvents:'none',
        }}/>
        <input {...getInputProps()} />

        <div style={{ fontSize: 40, marginBottom: 14 }}>
          {isDragActive ? '🎯' : '📁'}
        </div>
        <div style={{ fontSize:16, fontWeight:600, marginBottom:6 }}>
          {isDragActive ? 'Drop to scan' : 'Drop your files here'}
        </div>
        <div style={{ fontSize:13, color:'var(--text-secondary)', marginBottom:20 }}>
          or click to browse from your computer
        </div>
        <div style={{ display:'flex', gap:6, justifyContent:'center', flexWrap:'wrap' }}>
          {['.c','.cpp','.h','.hpp','.zip'].map(ext => (
            <span key={ext} style={{
              fontFamily:"'JetBrains Mono',monospace", fontSize:11,
              background:'var(--bg-elevated)', border:'1px solid var(--border-subtle)',
              borderRadius:5, padding:'3px 9px', color:'var(--text-secondary)',
            }}>{ext}</span>
          ))}
        </div>
      </motion.div>

      {/* OR divider */}
      <motion.div
        initial={{ opacity:0 }}
        animate={{ opacity:1 }}
        transition={{ delay:0.25 }}
        style={{ display:'flex', alignItems:'center', gap:12, width:'100%', maxWidth:540, color:'var(--text-muted)', fontSize:12 }}
      >
        <div style={{ flex:1, height:1, background:'var(--border-dim)' }}/>
        or try a demo
        <div style={{ flex:1, height:1, background:'var(--border-dim)' }}/>
      </motion.div>

      {/* Demo cards */}
      <div style={{ display:'flex', flexDirection:'column', gap:8, width:'100%', maxWidth:540 }}>
        {DEMO_CARDS.map((d, i) => (
          <motion.button
            key={d.key}
            onClick={() => onLoadDemo(d.key)}
            initial={{ opacity:0, y:8 }}
            animate={{ opacity:1, y:0 }}
            transition={{ delay: 0.3 + i*0.08 }}
            whileHover={{ x: 4 }}
            style={{
              display:'flex', alignItems:'center', gap:14,
              background:'var(--bg-tertiary)', border:'1px solid var(--border-dim)',
              borderRadius:9, padding:'12px 16px',
              cursor:'pointer', textAlign:'left', width:'100%',
              transition:'border-color 0.15s',
              fontFamily:"'Syne',sans-serif",
            }}
          >
            <div style={{ flex:1 }}>
              <div style={{ fontWeight:600, fontSize:13, marginBottom:3, fontFamily:"'JetBrains Mono',monospace", color:'var(--text-primary)' }}>
                {d.title}
              </div>
              <div style={{ fontSize:12, color:'var(--text-secondary)' }}>{d.desc}</div>
            </div>
            <span style={{
              fontSize:10, fontFamily:"'JetBrains Mono',monospace", fontWeight:600,
              padding:'3px 8px', borderRadius:4, flexShrink:0,
              background:'rgba(255,77,77,0.12)', color:'var(--risk-critical)',
              border:'1px solid rgba(255,77,77,0.25)',
            }}>{d.tag}</span>
          </motion.button>
        ))}
      </div>
    </div>
  )
}
