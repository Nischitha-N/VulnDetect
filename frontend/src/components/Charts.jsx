import { useMemo } from 'react'
import { Bar, Doughnut } from 'react-chartjs-2'
import {
  Chart as ChartJS,
  CategoryScale, LinearScale, BarElement, ArcElement,
  Tooltip, Legend,
} from 'chart.js'

ChartJS.register(CategoryScale, LinearScale, BarElement, ArcElement, Tooltip, Legend)

const BAR_COLORS  = ['#4f8fff','#ff4d4d','#ff8c42','#ffd43b','#4ade80','#2dd4bf','#a78bfa','#f472b6']
const RISK_COLORS = ['#ff4d4d','#ff8c42','#ffd43b','#4ade80']

export default function Charts({ results }) {
  const { typeData, riskData } = useMemo(() => {
    const typeCounts = {}
    const sevCounts  = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0 }

    results.forEach(r => {
      const key = r.vulnerability.split(':')[0].trim()
      typeCounts[key] = (typeCounts[key] || 0) + 1
      if (sevCounts[r.severity] !== undefined) sevCounts[r.severity]++
    })

    return {
      typeData: {
        labels: Object.keys(typeCounts),
        datasets: [{
          data: Object.values(typeCounts),
          backgroundColor: BAR_COLORS,
          borderRadius: 4,
          borderSkipped: false,
        }],
      },
      riskData: {
        labels: ['Critical','High','Medium','Low'],
        datasets: [{
          data: [sevCounts.CRITICAL, sevCounts.HIGH, sevCounts.MEDIUM, sevCounts.LOW],
          backgroundColor: RISK_COLORS,
          borderColor: '#111318',
          borderWidth: 3,
          hoverOffset: 6,
        }],
      },
    }
  }, [results])

  const barOpts = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display:false }, tooltip: { backgroundColor:'#1e2130', titleColor:'#e8eaf0', bodyColor:'#8b90a4', borderColor:'rgba(255,255,255,0.1)', borderWidth:1 } },
    scales: {
      x: { ticks: { color:'#525668', font:{ size:11 }, maxRotation:35 }, grid:{ display:false }, border:{ display:false } },
      y: { ticks: { color:'#525668', font:{ size:11 }, stepSize:1 }, grid:{ color:'rgba(255,255,255,0.05)' }, border:{ display:false } },
    },
  }

  const donutOpts = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: '70%',
    plugins: {
      legend: { position:'right', labels:{ color:'#8b90a4', font:{ size:12 }, boxWidth:10, padding:14 } },
      tooltip: { backgroundColor:'#1e2130', titleColor:'#e8eaf0', bodyColor:'#8b90a4', borderColor:'rgba(255,255,255,0.1)', borderWidth:1 },
    },
  }

  const cardStyle = {
    background:'var(--bg-secondary)', border:'1px solid var(--border-dim)',
    borderRadius:10, padding:'18px 20px',
  }
  const labelStyle = {
    fontSize:11, fontWeight:600, color:'var(--text-secondary)',
    textTransform:'uppercase', letterSpacing:'0.08em',
    fontFamily:"'JetBrains Mono',monospace", marginBottom:14,
  }

  return (
    <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:16, marginBottom:24 }}>
      <div style={cardStyle}>
        <div style={labelStyle}>Vulnerability Distribution</div>
        <div style={{ position:'relative', height:200 }}>
          <Bar data={typeData} options={barOpts} />
        </div>
      </div>
      <div style={cardStyle}>
        <div style={labelStyle}>Risk Level Breakdown</div>
        <div style={{ position:'relative', height:200 }}>
          <Doughnut data={riskData} options={donutOpts} />
        </div>
      </div>
    </div>
  )
}
