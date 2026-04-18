/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Syne', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      colors: {
        bg: {
          primary:   '#0a0b0f',
          secondary: '#111318',
          tertiary:  '#191c24',
          elevated:  '#1e2130',
        },
        border: {
          dim:    'rgba(255,255,255,0.07)',
          subtle: 'rgba(255,255,255,0.12)',
          strong: 'rgba(255,255,255,0.20)',
        },
        accent: { DEFAULT: '#4f8fff', muted: '#2d5ccc' },
        risk: {
          critical: '#ff4d4d',
          high:     '#ff8c42',
          medium:   '#ffd43b',
          low:      '#4ade80',
        },
      },
      animation: {
        'spin-slow': 'spin 1.4s linear infinite',
        'pulse-slow': 'pulse 2s cubic-bezier(0.4,0,0.6,1) infinite',
        'fade-in-up': 'fadeInUp 0.35s ease forwards',
      },
      keyframes: {
        fadeInUp: {
          '0%':   { opacity: 0, transform: 'translateY(10px)' },
          '100%': { opacity: 1, transform: 'translateY(0)' },
        },
      },
    },
  },
  plugins: [],
}
