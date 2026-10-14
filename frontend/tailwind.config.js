/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        void: '#05080f',
        panel: '#0a101c',
        edge: '#16233b',
        neon: { cyan: '#22d3ee', green: '#34d399', amber: '#fbbf24', red: '#f87171', violet: '#a78bfa' },
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      boxShadow: {
        glow: '0 0 12px rgba(34,211,238,0.35)',
        'glow-red': '0 0 12px rgba(248,113,113,0.45)',
      },
      keyframes: {
        dashmove: { to: { strokeDashoffset: '-24' } },
        pulsered: { '0%,100%': { opacity: 1 }, '50%': { opacity: 0.35 } },
      },
      animation: {
        dashmove: 'dashmove 1s linear infinite',
        pulsered: 'pulsered 1.6s ease-in-out infinite',
      },
    },
  },
  plugins: [],
}
