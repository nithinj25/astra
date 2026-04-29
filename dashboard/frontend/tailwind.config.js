/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        ds: {
          bg:       '#0b0f1a',
          panel:    '#0f1623',
          panel2:   '#141d2e',
          border:   '#1e2a3a',
          borderhi: '#283a52',
          t1:       '#dce3ef',
          t2:       '#7f8ea3',
          t3:       '#3d4f63',
          green:    '#22c55e',
          amber:    '#f59e0b',
          red:      '#ef4444',
          blue:     '#3b82f6',
          cyan:     '#06b6d4',
          purple:   '#a78bfa',
        },
      },
      fontFamily: {
        sans: ['"Segoe UI"', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"Fira Code"', 'Consolas', 'monospace'],
      },
      animation: {
        'pulse-fast': 'pulse 0.8s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
    },
  },
  plugins: [],
}
