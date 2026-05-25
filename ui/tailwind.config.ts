import type { Config } from 'tailwindcss';

const config: Config = {
  content: ['./app/**/*.{ts,tsx}', './components/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg:       { DEFAULT: '#0b0d12', soft: '#11141b', card: '#171a23' },
        line:     '#252a36',
        ink:      { DEFAULT: '#e6e9ef', dim: '#8a93a6', faint: '#5d6577' },
        accent:   { DEFAULT: '#7aa2ff', soft: '#1f2a44' },
        ok:       { DEFAULT: '#5dd6a8', soft: '#10261f' },
        warn:     { DEFAULT: '#f1c25b', soft: '#2b2410' },
        danger:   { DEFAULT: '#ff6b7a', soft: '#2b1015' },
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
    },
  },
  plugins: [],
};
export default config;
