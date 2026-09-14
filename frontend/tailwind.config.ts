import type { Config } from 'tailwindcss'

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        threat: {
          low: '#16a34a',
          medium: '#ca8a04',
          high: '#dc2626',
        },
      },
    },
  },
  plugins: [],
} satisfies Config
