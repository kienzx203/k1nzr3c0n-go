/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        surface: '#161b22',
        border: '#30363d',
        accent: '#238636',
        blue: { DEFAULT: '#58a6ff' },
        green: { DEFAULT: '#3fb950' },
        red: { DEFAULT: '#f85149' },
        yellow: { DEFAULT: '#d29922' },
      },
      fontFamily: {
        mono: ['Cascadia Code', 'Fira Code', 'ui-monospace', 'monospace'],
      },
    },
  },
  plugins: [],
}
