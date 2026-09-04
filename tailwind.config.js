/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        dark: '#0B0E14',
        surface: '#11161F',
        card: '#141A24',
        borderDark: '#2A3442',
        neonPink: '#EC4F88',
        neonBlue: '#35C7D8',
        slate: '#141A24',
      },
    },
  },
  plugins: [],
}