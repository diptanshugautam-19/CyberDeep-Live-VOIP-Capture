/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/live/index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyan: {
          glow: "#00d2ff",
        }
      }
    },
  },
  plugins: [],
}
