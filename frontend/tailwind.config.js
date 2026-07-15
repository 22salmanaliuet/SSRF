/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#0f1117",
        card: "#1a1d27",
        primary: "#3b82f6",
        critical: "#ef4444",
        high: "#f97316",
        medium: "#eab308",
        low: "#0ea5e9",
        info: "#64748b"
      }
    },
  },
  plugins: [],
}
