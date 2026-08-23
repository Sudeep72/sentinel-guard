/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Dark operations-console surface hierarchy — not a generic
        // near-black; a navy-leaning slate that reads as "console", not
        // "marketing site in dark mode."
        base: {
          950: "#0A0E14",
          900: "#0D1119",
          800: "#12161F",
          700: "#181D28",
          600: "#232936",
        },
        ink: {
          100: "#E4E7EC",
          300: "#B4BBC9",
          500: "#8B93A7",
          700: "#5C6478",
        },
        // Signal blue accent — a technical, slightly cyan-leaning blue
        // rather than the generic indigo-600 SaaS default.
        signal: {
          400: "#6FA3FF",
          500: "#4F8CFF",
          600: "#3A72E0",
        },
        // Severity scale — the core semantic language of the whole app.
        severity: {
          critical: "#EF4444",
          high: "#F97316",
          medium: "#EAB308",
          low: "#3B82F6",
          info: "#6B7280",
        },
        success: "#22C55E",
      },
      fontFamily: {
        sans: [
          "Inter",
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "sans-serif",
        ],
        mono: [
          "JetBrains Mono",
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "monospace",
        ],
      },
      boxShadow: {
        panel: "0 1px 2px rgba(0,0,0,0.4), 0 0 0 1px rgba(255,255,255,0.03)",
      },
    },
  },
  plugins: [],
};
