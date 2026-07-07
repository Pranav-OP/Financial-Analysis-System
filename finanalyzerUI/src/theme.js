import { createContext } from "react";
import { createTheme } from "@mui/material/styles";

// Toggled from the AppBar; consumed by main.jsx to rebuild the theme.
export const ColorModeContext = createContext({ mode: "light", toggle: () => {} });

export function getDesignTokens(mode) {
  const isDark = mode === "dark";
  return createTheme({
    palette: {
      mode,
      primary: { main: "#4f46e5" },      // indigo
      secondary: { main: "#10b981" },    // emerald
      success: { main: "#16a34a" },
      warning: { main: "#f59e0b" },
      error: { main: "#dc2626" },
      background: {
        default: isDark ? "#0b1120" : "#f4f6fb",
        paper: isDark ? "#111a2e" : "#ffffff",
      },
    },
    shape: { borderRadius: 14 },
    typography: {
      fontFamily:
        '"Inter","Segoe UI",system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif',
      h4: { fontWeight: 700, letterSpacing: -0.5 },
      h5: { fontWeight: 700 },
      h6: { fontWeight: 700 },
      subtitle1: { fontWeight: 600 },
      subtitle2: { fontWeight: 600 },
      button: { textTransform: "none", fontWeight: 600 },
    },
    components: {
      MuiCard: {
        styleOverrides: {
          root: {
            backgroundImage: "none",
            border: isDark ? "1px solid #1e293b" : "1px solid #eceef4",
            boxShadow: isDark
              ? "0 1px 2px rgba(0,0,0,0.5)"
              : "0 1px 3px rgba(16,24,40,0.06), 0 1px 2px rgba(16,24,40,0.04)",
          },
        },
      },
      MuiButton: { defaultProps: { disableElevation: true } },
      MuiPaper: { styleOverrides: { root: { backgroundImage: "none" } } },
      MuiTableCell: {
        styleOverrides: {
          head: { fontWeight: 700, color: isDark ? "#94a3b8" : "#64748b" },
        },
      },
      MuiChip: { styleOverrides: { root: { fontWeight: 600 } } },
    },
  });
}
