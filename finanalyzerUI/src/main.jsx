import React, { useMemo, useState } from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { ThemeProvider, CssBaseline } from "@mui/material";
import App from "./App";
import { ColorModeContext, getDesignTokens } from "./theme";

function Root() {
  const [mode, setMode] = useState(
    () => localStorage.getItem("color_mode") || "light"
  );

  const colorMode = useMemo(
    () => ({
      mode,
      toggle: () =>
        setMode((prev) => {
          const next = prev === "light" ? "dark" : "light";
          localStorage.setItem("color_mode", next);
          return next;
        }),
    }),
    [mode]
  );

  const theme = useMemo(() => getDesignTokens(mode), [mode]);

  return (
    <ColorModeContext.Provider value={colorMode}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <BrowserRouter>
          <Routes>
            <Route path="/*" element={<App />} />
          </Routes>
        </BrowserRouter>
      </ThemeProvider>
    </ColorModeContext.Provider>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>
);
