import React, { useState, useEffect, useContext } from "react";
import { Routes, Route, Link, Navigate } from "react-router-dom";
import {
  AppBar, Toolbar, Button, Container, Typography, Box, Stack, IconButton, Tooltip,
} from "@mui/material";
import {
  InsightsRounded, DarkModeRounded, LightModeRounded, LogoutRounded,
  UploadFileRounded, QueryStatsRounded, ShieldRounded,
} from "@mui/icons-material";

import Login from "./pages/Login";
import Register from "./pages/Register";
import Dashboard from "./pages/Dashboard";
import ProtectedRoute from "./components/ProtectedRoute";
import { ColorModeContext } from "./theme";

function Brand() {
  return (
    <Stack direction="row" alignItems="center" spacing={1} component={Link}
      to="/" sx={{ textDecoration: "none", color: "inherit", flexGrow: 1 }}>
      <Box sx={{
        display: "grid", placeItems: "center", width: 36, height: 36, borderRadius: 2,
        background: "linear-gradient(135deg,#4f46e5,#10b981)", color: "#fff",
      }}>
        <InsightsRounded fontSize="small" />
      </Box>
      <Typography variant="h6" sx={{ fontWeight: 800, letterSpacing: -0.5 }}>
        Finanalyzer
      </Typography>
    </Stack>
  );
}

function Landing() {
  const features = [
    { icon: <UploadFileRounded />, title: "Upload filings", desc: "PDF earnings reports, 10-Ks, investor decks." },
    { icon: <QueryStatsRounded />, title: "AI analysis", desc: "Retrieval-augmented, figure-grounded insights." },
    { icon: <ShieldRounded />, title: "Risk & advice", desc: "Risk matrix and compliant recommendations." },
  ];
  return (
    <Box sx={{ textAlign: "center", mt: { xs: 4, md: 8 } }}>
      <Typography variant="h3" sx={{ fontWeight: 800, letterSpacing: -1, mb: 1.5 }}>
        Understand any financial document
      </Typography>
      <Typography variant="h6" color="text.secondary" sx={{ maxWidth: 620, mx: "auto", fontWeight: 400 }}>
        Upload a report and let a crew of AI analysts extract metrics, surface risks,
        and draft investment insights — grounded in the source.
      </Typography>
      <Stack direction="row" spacing={2} justifyContent="center" sx={{ mt: 4 }}>
        <Button size="large" variant="contained" component={Link} to="/register">
          Get started
        </Button>
        <Button size="large" variant="outlined" component={Link} to="/login">
          Sign in
        </Button>
      </Stack>
      <Box sx={{
        mt: 7, display: "grid", gap: 2,
        gridTemplateColumns: { xs: "1fr", md: "repeat(3,1fr)" },
      }}>
        {features.map((f) => (
          <Box key={f.title} sx={{
            p: 3, borderRadius: 3, textAlign: "left",
            bgcolor: "background.paper", border: "1px solid", borderColor: "divider",
          }}>
            <Box sx={{ color: "primary.main", mb: 1 }}>{f.icon}</Box>
            <Typography variant="subtitle1">{f.title}</Typography>
            <Typography variant="body2" color="text.secondary">{f.desc}</Typography>
          </Box>
        ))}
      </Box>
    </Box>
  );
}

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(!!localStorage.getItem("access_token"));
  const colorMode = useContext(ColorModeContext);

  const handleLogout = () => {
    localStorage.clear();
    setIsAuthenticated(false);
  };

  useEffect(() => {
    setIsAuthenticated(!!localStorage.getItem("access_token"));
  }, []);

  return (
    <Box sx={{ minHeight: "100vh", bgcolor: "background.default" }}>
      <AppBar position="sticky" elevation={0}
        sx={{ bgcolor: "background.paper", color: "text.primary", borderBottom: "1px solid", borderColor: "divider" }}>
        <Toolbar>
          <Brand />
          <Stack direction="row" spacing={1} alignItems="center">
            <Tooltip title={colorMode.mode === "dark" ? "Light mode" : "Dark mode"}>
              <IconButton onClick={colorMode.toggle} color="inherit">
                {colorMode.mode === "dark" ? <LightModeRounded /> : <DarkModeRounded />}
              </IconButton>
            </Tooltip>
            {!isAuthenticated ? (
              <>
                <Button color="inherit" component={Link} to="/login">Login</Button>
                <Button variant="contained" component={Link} to="/register">Register</Button>
              </>
            ) : (
              <Button color="inherit" startIcon={<LogoutRounded />} onClick={handleLogout}>
                Logout
              </Button>
            )}
          </Stack>
        </Toolbar>
      </AppBar>

      <Container maxWidth="lg" sx={{ mt: 4, mb: 6 }}>
        <Routes>
          <Route path="/" element={isAuthenticated ? <Navigate to="/dashboard" replace /> : <Landing />} />
          <Route path="/login"
            element={isAuthenticated ? <Navigate to="/dashboard" replace /> : <Login setIsAuthenticated={setIsAuthenticated} />} />
          <Route path="/register"
            element={isAuthenticated ? <Navigate to="/dashboard" replace /> : <Register />} />
          <Route path="/dashboard"
            element={
              <ProtectedRoute allowedRoles={["viewer", "analyst", "admin"]}>
                <Dashboard />
              </ProtectedRoute>
            } />
        </Routes>
      </Container>
    </Box>
  );
}

export default App;
