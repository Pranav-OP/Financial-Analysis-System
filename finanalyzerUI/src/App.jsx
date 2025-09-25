import React, { useState, useEffect } from "react";
import { Routes, Route, Link, Navigate } from "react-router-dom";
import { AppBar, Toolbar, Button, Container, Typography, Box, Card, CardContent } from "@mui/material";

import Login from "./pages/Login";
import Register from "./pages/Register";
import Dashboard from "./pages/Dashboard";
import ProtectedRoute from "./components/ProtectedRoute";

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(!!localStorage.getItem("access_token"));

  const handleLogout = () => {
    localStorage.clear();
    setIsAuthenticated(false);
  };

  // Optionally, check localStorage on mount in case token exists
  useEffect(() => {
    setIsAuthenticated(!!localStorage.getItem("access_token"));
  }, []);

  return (
    <>
      {/* Navigation Bar */}
      <AppBar position="static">
        <Toolbar>
          <Typography variant="h6" sx={{ flexGrow: 1 }}>
            Finanalyzer
          </Typography>
          {!isAuthenticated ? (
            <>
              <Button color="inherit" component={Link} to="/login">Login</Button>
              <Button color="inherit" component={Link} to="/register">Register</Button>
            </>
          ) : (
            <Button color="inherit" onClick={handleLogout}>Logout</Button>
          )}
        </Toolbar>
      </AppBar>

      {/* Page Content */}
      <Container sx={{ mt: 4, mb: 4 }}>
        <Routes>
          <Route
            path="/"
            element={
              <Box sx={{ display: "flex", justifyContent: "center", mt: 10 }}>
                <Card sx={{ width: 500, p: 4, textAlign: "center" }}>
                  <CardContent>
                    <Typography variant="h4" gutterBottom>
                      Welcome to Finanalyzer
                    </Typography>
                    <Typography variant="body1" gutterBottom>
                      Your one-stop platform to upload, analyze, and assess financial documents.
                    </Typography>
                    <Box sx={{ mt: 3, display: "flex", justifyContent: "center", gap: 2 }}>
                      <Button variant="contained" component={Link} to="/login">
                        Login
                      </Button>
                      <Button variant="outlined" component={Link} to="/register">
                        Register
                      </Button>
                    </Box>
                  </CardContent>
                </Card>
              </Box>
            }
          />

          {/* Other Pages */}
          <Route
            path="/login"
            element={isAuthenticated ? <Navigate to="/dashboard" replace /> : <Login setIsAuthenticated={setIsAuthenticated} />}/>
          <Route
            path="/register"
            element={isAuthenticated ? <Navigate to="/dashboard" replace /> : <Register />}/>
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute allowedRoles={["viewer", "analyst", "admin"]}>
                <Dashboard />
              </ProtectedRoute>
            }
          />
        </Routes>
      </Container>
    </>
  );
}

export default App;