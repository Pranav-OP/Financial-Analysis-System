import React, { useState } from "react";
import {
  TextField, Button, Box, Typography, Alert, Card, CardContent, Stack, Link as MuiLink,
} from "@mui/material";
import { LoginRounded } from "@mui/icons-material";
import { useNavigate, Link } from "react-router-dom";
import api from "../api/axios";

function Login({ setIsAuthenticated }) {
  const [form, setForm] = useState({ username: "", password: "" });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleChange = (e) => setForm({ ...form, [e.target.name]: e.target.value });

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await api.post(
        "/auth/login",
        new URLSearchParams({ username: form.username, password: form.password })
      );
      localStorage.setItem("access_token", res.data.access_token);
      localStorage.setItem("refresh_token", res.data.refresh_token);
      const payload = JSON.parse(atob(res.data.access_token.split(".")[1]));
      localStorage.setItem("role", payload.roles?.[0] || "analyst");
      setIsAuthenticated(true);
      navigate("/dashboard");
    } catch (err) {
      setError(err.response?.data?.detail || "Login failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box sx={{ display: "flex", justifyContent: "center", mt: { xs: 4, md: 8 } }}>
      <Card sx={{ width: 420, borderRadius: 4 }}>
        <Box sx={{ height: 6, background: "linear-gradient(90deg,#4f46e5,#10b981)" }} />
        <CardContent sx={{ p: 4 }}>
          <Typography variant="h5" gutterBottom sx={{ fontWeight: 800 }}>
            Welcome back
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Sign in to analyze your financial documents.
          </Typography>
          {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
          <form onSubmit={handleSubmit}>
            <Stack spacing={2}>
              <TextField label="Username" name="username" fullWidth
                value={form.username} onChange={handleChange} autoFocus />
              <TextField label="Password" name="password" type="password" fullWidth
                value={form.password} onChange={handleChange} />
              <Button type="submit" variant="contained" size="large" fullWidth
                startIcon={<LoginRounded />} disabled={loading}>
                {loading ? "Signing in…" : "Sign in"}
              </Button>
            </Stack>
          </form>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 3, textAlign: "center" }}>
            No account?{" "}
            <MuiLink component={Link} to="/register" underline="hover">Create one</MuiLink>
          </Typography>
        </CardContent>
      </Card>
    </Box>
  );
}

export default Login;
