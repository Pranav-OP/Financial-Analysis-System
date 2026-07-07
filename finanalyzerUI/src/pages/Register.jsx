import React, { useState } from "react";
import {
  TextField, Button, Box, Typography, Alert, Card, CardContent, Stack, Link as MuiLink,
} from "@mui/material";
import { PersonAddRounded } from "@mui/icons-material";
import { useNavigate, Link } from "react-router-dom";
import api from "../api/axios";

function Register() {
  const [form, setForm] = useState({ email: "", username: "", password: "", full_name: "" });
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleChange = (e) => setForm({ ...form, [e.target.name]: e.target.value });

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await api.post("/auth/register", form);
      setSuccess("Account created! Redirecting to sign in…");
      setTimeout(() => navigate("/login"), 900);
    } catch (err) {
      setError(err.response?.data?.detail || "Registration failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box sx={{ display: "flex", justifyContent: "center", mt: { xs: 4, md: 6 } }}>
      <Card sx={{ width: 440, borderRadius: 4 }}>
        <Box sx={{ height: 6, background: "linear-gradient(90deg,#4f46e5,#10b981)" }} />
        <CardContent sx={{ p: 4 }}>
          <Typography variant="h5" gutterBottom sx={{ fontWeight: 800 }}>
            Create your account
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Start analyzing financial documents in minutes.
          </Typography>
          {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
          {success && <Alert severity="success" sx={{ mb: 2 }}>{success}</Alert>}
          <form onSubmit={handleSubmit}>
            <Stack spacing={2}>
              <TextField label="Full Name" name="full_name" fullWidth
                value={form.full_name} onChange={handleChange} />
              <TextField label="Username" name="username" fullWidth
                value={form.username} onChange={handleChange} />
              <TextField label="Email" name="email" type="email" fullWidth
                value={form.email} onChange={handleChange} />
              <TextField label="Password" name="password" type="password" fullWidth
                helperText="At least 6 characters" value={form.password} onChange={handleChange} />
              <Button type="submit" variant="contained" size="large" fullWidth
                startIcon={<PersonAddRounded />} disabled={loading}>
                {loading ? "Creating…" : "Create account"}
              </Button>
            </Stack>
          </form>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 3, textAlign: "center" }}>
            Already registered?{" "}
            <MuiLink component={Link} to="/login" underline="hover">Sign in</MuiLink>
          </Typography>
        </CardContent>
      </Card>
    </Box>
  );
}

export default Register;
