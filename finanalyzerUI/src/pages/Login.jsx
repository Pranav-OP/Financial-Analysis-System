import React, { useState } from "react";
import { TextField, Button, Box, Typography, Alert, Card, CardContent } from "@mui/material";
import { useNavigate } from "react-router-dom";
import api from "../api/axios";

function Login({ setIsAuthenticated }) {
    const [form, setForm] = useState({ username: "", password: "" });
    const [error, setError] = useState("");
    const navigate = useNavigate();

    const handleChange = (e) => setForm({ ...form, [e.target.name]: e.target.value });

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError("");

        try {
            const res = await api.post(
                "/auth/login",
                new URLSearchParams({
                    username: form.username,
                    password: form.password,
                })
            );
            localStorage.setItem("access_token", res.data.access_token);
            localStorage.setItem("refresh_token", res.data.refresh_token);

            // Store role from JWT (decoded in backend, we can optionally add role field in response)
            const payload = JSON.parse(atob(res.data.access_token.split(".")[1]));
            localStorage.setItem("role", payload.roles[0]); // assuming single role for simplicity

            // Update App state for logout button to appear
            setIsAuthenticated(true);
            navigate("/dashboard");
        } catch (err) {
            setError(err.response?.data?.detail || "Login failed");
        }
    };

    return (
        <Box sx={{ display: "flex", justifyContent: "center", mt: 10 }}>
            <Card sx={{ width: 400, p: 3 }}>
                <CardContent>
                    <Typography variant="h5" gutterBottom align="center">
                        Login
                    </Typography>
                    {error && <Alert severity="error">{error}</Alert>}
                    <form onSubmit={handleSubmit}>
                        <TextField
                            label="Username"
                            name="username"
                            fullWidth
                            margin="normal"
                            value={form.username}
                            onChange={handleChange}
                        />
                        <TextField
                            label="Password"
                            name="password"
                            type="password"
                            fullWidth
                            margin="normal"
                            value={form.password}
                            onChange={handleChange}
                        />
                        <Button type="submit" variant="contained" fullWidth sx={{ mt: 2 }}>
                            Login
                        </Button>
                    </form>
                </CardContent>
            </Card>
        </Box>
    );
}

export default Login;
