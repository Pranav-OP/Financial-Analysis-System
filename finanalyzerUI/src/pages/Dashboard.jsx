import React, { useEffect, useState } from "react";
import {
    Box,
    Typography,
    Button,
    TextField,
    Table,
    TableHead,
    TableRow,
    TableCell,
    TableBody,
    Paper,
    LinearProgress,
    Alert,
} from "@mui/material";
import api from "../api/axios";

function Dashboard() {
    const [documents, setDocuments] = useState([]);
    const [selectedFile, setSelectedFile] = useState(null);
    const [query, setQuery] = useState(
        "Analyze this financial document for investment insights"
    );
    const [loading, setLoading] = useState(false);
    const [analysisResults, setAnalysisResults] = useState({});
    const [error, setError] = useState("");
    const [user, setUser] = useState(null); // <-- user info

    useEffect(() => {
        // fetchUser();
        if (localStorage.getItem("access_token")) {
            fetchUser();
        }
        fetchDocuments();
    }, []);

    // Fetch current user to determine roles
    const fetchUser = async () => {
        try {
            // const token = localStorage.getItem("access_token");
            // const res = await api.get("/auth/me", {
            //     headers: { Authorization: `Bearer ${token}` },
            // });
            const res = await api.get("/auth/me"); // interceptor adds token automatically
            setUser(res.data);
        } catch (err) {
            console.error(err);
            setError("Failed to fetch user info.");
        }
    };

    const fetchDocuments = async () => {
        try {
            const res = await api.get("/documents");
            setDocuments(res.data);
        } catch (err) {
            console.error(err);
            setError("Failed to fetch documents.");
        }
    };

    const handleFileChange = (e) => {
        setSelectedFile(e.target.files[0]);
    };

    const handleUpload = async () => {
        if (!selectedFile) return;
        setLoading(true);
        setError("");
        const formData = new FormData();
        formData.append("file", selectedFile);

        try {
            await api.post("/documents/upload", formData, {
                headers: { "Content-Type": "multipart/form-data" },
            });
            setSelectedFile(null);
            fetchDocuments();
        } catch (err) {
            console.error(err);
            setError("Upload failed.");
        } finally {
            setLoading(false);
        }
    };

    const runAnalysis = async (docId) => {
        setLoading(true);
        setError("");
        try {
            const res = await api.post(`/analyses/${docId}`, { query });
            setAnalysisResults((prev) => ({ ...prev, [docId]: res.data }));
        } catch (err) {
            console.error(err);
            setError("Analysis failed.");
        } finally {
            setLoading(false);
        }
    };

    const canUpload = user?.roles.includes("analyst") || user?.roles.includes("admin");
    const canAnalyze = canUpload; // same roles can request analysis

    // helper to safely parse summary if it's JSON inside code block
    const parseSummary = (summary) => {
        if (!summary) return null;
        try {
            const cleaned = summary.replace(/```json|```/g, "").trim();
            return JSON.parse(cleaned);
        } catch {
            return null;
        }
    };

    return (
        <Box>
            <Typography variant="h4" gutterBottom>
                Dashboard
            </Typography>

            {error && <Alert severity="error">{error}</Alert>}

            {/* Upload Section */}
            {canUpload && (
                <Box sx={{ my: 2 }}>
                    <TextField
                        type="file"
                        onChange={handleFileChange}
                        inputProps={{ accept: ".pdf,.docx,.xlsx,.csv,.png,.jpg,.jpeg" }}
                    />
                    <Button variant="contained" onClick={handleUpload} sx={{ ml: 2 }}>
                        Upload
                    </Button>
                </Box>
            )}

            {/* Analysis Query */}
            {canAnalyze && (
                <Box sx={{ my: 2 }}>
                    <TextField
                        label="Analysis Query"
                        fullWidth
                        value={query}
                        onChange={(e) => setQuery(e.target.value)}
                    />
                </Box>
            )}

            {loading && <LinearProgress sx={{ mb: 2 }} />}

            {/* Documents Table */}
            <Paper>
                <Table>
                    <TableHead>
                        <TableRow>
                            <TableCell>Filename</TableCell>
                            <TableCell>Size</TableCell>
                            <TableCell>Status</TableCell>
                            {canAnalyze && <TableCell>Actions</TableCell>}
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {documents.map((doc) => (
                            <TableRow key={doc.id}>
                                <TableCell>{doc.filename}</TableCell>
                                <TableCell>{(doc.size_bytes / 1024).toFixed(2)} KB</TableCell>
                                <TableCell>{doc.status}</TableCell>
                                {canAnalyze && (
                                    <TableCell>
                                        <Button
                                            variant="outlined"
                                            onClick={() => runAnalysis(doc.id)}
                                        >
                                            Analyze
                                        </Button>
                                    </TableCell>
                                )}
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
            </Paper>

            {/* Analysis Results */}
            {Object.keys(analysisResults).length > 0 && (
                <Box sx={{ mt: 4 }}>
                    <Typography variant="h5" gutterBottom>
                        Analysis Results
                    </Typography>
                    {Object.entries(analysisResults).map(([docId, result]) => (
                        <Paper key={docId} sx={{ p: 2, my: 1 }}>
                            <Typography variant="subtitle1">{result.document_id}</Typography>
                            <Typography>Status: <br/>{result.status}</Typography>
                            <Typography>Summary: <br/>{result.summary}</Typography>
                            <Typography>
                                Investment Insights:<br/>{" "}
                                {result.investment_insights.join(", ") || "None"}
                            </Typography>
                            <Typography>
                                Risk Assessment: <br/>{result.risk_assessment.join(", ") || "None"}
                            </Typography>
                        </Paper>
                    ))}
                </Box>
            )}
        </Box>
    );
}

export default Dashboard;
