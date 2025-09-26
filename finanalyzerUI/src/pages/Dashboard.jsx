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
    Card,
    CardContent,
    Divider,
    Chip,
    Stack,
} from "@mui/material";
import api from "../api/axios";

function Dashboard() {
    const [documents, setDocuments] = useState([]);
    const [analyses, setAnalyses] = useState([]);
    const [selectedFile, setSelectedFile] = useState(null);
    const [query, setQuery] = useState("Analyze this financial document for investment insights");
    const [loading, setLoading] = useState(false);
    const [analysisResults, setAnalysisResults] = useState({});
    const [error, setError] = useState("");
    const [user, setUser] = useState(null);

    useEffect(() => {
        if (localStorage.getItem("access_token")) {
            fetchUser();
        }
        fetchDocuments();
        fetchAnalyses();
    }, []);

    const fetchUser = async () => {
        try {
            const res = await api.get("/auth/me");
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

    const fetchAnalyses = async () => {
        try {
            const res = await api.get("/analyses");
            setAnalyses(res.data);
        } catch (err) {
            console.error(err);
            setError("Failed to fetch analyses.");
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
            fetchAnalyses();
        } catch (err) {
            console.error(err);
            setError("Analysis failed.");
        } finally {
            setLoading(false);
        }
    };

    const handleDelete = async (docId) => {
        if (!window.confirm("Are you sure you want to delete this document?")) return;
        try {
            await api.delete(`/documents/${docId}`);
            fetchDocuments();
        } catch (err) {
            console.error(err);
            setError("Delete failed.");
        }
    };

    const handleDownload = async (docId, filename) => {
        try {
            const res = await api.get(`/documents/${docId}/download`, {
                responseType: "blob", // important for binary data
            });

            // create a link and click it programmatically
            const url = window.URL.createObjectURL(new Blob([res.data]));
            const link = document.createElement("a");
            link.href = url;
            link.setAttribute("download", filename || `document_${docId}.pdf`);
            document.body.appendChild(link);
            link.click();
            link.remove();
        } catch (err) {
            console.error(err);
            alert("Download failed.");
        }
    };


    const handleExport = async (analysisId, filename = "analysis_export.pdf") => {
        try {
            const res = await api.get(`/analyses/${analysisId}/export`, {
                responseType: "blob",
            });

            const url = window.URL.createObjectURL(new Blob([res.data]));
            const link = document.createElement("a");
            link.href = url;
            link.setAttribute("download", filename);
            document.body.appendChild(link);
            link.click();
            link.remove();
        } catch (err) {
            console.error(err);
            alert("Export failed.");
        }
    };


    const canUpload = user?.roles.includes("analyst") || user?.roles.includes("admin");
    const canAnalyze = canUpload;

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

    const parseJsonMaybe = (text) => {
        if (!text) return null;
        try {
          const cleaned = typeof text === "string" ? text.replace(/```json|```/g, "").trim() : text;
          return typeof cleaned === "string" ? JSON.parse(cleaned) : cleaned;
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
            <Typography variant="h6" sx={{ mt: 3, mb: 1 }}>
                Documents
            </Typography>
            <Paper>
                <Table>
                    <TableHead>
                        <TableRow>
                            <TableCell>Filename</TableCell>
                            <TableCell>Size</TableCell>
                            <TableCell>Status</TableCell>
                            <TableCell>Actions</TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {documents.map((doc) => (
                            <TableRow key={doc.id}>
                                <TableCell>{doc.filename}</TableCell>
                                <TableCell>{(doc.size_bytes / 1024).toFixed(2)} KB</TableCell>
                                <TableCell>{doc.status}</TableCell>
                                <TableCell>
                                    <Stack direction="row" spacing={1}>
                                        <Button variant="outlined" onClick={() => handleDownload(doc.id, doc.filename)}>
                                            Download
                                        </Button>
                                        {canAnalyze && (
                                            <Button variant="outlined" onClick={() => runAnalysis(doc.id)}>
                                                Analyze
                                            </Button>
                                        )}
                                        <Button variant="outlined" color="error" onClick={() => handleDelete(doc.id)}>
                                            Delete
                                        </Button>
                                    </Stack>
                                </TableCell>
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
            </Paper>

            {/* Analysis Results */}
            {Object.keys(analysisResults).length > 0 && (
                <Box sx={{ mt: 4 }}>
                    <Typography variant="h5" gutterBottom>
                        Latest Analysis Results
                    </Typography>
                    {Object.entries(analysisResults).map(([docId, result]) => {
                        const parsedSummary = parseSummary(result.summary);
                        return (
                            <Card key={docId} sx={{ mb: 2 }}>
                                <CardContent>
                                    <Typography variant="h6" gutterBottom>
                                        Document ID: {result.document_id}
                                    </Typography>
                                    <Chip
                                        label={`Status: ${result.status}`}
                                        color={result.status === "completed" ? "success" : "warning"}
                                        sx={{ mb: 2 }}
                                    />
                                    <Divider sx={{ my: 1 }} />
                                    <Typography variant="subtitle1" gutterBottom>
                                        Summary:
                                    </Typography>
                                    {parsedSummary ? (
                                        <pre style={{
                                            background: "#f5f5f5", padding: "8px", borderRadius: "4px", whiteSpace: "pre-wrap",
                                            wordWrap: "break-word", overflowX: "auto", maxWidth: "100%",
                                        }}>
                                            {JSON.stringify(parsedSummary, null, 2)}
                                        </pre>
                                    ) : (
                                        <Typography>{result.summary || "N/A"}</Typography>
                                    )}
                                     <Divider sx={{ my: 2 }} />
                                    {/*<Typography variant="subtitle1">Investment Insights:</Typography>
                                    {Array.isArray(result.investment_insights) &&
                                        result.investment_insights.length > 0 ? (
                                        <ul>
                                            {result.investment_insights.map((ins, idx) => (
                                                <li key={idx}>{ins}</li>
                                            ))}
                                        </ul>
                                    ) : (
                                        <Typography color="text.secondary">None</Typography>
                                    )}
                                    <Divider sx={{ my: 2 }} />
                                    <Typography variant="subtitle1">Risk Assessment:</Typography>
                                    {Array.isArray(result.risk_assessment) &&
                                        result.risk_assessment.length > 0 ? (
                                        <ul>
                                            {result.risk_assessment.map((risk, idx) => (
                                                <li key={idx}>{risk}</li>
                                            ))}
                                        </ul>
                                    ) : (
                                        <Typography color="text.secondary">None</Typography>
                                    )} */}
                                    <Typography variant="subtitle1">Investment Insights:</Typography>
                                    {(() => {
                                        const parsed = parseJsonMaybe(result.investment_insights);
                                        if (parsed) {
                                            return (
                                                <pre style={{ background: "#f5f5f5", padding: "8px", borderRadius: "4px", whiteSpace: "pre-wrap", wordWrap: "break-word", overflowX: "auto" }}>
                                                    {JSON.stringify(parsed, null, 2)}
                                                </pre>
                                            );
                                        }
                                        if (Array.isArray(result.investment_insights) && result.investment_insights.length > 0) {
                                            return (
                                                <ul>
                                                    {result.investment_insights.map((ins, idx) => (<li key={idx}>{ins}</li>))}
                                                </ul>
                                            );
                                        }
                                        if (typeof result.investment_insights === "string" && result.investment_insights.trim()) {
                                            return <pre style={{ background: "#f5f5f5", padding: "8px", borderRadius: "4px", whiteSpace: "pre-wrap" }}>{result.investment_insights}</pre>;
                                        }
                                        return <Typography color="text.secondary">None</Typography>;
                                    })()}
                                    <Divider sx={{ my: 2 }} />
                                    <Typography variant="subtitle1">Risk Assessment:</Typography>
                                    {(() => {
                                        const parsed = parseJsonMaybe(result.risk_assessment);
                                        if (parsed) {
                                            return (
                                                <pre style={{ background: "#f5f5f5", padding: "8px", borderRadius: "4px", whiteSpace: "pre-wrap", wordWrap: "break-word", overflowX: "auto" }}>
                                                    {JSON.stringify(parsed, null, 2)}
                                                </pre>
                                            );
                                        }
                                        if (Array.isArray(result.risk_assessment) && result.risk_assessment.length > 0) {
                                            return (
                                                <ul>
                                                    {result.risk_assessment.map((risk, idx) => (<li key={idx}>{risk}</li>))}
                                                </ul>
                                            );
                                        }
                                        if (typeof result.risk_assessment === "string" && result.risk_assessment.trim()) {
                                            return <pre style={{ background: "#f5f5f5", padding: "8px", borderRadius: "4px", whiteSpace: "pre-wrap" }}>{result.risk_assessment}</pre>;
                                        }
                                        return <Typography color="text.secondary">None</Typography>;
                                    })()}

                                </CardContent>
                            </Card>
                        );
                    })}
                </Box>
            )}

            {/* Analysis History */}
            <Typography variant="h6" sx={{ mt: 4, mb: 1 }}>
                Analysis History
            </Typography>
            <Paper>
                <Table>
                    <TableHead>
                        <TableRow>
                            <TableCell>Analysis ID</TableCell>
                            <TableCell>Document</TableCell>
                            <TableCell>Query</TableCell>
                            <TableCell>Status</TableCell>
                            <TableCell>Created</TableCell>
                            <TableCell>Actions</TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {analyses.map((a) => (
                            <TableRow key={a.id}>
                                <TableCell>{a.id}</TableCell>
                                <TableCell>{a.document_id}</TableCell>
                                <TableCell>{a.query}</TableCell>
                                <TableCell>{a.status}</TableCell>
                                <TableCell>{new Date(a.created_at).toLocaleString()}</TableCell>
                                <TableCell>
                                    {/* <Button variant="outlined" onClick={() => handleExport(result.id, `analysis_${result.id}.pdf`)}>
                                        Export
                                    </Button> */}
                                    <Button variant="outlined" onClick={() => handleExport(a.id, `analysis_${a.id}.pdf`)}>
                                        Export
                                    </Button>
                                </TableCell>
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
            </Paper>
        </Box>
    );
}

export default Dashboard;
