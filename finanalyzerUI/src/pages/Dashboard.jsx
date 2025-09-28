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
    Pagination,
    Grid,
    InputAdornment,
    IconButton,
} from "@mui/material";
import { Search as SearchIcon, Clear as ClearIcon } from "@mui/icons-material";
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
    const [runningJobs, setRunningJobs] = useState({});

    // Pagination states for documents
    const [docsPage, setDocsPage] = useState(1);
    const [docsLimit] = useState(10);
    const [docsTotalPages, setDocsTotalPages] = useState(1);
    const [docsSearchQuery, setDocsSearchQuery] = useState("");
    const [docsSearchInput, setDocsSearchInput] = useState("");

    // Pagination states for analyses
    const [analysesPage, setAnalysesPage] = useState(1);
    const [analysesLimit] = useState(10);
    const [analysesTotalPages, setAnalysesTotalPages] = useState(1);
    const [selectedDocumentFilter, setSelectedDocumentFilter] = useState("");

    useEffect(() => {
        if (localStorage.getItem("access_token")) {
            fetchUser();
        }
        fetchDocuments();
        fetchAnalyses();
    }, []);

    useEffect(() => {
        fetchDocuments();
    }, [docsPage, docsSearchQuery]);

    useEffect(() => {
        fetchAnalyses();
    }, [analysesPage, selectedDocumentFilter]);

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
            const params = new URLSearchParams({
                page: docsPage.toString(),
                limit: docsLimit.toString(),
            });
            
            if (docsSearchQuery) {
                params.append("q", docsSearchQuery);
            }

            const res = await api.get(`/documents?${params}`);
            setDocuments(res.data.documents || res.data);
            
            // Calculate total pages from response
            if (res.data.total) {
                setDocsTotalPages(Math.ceil(res.data.total / docsLimit));
            } else {
                // Fallback: if we get less than limit, we're on the last page
                setDocsTotalPages(res.data.documents?.length < docsLimit ? docsPage : docsPage + 1);
            }
        } catch (err) {
            console.error(err);
            setError("Failed to fetch documents.");
        }
    };

    const fetchAnalyses = async () => {
        try {
            const params = new URLSearchParams({
                page: analysesPage.toString(),
                limit: analysesLimit.toString(),
            });
            
            if (selectedDocumentFilter) {
                params.append("document_id", selectedDocumentFilter);
            }

            const res = await api.get(`/analyses?${params}`);
            setAnalyses(res.data.analyses || res.data);
            
            // Calculate total pages from response
            if (res.data.total) {
                setAnalysesTotalPages(Math.ceil(res.data.total / analysesLimit));
            } else {
                // Fallback: if we get less than limit, we're on the last page
                setAnalysesTotalPages(res.data.analyses?.length < analysesLimit ? analysesPage : analysesPage + 1);
            }
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
            // Reset to first page and refresh
            setDocsPage(1);
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
            const { job_id } = res.data;

            // Track the job
            setRunningJobs(prev => ({ ...prev, [docId]: job_id }));

            // Start polling for status
            pollJobStatus(docId, job_id);

        } catch (err) {
            console.error(err);
            setError("Analysis failed to start.");
        } finally {
            setLoading(false);
        }
    };

    const pollJobStatus = async (docId, jobId) => {
        const poll = async () => {
            try {
                const res = await api.get(`/analyses/job/${jobId}`);
                const { status } = res.data;

                if (status === "completed") {
                    // Job completed, fetch the analysis result
                    const analysisRes = await api.get(`/analyses/${jobId}`);
                    setAnalysisResults(prev => ({ ...prev, [docId]: analysisRes.data }));
                    setRunningJobs(prev => {
                        const newJobs = { ...prev };
                        delete newJobs[docId];
                        return newJobs;
                    });
                    fetchAnalyses();
                } else if (status === "failed") {
                    setError("Analysis failed.");
                    setRunningJobs(prev => {
                        const newJobs = { ...prev };
                        delete newJobs[docId];
                        return newJobs;
                    });
                } else {
                    // Still running, poll again in 2 seconds
                    setTimeout(poll, 2000);
                }
            } catch (err) {
                console.error("Polling error:", err);
                setError("Failed to check analysis status.");
            }
        };

        poll();
    };

    const handleDelete = async (docId) => {
        if (!window.confirm("Are you sure you want to delete this document?")) return;
        try {
            await api.delete(`/documents/${docId}`);
            fetchDocuments();
            fetchAnalyses(); // Refresh analyses as they might be affected
        } catch (err) {
            console.error(err);
            setError("Delete failed.");
        }
    };

    const handleDownload = async (docId, filename) => {
        try {
            const res = await api.get(`/documents/${docId}/download`, {
                responseType: "blob",
            });

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

    const handleSearchDocuments = () => {
        setDocsSearchQuery(docsSearchInput);
        setDocsPage(1); // Reset to first page
    };

    const handleClearSearch = () => {
        setDocsSearchInput("");
        setDocsSearchQuery("");
        setDocsPage(1);
    };

    const handleRetryAnalysis = async (docId) => {
        try {
            setLoading(true);
            const response = await api.post(`/analyses/${docId}`, { query });
            if (response.data.job_id) {
                setRunningJobs(prev => ({ ...prev, [docId]: response.data.job_id }));
                pollJobStatus(docId, response.data.job_id);
            }
        } catch (error) {
            console.error('Retry failed:', error);
            setError("Failed to retry analysis.");
        } finally {
            setLoading(false);
        }
    };

    const canUpload = user?.roles.includes("analyst") || user?.roles.includes("admin");
    const canAnalyze = canUpload;

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

            {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

            {/* Upload Section */}
            {canUpload && (
                <Card sx={{ mb: 3 }}>
                    <CardContent>
                        <Typography variant="h6" gutterBottom>
                            Upload Document
                        </Typography>
                        <Grid container spacing={2} alignItems="center">
                            <Grid item xs={12} md={6}>
                                <TextField
                                    type="file"
                                    fullWidth
                                    onChange={handleFileChange}
                                    inputProps={{ accept: ".pdf,.docx,.xlsx,.csv,.png,.jpg,.jpeg" }}
                                />
                            </Grid>
                            <Grid item>
                                <Button 
                                    variant="contained" 
                                    onClick={handleUpload}
                                    disabled={!selectedFile || loading}
                                >
                                    Upload
                                </Button>
                            </Grid>
                        </Grid>
                    </CardContent>
                </Card>
            )}

            {/* Analysis Query */}
            {canAnalyze && (
                <Card sx={{ mb: 3 }}>
                    <CardContent>
                        <Typography variant="h6" gutterBottom>
                            Analysis Settings
                        </Typography>
                        <TextField
                            label="Analysis Query"
                            fullWidth
                            multiline
                            rows={2}
                            value={query}
                            onChange={(e) => setQuery(e.target.value)}
                        />
                    </CardContent>
                </Card>
            )}

            {loading && <LinearProgress sx={{ mb: 2 }} />}

            {/* Documents Section */}
            <Card sx={{ mb: 3 }}>
                <CardContent>
                    <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
                        <Typography variant="h6">
                            Documents
                        </Typography>
                        <Box display="flex" alignItems="center" gap={1}>
                            <TextField
                                size="small"
                                placeholder="Search documents..."
                                value={docsSearchInput}
                                onChange={(e) => setDocsSearchInput(e.target.value)}
                                onKeyPress={(e) => e.key === 'Enter' && handleSearchDocuments()}
                                InputProps={{
                                    endAdornment: (
                                        <InputAdornment position="end">
                                            {docsSearchInput && (
                                                <IconButton
                                                    size="small"
                                                    onClick={handleClearSearch}
                                                >
                                                    <ClearIcon />
                                                </IconButton>
                                            )}
                                            <IconButton
                                                size="small"
                                                onClick={handleSearchDocuments}
                                            >
                                                <SearchIcon />
                                            </IconButton>
                                        </InputAdornment>
                                    ),
                                }}
                            />
                        </Box>
                    </Box>
                    
                    <Paper>
                        <Table>
                            <TableHead>
                                <TableRow>
                                    <TableCell>Filename</TableCell>
                                    <TableCell>Size</TableCell>
                                    <TableCell>Status</TableCell>
                                    <TableCell>Created</TableCell>
                                    <TableCell>Actions</TableCell>
                                </TableRow>
                            </TableHead>
                            <TableBody>
                                {documents.map((doc) => (
                                    <TableRow key={doc.id}>
                                        <TableCell>{doc.filename}</TableCell>
                                        <TableCell>{(doc.size_bytes / 1024).toFixed(2)} KB</TableCell>
                                        <TableCell>
                                            <Chip
                                                label={doc.status}
                                                color={doc.status === "uploaded" ? "success" : "default"}
                                                size="small"
                                            />
                                        </TableCell>
                                        <TableCell>
                                            {new Date(doc.created_at).toLocaleDateString()}
                                        </TableCell>
                                        <TableCell>
                                            <Stack direction="row" spacing={1}>
                                                <Button
                                                    variant="outlined"
                                                    size="small"
                                                    onClick={() => handleDownload(doc.id, doc.filename)}
                                                >
                                                    Download
                                                </Button>
                                                {canAnalyze && (
                                                    <Button
                                                        variant="outlined"
                                                        size="small"
                                                        onClick={() => runAnalysis(doc.id)}
                                                        disabled={runningJobs[doc.id]}
                                                    >
                                                        {runningJobs[doc.id] ? "Analyzing..." : "Analyze"}
                                                    </Button>
                                                )}
                                                <Button
                                                    variant="outlined"
                                                    color="error"
                                                    size="small"
                                                    onClick={() => handleDelete(doc.id)}
                                                >
                                                    Delete
                                                </Button>
                                            </Stack>
                                        </TableCell>
                                    </TableRow>
                                ))}
                                {documents.length === 0 && (
                                    <TableRow>
                                        <TableCell colSpan={5} align="center">
                                            No documents found
                                        </TableCell>
                                    </TableRow>
                                )}
                            </TableBody>
                        </Table>
                    </Paper>
                    
                    {docsTotalPages > 1 && (
                        <Box display="flex" justifyContent="center" mt={2}>
                            <Pagination
                                count={docsTotalPages}
                                page={docsPage}
                                onChange={(event, value) => setDocsPage(value)}
                                color="primary"
                            />
                        </Box>
                    )}
                </CardContent>
            </Card>

            {/* Analysis Results */}
            {Object.keys(analysisResults).length > 0 && (
                <Card sx={{ mb: 3 }}>
                    <CardContent>
                        <Typography variant="h6" gutterBottom>
                            Latest Analysis Results
                        </Typography>
                        {Object.entries(analysisResults).map(([docId, result]) => {
                            const parsedSummary = parseSummary(result.summary);
                            return (
                                <Card key={docId} sx={{ mb: 2 }} variant="outlined">
                                    <CardContent>
                                        <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
                                            <Typography variant="subtitle1">
                                                Document ID: {result.document_id}
                                            </Typography>
                                            <Chip
                                                label={`Status: ${result.status}`}
                                                color={result.status === "completed" ? "success" : result.status === "failed" ? "error" : "warning"}
                                            />
                                        </Box>
                                        
                                        {result.status === "failed" && (
                                            <Button
                                                variant="contained"
                                                color="error"
                                                size="small"
                                                onClick={() => handleRetryAnalysis(result.document_id)}
                                                sx={{ mb: 2 }}
                                            >
                                                Retry Analysis
                                            </Button>
                                        )}
                                        
                                        <Divider sx={{ my: 2 }} />
                                        <Typography variant="subtitle2" gutterBottom>
                                            Summary:
                                        </Typography>
                                        {parsedSummary ? (
                                            <pre style={{
                                                background: "#f5f5f5", padding: "8px", borderRadius: "4px", whiteSpace: "pre-wrap",
                                                wordWrap: "break-word", overflowX: "auto", maxWidth: "100%", fontSize: "12px"
                                            }}>
                                                {JSON.stringify(parsedSummary, null, 2)}
                                            </pre>
                                        ) : (
                                            <Typography variant="body2">{result.summary || "N/A"}</Typography>
                                        )}
                                        
                                        <Divider sx={{ my: 2 }} />
                                        <Typography variant="subtitle2">Investment Insights:</Typography>
                                        {(() => {
                                            const parsed = parseJsonMaybe(result.investment_insights);
                                            if (parsed) {
                                                return (
                                                    <pre style={{ background: "#f5f5f5", padding: "8px", borderRadius: "4px", whiteSpace: "pre-wrap", wordWrap: "break-word", overflowX: "auto", fontSize: "12px" }}>
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
                                                return <pre style={{ background: "#f5f5f5", padding: "8px", borderRadius: "4px", whiteSpace: "pre-wrap", fontSize: "12px" }}>{result.investment_insights}</pre>;
                                            }
                                            return <Typography color="text.secondary" variant="body2">None</Typography>;
                                        })()}
                                        
                                        <Divider sx={{ my: 2 }} />
                                        <Typography variant="subtitle2">Risk Assessment:</Typography>
                                        {(() => {
                                            const parsed = parseJsonMaybe(result.risk_assessment);
                                            if (parsed) {
                                                return (
                                                    <pre style={{ background: "#f5f5f5", padding: "8px", borderRadius: "4px", whiteSpace: "pre-wrap", wordWrap: "break-word", overflowX: "auto", fontSize: "12px" }}>
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
                                                return <pre style={{ background: "#f5f5f5", padding: "8px", borderRadius: "4px", whiteSpace: "pre-wrap", fontSize: "12px" }}>{result.risk_assessment}</pre>;
                                            }
                                            return <Typography color="text.secondary" variant="body2">None</Typography>;
                                        })()}
                                    </CardContent>
                                </Card>
                            );
                        })}
                    </CardContent>
                </Card>
            )}

            {/* Analysis History */}
            <Card>
                <CardContent>
                    <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
                        <Typography variant="h6">
                            Analysis History
                        </Typography>
                        <TextField
                            select
                            size="small"
                            value={selectedDocumentFilter}
                            onChange={(e) => {
                                setSelectedDocumentFilter(e.target.value);
                                setAnalysesPage(1);
                            }}
                            SelectProps={{ native: true }}
                            sx={{ minWidth: 200 }}
                        >
                            <option value="">All Documents</option>
                            {documents.map((doc) => (
                                <option key={doc.id} value={doc.id}>
                                    {doc.filename}
                                </option>
                            ))}
                        </TextField>
                    </Box>
                    
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
                                        <TableCell>
                                            <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                                                {a.id.substring(0, 8)}...
                                            </Typography>
                                        </TableCell>
                                        <TableCell>
                                            <Typography variant="body2" noWrap>
                                                {documents.find(d => d.id === a.document_id)?.filename || a.document_id}
                                            </Typography>
                                        </TableCell>
                                        <TableCell>
                                            <Typography variant="body2" noWrap sx={{ maxWidth: 200 }}>
                                                {a.query}
                                            </Typography>
                                        </TableCell>
                                        <TableCell>
                                            <Chip
                                                label={a.status}
                                                color={
                                                    a.status === "completed" ? "success" :
                                                    a.status === "failed" ? "error" : "warning"
                                                }
                                                size="small"
                                            />
                                        </TableCell>
                                        <TableCell>
                                            {new Date(a.created_at).toLocaleDateString()}
                                        </TableCell>
                                        <TableCell>
                                            {a.status === "completed" && (
                                                <Button
                                                    variant="outlined"
                                                    size="small"
                                                    onClick={() => handleExport(a.id, `analysis_${a.id.substring(0, 8)}.pdf`)}
                                                >
                                                    Export
                                                </Button>
                                            )}
                                        </TableCell>
                                    </TableRow>
                                ))}
                                {analyses.length === 0 && (
                                    <TableRow>
                                        <TableCell colSpan={6} align="center">
                                            No analyses found
                                        </TableCell>
                                    </TableRow>
                                )}
                            </TableBody>
                        </Table>
                    </Paper>
                    
                    {analysesTotalPages > 1 && (
                        <Box display="flex" justifyContent="center" mt={2}>
                            <Pagination
                                count={analysesTotalPages}
                                page={analysesPage}
                                onChange={(event, value) => setAnalysesPage(value)}
                                color="primary"
                            />
                        </Box>
                    )}
                </CardContent>
            </Card>
        </Box>
    );
}

export default Dashboard;