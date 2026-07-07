import React, { useEffect, useRef, useState } from "react";
import {
  Box, Typography, Button, TextField, Table, TableHead, TableRow, TableCell, TableBody,
  Paper, LinearProgress, Alert, Card, CardContent, Chip, Stack, Pagination,
  InputAdornment, IconButton, Tooltip, CircularProgress, Snackbar,
} from "@mui/material";
import {
  Search as SearchIcon, Clear as ClearIcon, UploadFileRounded, DownloadRounded,
  DeleteOutlineRounded, PlayArrowRounded, ReplayRounded, DescriptionRounded,
  AssessmentRounded, PendingActionsRounded, VisibilityRounded, PictureAsPdfRounded,
} from "@mui/icons-material";
import api from "../api/axios";
import AnalysisResult from "../components/AnalysisResult";

const POLL_INTERVAL_MS = 10000;
const POLL_MAX_ATTEMPTS = 60; // ~10 minutes

function StatCard({ icon, label, value, color }) {
  return (
    <Card sx={{ flex: 1, minWidth: 160 }}>
      <CardContent sx={{ display: "flex", alignItems: "center", gap: 2 }}>
        <Box sx={{
          display: "grid", placeItems: "center", width: 46, height: 46, borderRadius: 2,
          bgcolor: `${color}.main`, color: "#fff",
        }}>
          {icon}
        </Box>
        <Box>
          <Typography variant="h5">{value}</Typography>
          <Typography variant="body2" color="text.secondary">{label}</Typography>
        </Box>
      </CardContent>
    </Card>
  );
}

function Dashboard() {
  const [documents, setDocuments] = useState([]);
  const [analyses, setAnalyses] = useState([]);
  const [totalDocs, setTotalDocs] = useState(0);
  const [totalAnalyses, setTotalAnalyses] = useState(0);
  const [selectedFile, setSelectedFile] = useState(null);
  const [query, setQuery] = useState("Analyze this financial document for investment insights");
  const [uploading, setUploading] = useState(false);
  const [activeResult, setActiveResult] = useState(null);
  const [error, setError] = useState("");
  const [toast, setToast] = useState("");
  const [user, setUser] = useState(null);
  const [runningJobs, setRunningJobs] = useState({});

  const [docsPage, setDocsPage] = useState(1);
  const [docsLimit] = useState(10);
  const [docsTotalPages, setDocsTotalPages] = useState(1);
  const [docsSearchQuery, setDocsSearchQuery] = useState("");
  const [docsSearchInput, setDocsSearchInput] = useState("");

  const [analysesPage, setAnalysesPage] = useState(1);
  const [analysesLimit] = useState(10);
  const [analysesTotalPages, setAnalysesTotalPages] = useState(1);
  const [selectedDocumentFilter, setSelectedDocumentFilter] = useState("");

  const mounted = useRef(true);
  useEffect(() => {
    // Must reset to true here: React 19 StrictMode mounts → runs cleanup → remounts,
    // which would otherwise leave mounted.current stuck false and block all polling.
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);

  useEffect(() => {
    if (localStorage.getItem("access_token")) fetchUser();
  }, []);
  useEffect(() => { fetchDocuments(); }, [docsPage, docsSearchQuery]);
  useEffect(() => { fetchAnalyses(); }, [analysesPage, selectedDocumentFilter]);

  const fetchUser = async () => {
    try {
      const res = await api.get("/auth/me");
      setUser(res.data);
    } catch {
      setError("Failed to fetch user info.");
    }
  };

  const fetchDocuments = async () => {
    try {
      const params = new URLSearchParams({ page: String(docsPage), limit: String(docsLimit) });
      if (docsSearchQuery) params.append("q", docsSearchQuery);
      const res = await api.get(`/documents?${params}`);
      const list = res.data.documents || res.data;
      setDocuments(list);
      setTotalDocs(res.data.total ?? list.length);
      setDocsTotalPages(res.data.total ? Math.max(1, Math.ceil(res.data.total / docsLimit)) : 1);
    } catch {
      setError("Failed to fetch documents.");
    }
  };

  const fetchAnalyses = async () => {
    try {
      const params = new URLSearchParams({ page: String(analysesPage), limit: String(analysesLimit) });
      if (selectedDocumentFilter) params.append("document_id", selectedDocumentFilter);
      const res = await api.get(`/analyses?${params}`);
      const list = res.data.analyses || res.data;
      setAnalyses(list);
      setTotalAnalyses(res.data.total ?? list.length);
      setAnalysesTotalPages(res.data.total ? Math.max(1, Math.ceil(res.data.total / analysesLimit)) : 1);
    } catch {
      setError("Failed to fetch analyses.");
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) return;
    setUploading(true);
    setError("");
    const formData = new FormData();
    formData.append("file", selectedFile);
    try {
      await api.post("/documents/upload", formData, { headers: { "Content-Type": "multipart/form-data" } });
      setSelectedFile(null);
      setDocsPage(1);
      fetchDocuments();
      setToast("Document uploaded.");
    } catch (err) {
      setError(err.response?.data?.detail || "Upload failed.");
    } finally {
      setUploading(false);
    }
  };

  const runAnalysis = async (docId) => {
    setError("");
    try {
      const res = await api.post(`/analyses/${docId}`, { query });
      const { job_id } = res.data;
      setRunningJobs((p) => ({ ...p, [docId]: job_id }));
      pollJobStatus(docId, job_id);
      setToast("Analysis started.");
    } catch (err) {
      setError(err.response?.data?.detail || "Analysis failed to start.");
    }
  };

  const clearJob = (docId) =>
    setRunningJobs((p) => { const n = { ...p }; delete n[docId]; return n; });

  const pollJobStatus = (docId, jobId, attempt = 0) => {
    const poll = async () => {
      if (!mounted.current) return;
      try {
        const res = await api.get(`/analyses/job/${jobId}`);
        const { status } = res.data;
        if (status === "completed") {
          const analysisRes = await api.get(`/analyses/${jobId}`);
          setActiveResult(analysisRes.data);
          clearJob(docId);
          fetchAnalyses();
          setToast("Analysis complete.");
        } else if (status === "failed") {
          setError(res.data.error || "Analysis failed.");
          clearJob(docId);
        } else if (attempt >= POLL_MAX_ATTEMPTS) {
          setError("Analysis timed out. Please retry.");
          clearJob(docId);
        } else {
          setTimeout(() => pollJobStatus(docId, jobId, attempt + 1), POLL_INTERVAL_MS);
        }
      } catch {
        setError("Failed to check analysis status.");
        clearJob(docId);
      }
    };
    poll();
  };

  const handleDelete = async (docId) => {
    if (!window.confirm("Delete this document and its analyses?")) return;
    try {
      await api.delete(`/documents/${docId}`);
      fetchDocuments();
      fetchAnalyses();
      setToast("Document deleted.");
    } catch {
      setError("Delete failed.");
    }
  };

  const downloadBlob = (data, filename) => {
    const url = window.URL.createObjectURL(new Blob([data]));
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", filename);
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  };

  const handleDownload = async (docId, filename) => {
    try {
      const res = await api.get(`/documents/${docId}/download`, { responseType: "blob" });
      downloadBlob(res.data, filename || `document_${docId}.pdf`);
    } catch {
      setError("Download failed.");
    }
  };

  const handleExport = async (analysisId) => {
    try {
      const res = await api.get(`/analyses/${analysisId}/export`, { responseType: "blob" });
      downloadBlob(res.data, `analysis_${analysisId.substring(0, 8)}.pdf`);
    } catch {
      setError("Export failed.");
    }
  };

  const handleViewAnalysis = async (analysisId) => {
    try {
      const res = await api.get(`/analyses/${analysisId}`);
      setActiveResult(res.data);
      window.scrollTo({ top: 0, behavior: "smooth" });
    } catch {
      setError("Failed to load analysis.");
    }
  };

  const handleSearchDocuments = () => { setDocsSearchQuery(docsSearchInput); setDocsPage(1); };
  const handleClearSearch = () => { setDocsSearchInput(""); setDocsSearchQuery(""); setDocsPage(1); };

  const canUpload = user?.roles?.includes("analyst") || user?.roles?.includes("admin");
  const canAnalyze = canUpload;
  const runningCount = Object.keys(runningJobs).length;

  const statusColor = (s) =>
    s === "completed" ? "success" : s === "failed" ? "error" : s === "uploaded" ? "info" : "warning";

  return (
    <Box>
      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 3 }}>
        <Box>
          <Typography variant="h4">Dashboard</Typography>
          <Typography variant="body2" color="text.secondary">
            {user?.full_name ? `Welcome, ${user.full_name}` : "Welcome back"}
            {user?.roles?.length ? ` · ${user.roles.join(", ")}` : ""}
          </Typography>
        </Box>
      </Stack>

      {error && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError("")}>{error}</Alert>}

      {/* Stats */}
      <Stack direction={{ xs: "column", sm: "row" }} spacing={2} sx={{ mb: 3 }}>
        <StatCard icon={<DescriptionRounded />} label="Documents" value={totalDocs} color="primary" />
        <StatCard icon={<AssessmentRounded />} label="Analyses" value={totalAnalyses} color="secondary" />
        <StatCard icon={<PendingActionsRounded />} label="Running" value={runningCount} color="warning" />
      </Stack>

      {/* Upload + query */}
      {canUpload && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>Analyze a document</Typography>
            <Stack spacing={2}>
              <Stack direction={{ xs: "column", md: "row" }} spacing={2} alignItems={{ md: "center" }}>
                <Button component="label" variant="outlined" startIcon={<UploadFileRounded />} sx={{ minWidth: 160 }}>
                  {selectedFile ? "Change file" : "Choose file"}
                  <input hidden type="file" accept=".pdf,.docx,.xlsx,.csv,.png,.jpg,.jpeg,.txt"
                    onChange={(e) => setSelectedFile(e.target.files[0])} />
                </Button>
                <Typography variant="body2" color="text.secondary" sx={{ flexGrow: 1 }} noWrap>
                  {selectedFile ? `${selectedFile.name} · ${(selectedFile.size / 1024).toFixed(1)} KB` : "PDF, DOCX, XLSX, CSV, or image (max 50 MB)"}
                </Typography>
                <Button variant="contained" onClick={handleUpload} disabled={!selectedFile || uploading}
                  startIcon={uploading ? <CircularProgress size={16} color="inherit" /> : <UploadFileRounded />}>
                  {uploading ? "Uploading…" : "Upload"}
                </Button>
              </Stack>
              <TextField label="Analysis query" fullWidth multiline rows={2}
                value={query} onChange={(e) => setQuery(e.target.value)}
                helperText="This prompt guides what the AI analysts focus on." />
            </Stack>
          </CardContent>
        </Card>
      )}

      {/* Active result */}
      {activeResult && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 2 }}>
              <Box>
                <Typography variant="h6">Analysis result</Typography>
                <Typography variant="body2" color="text.secondary">
                  {documents.find((d) => d.id === activeResult.document_id)?.filename || activeResult.document_id}
                </Typography>
              </Box>
              <Stack direction="row" spacing={1} alignItems="center">
                <Chip color={statusColor(activeResult.status)} label={activeResult.status} size="small" />
                {activeResult.status === "completed" && (
                  <Button size="small" variant="outlined" startIcon={<PictureAsPdfRounded />}
                    onClick={() => handleExport(activeResult.id)}>Export PDF</Button>
                )}
                <IconButton size="small" onClick={() => setActiveResult(null)}><ClearIcon /></IconButton>
              </Stack>
            </Stack>
            {activeResult.query && (
              <Alert severity="info" variant="outlined" sx={{ mb: 2 }}>Query: {activeResult.query}</Alert>
            )}
            <AnalysisResult result={activeResult} />
          </CardContent>
        </Card>
      )}

      {/* Documents */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Stack direction={{ xs: "column", sm: "row" }} justifyContent="space-between" alignItems={{ sm: "center" }} spacing={1} mb={2}>
            <Typography variant="h6">Documents</Typography>
            <TextField size="small" placeholder="Search documents…" value={docsSearchInput}
              onChange={(e) => setDocsSearchInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSearchDocuments()}
              InputProps={{
                endAdornment: (
                  <InputAdornment position="end">
                    {docsSearchInput && (
                      <IconButton size="small" onClick={handleClearSearch}><ClearIcon fontSize="small" /></IconButton>
                    )}
                    <IconButton size="small" onClick={handleSearchDocuments}><SearchIcon fontSize="small" /></IconButton>
                  </InputAdornment>
                ),
              }} />
          </Stack>

          <Paper variant="outlined" sx={{ overflowX: "auto" }}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Filename</TableCell>
                  <TableCell>Size</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Created</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {documents.map((doc) => (
                  <TableRow key={doc.id} hover>
                    <TableCell>
                      <Stack direction="row" spacing={1} alignItems="center">
                        <DescriptionRounded fontSize="small" color="action" />
                        <Typography variant="body2" sx={{ fontWeight: 600 }}>{doc.filename}</Typography>
                      </Stack>
                    </TableCell>
                    <TableCell>{(doc.size_bytes / 1024).toFixed(1)} KB</TableCell>
                    <TableCell><Chip label={doc.status} color={statusColor(doc.status)} size="small" /></TableCell>
                    <TableCell>{new Date(doc.created_at).toLocaleDateString()}</TableCell>
                    <TableCell align="right">
                      <Stack direction="row" spacing={0.5} justifyContent="flex-end">
                        <Tooltip title="Download">
                          <IconButton size="small" onClick={() => handleDownload(doc.id, doc.filename)}>
                            <DownloadRounded fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        {canAnalyze && (
                          <Button size="small" variant="contained"
                            startIcon={runningJobs[doc.id] ? <CircularProgress size={14} color="inherit" /> : <PlayArrowRounded />}
                            onClick={() => runAnalysis(doc.id)} disabled={!!runningJobs[doc.id]}>
                            {runningJobs[doc.id] ? "Analyzing" : "Analyze"}
                          </Button>
                        )}
                        <Tooltip title="Delete">
                          <IconButton size="small" color="error" onClick={() => handleDelete(doc.id)}>
                            <DeleteOutlineRounded fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </Stack>
                    </TableCell>
                  </TableRow>
                ))}
                {documents.length === 0 && (
                  <TableRow><TableCell colSpan={5} align="center" sx={{ py: 5, color: "text.secondary" }}>
                    No documents yet — upload one to get started.
                  </TableCell></TableRow>
                )}
              </TableBody>
            </Table>
          </Paper>
          {docsTotalPages > 1 && (
            <Box display="flex" justifyContent="center" mt={2}>
              <Pagination count={docsTotalPages} page={docsPage} color="primary"
                onChange={(_, v) => setDocsPage(v)} />
            </Box>
          )}
        </CardContent>
      </Card>

      {/* History */}
      <Card>
        <CardContent>
          <Stack direction={{ xs: "column", sm: "row" }} justifyContent="space-between" alignItems={{ sm: "center" }} spacing={1} mb={2}>
            <Typography variant="h6">Analysis history</Typography>
            <TextField select size="small" value={selectedDocumentFilter}
              onChange={(e) => { setSelectedDocumentFilter(e.target.value); setAnalysesPage(1); }}
              SelectProps={{ native: true }} sx={{ minWidth: 220 }}>
              <option value="">All documents</option>
              {documents.map((d) => <option key={d.id} value={d.id}>{d.filename}</option>)}
            </TextField>
          </Stack>

          <Paper variant="outlined" sx={{ overflowX: "auto" }}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>ID</TableCell>
                  <TableCell>Document</TableCell>
                  <TableCell>Query</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Created</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {analyses.map((a) => (
                  <TableRow key={a.id} hover>
                    <TableCell><Typography variant="body2" sx={{ fontFamily: "monospace" }}>{a.id.substring(0, 8)}…</Typography></TableCell>
                    <TableCell><Typography variant="body2" noWrap sx={{ maxWidth: 180 }}>
                      {documents.find((d) => d.id === a.document_id)?.filename || a.document_id}
                    </Typography></TableCell>
                    <TableCell><Typography variant="body2" noWrap sx={{ maxWidth: 220 }}>{a.query}</Typography></TableCell>
                    <TableCell><Chip label={a.status} color={statusColor(a.status)} size="small" /></TableCell>
                    <TableCell>{new Date(a.created_at).toLocaleDateString()}</TableCell>
                    <TableCell align="right">
                      <Stack direction="row" spacing={0.5} justifyContent="flex-end">
                        {a.status === "completed" && (
                          <>
                            <Tooltip title="View">
                              <IconButton size="small" onClick={() => handleViewAnalysis(a.id)}>
                                <VisibilityRounded fontSize="small" />
                              </IconButton>
                            </Tooltip>
                            <Tooltip title="Export PDF">
                              <IconButton size="small" onClick={() => handleExport(a.id)}>
                                <PictureAsPdfRounded fontSize="small" />
                              </IconButton>
                            </Tooltip>
                          </>
                        )}
                        {a.status === "failed" && (
                          <Tooltip title="Retry">
                            <IconButton size="small" color="warning" onClick={() => runAnalysis(a.document_id)}>
                              <ReplayRounded fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        )}
                      </Stack>
                    </TableCell>
                  </TableRow>
                ))}
                {analyses.length === 0 && (
                  <TableRow><TableCell colSpan={6} align="center" sx={{ py: 5, color: "text.secondary" }}>
                    No analyses yet.
                  </TableCell></TableRow>
                )}
              </TableBody>
            </Table>
          </Paper>
          {analysesTotalPages > 1 && (
            <Box display="flex" justifyContent="center" mt={2}>
              <Pagination count={analysesTotalPages} page={analysesPage} color="primary"
                onChange={(_, v) => setAnalysesPage(v)} />
            </Box>
          )}
        </CardContent>
      </Card>

      {(uploading || runningCount > 0) && <LinearProgress sx={{ mt: 2 }} />}

      <Snackbar open={!!toast} autoHideDuration={3000} onClose={() => setToast("")}
        message={toast} anchorOrigin={{ vertical: "bottom", horizontal: "center" }} />
    </Box>
  );
}

export default Dashboard;
