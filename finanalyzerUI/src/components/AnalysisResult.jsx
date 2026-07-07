import React from "react";
import {
  Box, Typography, Chip, Divider, Stack, Table, TableHead, TableRow, TableCell,
  TableBody, Accordion, AccordionSummary, AccordionDetails, Alert,
} from "@mui/material";
import { ExpandMoreRounded, TrendingUpRounded, LightbulbRounded } from "@mui/icons-material";

// ---- parsing helpers --------------------------------------------------------
export function parseJsonMaybe(text) {
  if (text == null) return null;
  if (typeof text !== "string") return text;
  try {
    return JSON.parse(text.replace(/```json|```/g, "").trim());
  } catch {
    return null;
  }
}

function toDisplay(v) {
  if (v == null) return "";
  if (typeof v === "object") {
    if (Array.isArray(v)) return v.map(toDisplay).join(", ");
    return Object.entries(v)
      .map(([k, val]) => `${humanize(k)}: ${toDisplay(val)}`)
      .join("; ");
  }
  return String(v);
}

function humanize(k) {
  return String(k).replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

const sevColor = (s) => {
  const v = String(s || "").toLowerCase();
  if (v.includes("high")) return "error";
  if (v.includes("med")) return "warning";
  if (v.includes("low")) return "success";
  return "default";
};

// ---- small building blocks --------------------------------------------------
function SectionTitle({ icon, children }) {
  return (
    <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1.5, mt: 1 }}>
      {icon}
      <Typography variant="subtitle1">{children}</Typography>
    </Stack>
  );
}

function KeyMetrics({ metrics }) {
  const entries = Object.entries(metrics || {}).filter(([, v]) => v != null && v !== "");
  if (!entries.length) return null;
  return (
    <Box sx={{
      display: "grid", gap: 1.5, mb: 2,
      gridTemplateColumns: { xs: "1fr 1fr", sm: "repeat(3,1fr)", md: "repeat(4,1fr)" },
    }}>
      {entries.map(([k, v]) => (
        <Box key={k} sx={{
          p: 1.5, borderRadius: 2, bgcolor: "action.hover", border: "1px solid", borderColor: "divider",
        }}>
          <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
            {humanize(k)}
          </Typography>
          <Typography variant="subtitle2" sx={{ wordBreak: "break-word" }}>
            {toDisplay(v)}
          </Typography>
        </Box>
      ))}
    </Box>
  );
}

function BulletList({ items }) {
  const arr = Array.isArray(items) ? items : items ? [items] : [];
  if (!arr.length) return null;
  return (
    <Box component="ul" sx={{ m: 0, mb: 2, pl: 3 }}>
      {arr.map((it, i) => (
        <li key={i}>
          <Typography variant="body2">{toDisplay(it)}</Typography>
        </li>
      ))}
    </Box>
  );
}

// ---- section renderers ------------------------------------------------------
function SummarySection({ summary }) {
  const s = parseJsonMaybe(summary);
  if (!s || typeof s !== "object") {
    return <Typography variant="body2" color="text.secondary">{summary || "No summary available."}</Typography>;
  }
  return (
    <Box>
      {s.executive_summary && (
        <Typography variant="body2" sx={{ mb: 2 }}>{s.executive_summary}</Typography>
      )}
      {s.key_metrics && Object.keys(s.key_metrics).length > 0 && (
        <>
          <SectionTitle>Key Metrics</SectionTitle>
          <KeyMetrics metrics={s.key_metrics} />
        </>
      )}
      {s.growth_trends && Object.keys(s.growth_trends).length > 0 && (
        <>
          <SectionTitle icon={<TrendingUpRounded fontSize="small" color="secondary" />}>Growth Trends</SectionTitle>
          <Stack direction="row" flexWrap="wrap" gap={1} sx={{ mb: 2 }}>
            {Object.entries(s.growth_trends).map(([k, v]) => (
              <Chip key={k} size="small" variant="outlined" label={`${humanize(k)}: ${toDisplay(v)}`} />
            ))}
          </Stack>
        </>
      )}
      {Array.isArray(s.risks) && s.risks.length > 0 && (
        <>
          <SectionTitle>Highlighted Risks</SectionTitle>
          <BulletList items={s.risks} />
        </>
      )}
      {Array.isArray(s.recommendations) && s.recommendations.length > 0 && (
        <>
          <SectionTitle icon={<LightbulbRounded fontSize="small" color="warning" />}>Recommendations</SectionTitle>
          <BulletList items={s.recommendations} />
        </>
      )}
    </Box>
  );
}

function InvestmentSection({ data }) {
  const d = parseJsonMaybe(data);
  if (!d || typeof d !== "object") {
    return <Typography variant="body2" color="text.secondary">{data || "No investment insights."}</Typography>;
  }
  return (
    <Box>
      {Array.isArray(d.investment_themes) && d.investment_themes.length > 0 && (
        <Stack direction="row" flexWrap="wrap" gap={1} sx={{ mb: 2 }}>
          {d.investment_themes.map((t, i) => (
            <Chip key={i} color="primary" variant="outlined" label={toDisplay(t)} />
          ))}
        </Stack>
      )}
      {d.asset_allocation && Object.keys(d.asset_allocation).length > 0 && (
        <>
          <SectionTitle>Asset Allocation</SectionTitle>
          <Table size="small" sx={{ mb: 2 }}>
            <TableBody>
              {Object.entries(d.asset_allocation).map(([k, v]) => (
                <TableRow key={k}>
                  <TableCell sx={{ fontWeight: 600, width: "40%" }}>{humanize(k)}</TableCell>
                  <TableCell>{toDisplay(v)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </>
      )}
      {d.risk_assessment && (
        <Typography variant="body2" sx={{ mb: 1 }}>
          <strong>Risk assessment:</strong> {toDisplay(d.risk_assessment)}
        </Typography>
      )}
      {d.time_horizon && (
        <Typography variant="body2" sx={{ mb: 1 }}>
          <strong>Time horizon:</strong> {toDisplay(d.time_horizon)}
        </Typography>
      )}
      {d.disclaimer && (
        <Alert severity="info" variant="outlined" sx={{ mt: 1 }}>{toDisplay(d.disclaimer)}</Alert>
      )}
    </Box>
  );
}

function RiskSection({ data }) {
  const d = parseJsonMaybe(data);
  const risks = d && Array.isArray(d.identified_risks) ? d.identified_risks : null;
  if (!risks) {
    return <Typography variant="body2" color="text.secondary">{toDisplay(d) || data || "No risk assessment."}</Typography>;
  }
  if (!risks.length) return <Typography variant="body2" color="text.secondary">No risks identified.</Typography>;
  return (
    <Box sx={{ overflowX: "auto" }}>
      {d.overall_risk_rating && (
        <Chip sx={{ mb: 2 }} color={sevColor(d.overall_risk_rating)}
          label={`Overall risk: ${d.overall_risk_rating}`} />
      )}
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Risk</TableCell>
            <TableCell>Severity</TableCell>
            <TableCell>Likelihood</TableCell>
            <TableCell>Mitigation</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {risks.map((r, i) => (
            <TableRow key={i}>
              <TableCell sx={{ maxWidth: 240 }}>
                <Typography variant="body2" sx={{ fontWeight: 600 }}>
                  {r.risk || r.risk_name || "—"}
                </Typography>
                {r.description && (
                  <Typography variant="caption" color="text.secondary">{r.description}</Typography>
                )}
              </TableCell>
              <TableCell><Chip size="small" color={sevColor(r.severity)} label={r.severity || "—"} /></TableCell>
              <TableCell><Chip size="small" variant="outlined" color={sevColor(r.likelihood)} label={r.likelihood || "—"} /></TableCell>
              <TableCell><Typography variant="body2">{r.strategy || r.mitigation || "—"}</Typography></TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Box>
  );
}

// ---- public component -------------------------------------------------------
export default function AnalysisResult({ result }) {
  if (!result) return null;
  const sections = [
    { key: "summary", label: "Financial Summary", el: <SummarySection summary={result.summary} />, open: true },
    { key: "inv", label: "Investment Insights", el: <InvestmentSection data={result.investment_insights} /> },
    { key: "risk", label: "Risk Assessment", el: <RiskSection data={result.risk_assessment} /> },
  ];
  return (
    <Box>
      {sections.map((s) => (
        <Accordion key={s.key} defaultExpanded={s.open} disableGutters
          sx={{ "&:before": { display: "none" }, border: "1px solid", borderColor: "divider", borderRadius: 2, mb: 1, overflow: "hidden" }}>
          <AccordionSummary expandIcon={<ExpandMoreRounded />}>
            <Typography variant="subtitle1">{s.label}</Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Divider sx={{ mb: 2 }} />
            {s.el}
          </AccordionDetails>
        </Accordion>
      ))}
    </Box>
  );
}
