import os
import re
import unicodedata
import warnings
import logging
from collections import OrderedDict
from dotenv import load_dotenv
from crewai.tools import tool
from crewai_tools.tools.pdf_search_tool import pdf_search_tool
import pdfplumber

load_dotenv()

# Suppress PDF parsing warnings
warnings.filterwarnings("ignore", category=UserWarning, module="pdfplumber")
logging.getLogger("pdfplumber").setLevel(logging.ERROR)

# preprocess the financial text
def preprocess_financial_text(raw: str) -> str:
    # 1) Unicode normalize
    txt = unicodedata.normalize("NFKC", raw)

    # 2) Normalize line endings and remove BOMs
    txt = txt.replace("\r\n", "\n").replace("\r", "\n").replace("\ufeff", "")

    # 3) Remove page markers / page numbers on their own line
    txt = re.sub(r"(?mi)^\s*(page|p\.)\s*\d+\s*$", "", txt)

    # 4) Remove ALL-CAPS headers and “letter-spaced caps” like 'F I N A N C I A L  S U M M A R Y'
    def _is_all_caps_or_spaced(line: str) -> bool:
        plain = re.sub(r"[^A-Za-z]", "", line)
        spaced = re.sub(r"\s+", "", line)
        return (
            (len(plain) >= 3 and plain.isupper()) or
            (len(spaced) >= 3 and spaced.isupper() and " " in line)
        )

    lines = [ln.strip() for ln in txt.split("\n")]
    lines = [ln for ln in lines if ln and not _is_all_caps_or_spaced(ln)]

    # 5) Drop lines that are mostly numeric/symbols (tables)
    def _mostly_numeric(line: str) -> bool:
        if len(line) < 3:
            return True
        digits = sum(ch.isdigit() for ch in line)
        sym = sum(ch in "%$()[],:;+-/|" for ch in line)
        ratio = (digits + sym) / max(1, len(line))
        return ratio > 0.45

    lines = [ln for ln in lines if not _mostly_numeric(ln)]

    # 6) Rebuild text to do de-hyphenation across line breaks
    txt = "\n".join(lines)
    txt = re.sub(r"(\w)-\n(\w)", r"\1\2", txt)

    # 7) Join soft-wrapped sentences: newline followed by lowercase/number becomes space
    txt = re.sub(r"\n(?=[a-z0-9])", " ", txt)

    # 8) Collapse whitespace
    txt = re.sub(r"[ \t]{2,}", " ", txt)
    txt = re.sub(r"\n{2,}", "\n", txt).strip()

    # 9) Deduplicate paragraphs while preserving order
    paras = [p.strip() for p in txt.split("\n") if p.strip()]
    deduped = list(OrderedDict((p, None) for p in paras).keys())
    cleaned = "\n".join(deduped)

    return cleaned


# -------- Tools --------

@tool("read_financial_document")
def read_financial_document(path: str) -> str:
    """
    Reads and preprocesses text from a financial PDF document locally.
    Avoids PDFSearchTool to prevent APIStatusError.
    """
    path = os.path.normpath(path)
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")

    # Extract text locally (no external API/tool)
    text_chunks = []
    if path.lower().endswith(".pdf"):
        try:
            with pdfplumber.open(path) as pdf:
                for page_num, page in enumerate(pdf.pages, 1):
                    try:
                        text = page.extract_text()
                        if text:
                            text_chunks.append(text)
                    except Exception as e:
                        print(f"Warning: Could not extract text from page {page_num}: {e}")
                        continue
        except Exception as e:
            raise Exception(f"Failed to open PDF file: {e}")
    else:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text_chunks.append(f.read())

    raw_text = "\n".join(text_chunks)
    
    if not raw_text.strip():
        raise Exception("No text could be extracted from the document")

    print(f"Successfully extracted {len(raw_text)} characters from document")
    
    # Preprocess
    cleaned = preprocess_financial_text(raw_text)

    print(f"Preprocessed extracted text has {len(raw_text)} characters before returning")

    return cleaned


# Investment analysis tool
@tool("investment_analysis")
def analyze_investment_tool(financial_document_data: str) -> str:
    """
    Analyzes financial document data for potential investment insights.
    Extracts growth, profitability, and opportunity indicators.
    """
    try:
        # Very simple heuristic scan on cleaned text
        text = financial_document_data.lower()

        signals = {
            "growth": ["growth", "increase", "expansion", "positive trend", "forecast"],
            "profitability": ["profit", "margin", "revenue", "net income", "ebitda"],
            "cash": ["cash flow", "free cash flow", "liquidity", "capital expenditures", "capex"],
            "leverage": ["debt", "leverage", "liabilities", "interest expense"],
            "outlook": ["guidance", "outlook", "expect", "plan", "target"],
            "risk": ["decline", "loss", "uncertain", "volatility", "regulatory", "litigation"],
        }

        hits = []
        for bucket, kws in signals.items():
            found = [kw for kw in kws if kw in text]
            if found:
                hits.append(f"- {bucket.capitalize()}: {', '.join(found)}")

        summary = "No strong textual signals found." if not hits else "Signals:\n" + "\n".join(hits)

        # Include a short preview to aid debugging
        preview = text[:1200] + ("..." if len(text) > 1200 else "")
        return f"Preprocessed text length: {len(text)} chars\n\n{summary}\n\n---\nPreview:\n{preview}"

    except Exception as e:
        # Never propagate to avoid 500 in /analyses; return diagnostic text instead
        return f"Analyzer error: {type(e).__name__}: {e}"


# Risk assessment tool
@tool("risk_assessment")
def create_risk_assessment_tool(financial_document_data: str) -> str:
    """
    Performs a basic risk assessment on financial documents.
    Identifies red flags like debt, volatility, losses, litigation, etc.
    """
    text = financial_document_data.lower()

    risks = {
        "debt": ["debt", "liabilities", "borrowings"],
        "volatility": ["volatile", "uncertain", "instability", "fluctuations"],
        "losses": ["loss", "negative cash flow", "decline"],
        "litigation": ["lawsuit", "legal", "regulatory", "penalty", "compliance"],
    }

    red_flags = []
    for risk_area, keywords in risks.items():
        matches = [kw for kw in keywords if kw in text]
        if matches:
            red_flags.append(f"- {risk_area.capitalize()} concerns: {', '.join(matches)}")

    if not red_flags:
        return "No major risk concerns identified."

    return "Risk Assessment:\n" + "\n".join(red_flags)

