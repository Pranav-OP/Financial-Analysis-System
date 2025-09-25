import os
import re
import unicodedata
from collections import OrderedDict
from dotenv import load_dotenv
from crewai.tools import tool
from crewai_tools.tools.pdf_search_tool import pdf_search_tool
import pdfplumber

load_dotenv()

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


# def read_financial_document(path: str) -> str:
#     """
#     Reads and preprocesses text from a financial PDF document.
#     Uses PDFSearchTool internally, then applies basic cleaning:
#     1.Normalize whitespace
#     2.Remove duplicate newlines/spaces
#     3.Strip headers/footers like 'Page X'
#     4.return the preprocessed text from document
#     """
#     print(f"Printing Path in read_financial_document {path}")
    
#     # Normalize path to avoid path traversal issues
#     path = os.path.normpath(path)
#     if not os.path.exists(path):
#         raise FileNotFoundError(f"File not found: {path}")

#     print(f"Printing Path in read_financial_document {path}")
#     # Extract raw text
#     import PyPDF2

#     with open(path, "rb") as f:
#         reader = PyPDF2.PdfReader(f)
#         pdf_content = ""
#         for page in reader.pages:
#             pdf_content += page.extract_text() or ""

#     print("Extracted PDF content before passing to PDFSearchTool:\n", pdf_content)

#     # Now pass the content to PDFSearchTool
#     pdf_tool = pdf_search_tool.PDFSearchTool(pdf=path, content=pdf_content)
#     raw_text = pdf_tool.run("Extract full text") or ""

#     # Preprocessing
#     text = raw_text.encode("utf-8", errors="ignore").decode("utf-8")
#     text = re.sub(r"\n{2,}", "\n", text)         # collapse multiple newlines
#     text = re.sub(r"[ \t]{2,}", " ", text)       # collapse multiple spaces/tabs
#     text = re.sub(r"Page \d+\s*", "", text)      # strip page markers
#     text = text.strip()

#     return text

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
        with pdfplumber.open(path) as pdf:
            for page in pdf.pages:
                text_chunks.append(page.extract_text() or "")
    else:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text_chunks.append(f.read())

    raw_text = "\n".join(text_chunks)

    print(f"Printing Raw Text in read_financial_document \n {raw_text}")
    # Preprocess
    cleaned = preprocess_financial_text(raw_text)

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

