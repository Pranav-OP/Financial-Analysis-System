import os
import re
from dotenv import load_dotenv
from crewai.tools import tool
from crewai_tools.tools.pdf_search_tool import pdf_search_tool

load_dotenv()

@tool("read_financial_document")
def read_financial_document(path: str) -> str:
    """
    Reads and preprocesses text from a financial PDF document.
    Uses PDFSearchTool internally, then applies basic cleaning:
    1.Normalize whitespace
    2.Remove duplicate newlines/spaces
    3.Strip headers/footers like 'Page X'
    4.return the preprocessed text from document
    """
    print(f"Printing Path in read_financial_document {path}")
    
    # Normalize path to avoid path traversal issues
    path = os.path.normpath(path)
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")

    # Extract raw text
    pdf_tool = pdf_search_tool.PDFSearchTool(pdf=path)
    raw_text = pdf_tool.run("Extract full text") or ""

    # Preprocessing
    text = raw_text.encode("utf-8", errors="ignore").decode("utf-8")
    text = re.sub(r"\n{2,}", "\n", text)         # collapse multiple newlines
    text = re.sub(r"[ \t]{2,}", " ", text)       # collapse multiple spaces/tabs
    text = re.sub(r"Page \d+\s*", "", text)      # strip page markers
    text = text.strip()

    return text


# Investment analysis tool
@tool("investment_analysis")
def analyze_investment_tool(financial_document_data: str) -> str:
    """
    Analyzes financial document data for potential investment insights.
    Extracts growth, profitability, and opportunity indicators.
    """
    text = financial_document_data.lower()

    # Simple keyword-based logic
    signals = {
        "growth": ["growth", "increase", "expansion", "positive trend", "forecast"],
        "profitability": ["profit", "margin", "revenue", "net income"],
        "opportunity": ["investment", "opportunity", "roi", "valuation"],
    }

    insights = []
    for category, keywords in signals.items():
        matches = [kw for kw in keywords if kw in text]
        if matches:
            insights.append(f"- {category.capitalize()} indicators found: {', '.join(matches)}")

    if not insights:
        return "No significant investment indicators detected."

    return "Investment Analysis:\n" + "\n".join(insights)


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

