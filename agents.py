"""
Agent definitions for the Financial Document Analyzer crew.

Design: retrieve-then-generate RAG.
Relevant passages are retrieved up front (see celery_tasks / tools.py) and injected
into each task's prompt, so every agent makes ONE clean LLM call with NO tools. This
is ~2x fewer calls than agentic tool-calling (faster + far fewer tokens, which matters
on free-tier per-minute limits) and avoids the ReAct tool loop that made some models
emit truncated / non-JSON output.

The LLM is wired through CrewAI's native `LLM` abstraction (LiteLLM under the hood);
the provider is chosen by the LLM_MODEL env var (Groq by default).
"""

import os
from dotenv import load_dotenv

from crewai import Agent, LLM

load_dotenv()

# --- LLM provider selection (env-driven, one-line swap) -----------------------
# Chat model examples:
#   groq/llama-3.3-70b-versatile   (Groq — generous free tier, recommended)
#   gemini/gemini-2.5-flash        (Google — free tier only ~5 req/min)
LLM_MODEL = os.getenv("LLM_MODEL", "gemini/gemini-2.5-flash")
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.2"))

# RAG embeddings (tools.py) default to a local model; a Google key is only needed for
# gemini chat or EMBED_PROVIDER=gemini. LiteLLM reads GEMINI_API_KEY for gemini/* models.
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
if GOOGLE_API_KEY:
    os.environ["GEMINI_API_KEY"] = GOOGLE_API_KEY

llm_kwargs = {
    "model": LLM_MODEL,
    "temperature": LLM_TEMPERATURE,
    "num_retries": int(os.getenv("LLM_NUM_RETRIES", "3")),
}

if LLM_MODEL.startswith("groq/"):
    groq_key = os.getenv("GROQ_API_KEY")
    if not groq_key:
        raise ValueError("LLM_MODEL is a Groq model but GROQ_API_KEY is not set in .env")
    llm_kwargs["api_key"] = groq_key
elif LLM_MODEL.startswith("gemini/") and not GOOGLE_API_KEY:
    raise ValueError("LLM_MODEL is a Gemini model but GOOGLE_API_KEY is not set in .env")

llm = LLM(**llm_kwargs)

# --- Agent Definitions --------------------------------------------------------
# No tools + max_iter=1: each agent produces its JSON answer in a single call from the
# retrieved context injected into the task prompt.

financial_analyst = Agent(
    role="Senior Financial Analyst",
    goal="Provide accurate, compliant, data-driven analysis grounded in the provided financial excerpts.",
    backstory=(
        "You are an experienced financial analyst specializing in corporate earnings, "
        "macroeconomic indicators, and investment trends. You extract concrete figures and "
        "ratios from the provided document excerpts, assess performance with professional, "
        "compliant judgement, and never fabricate numbers that are not in the excerpts."
        "\n\nYou ALWAYS return valid JSON (no markdown fences) with this exact structure: "
        '{"analysis_type": "financial_analysis", "executive_summary": "...", '
        '"key_metrics": {...}, "growth_trends": {...}, "risks": [...], "recommendations": [...]}'
    ),
    llm=llm,
    max_iter=1,
    verbose=True,
    allow_delegation=False,
)


verifier = Agent(
    role="Financial Document Verifier",
    goal="Determine whether the provided document excerpt is a genuine financial document worth analysing.",
    backstory=(
        "You verify document integrity and type. From the provided excerpt, categorize the "
        "document as financial (10-Q, 10-K, annual report, earnings update, investor "
        "presentation) or non-financial, and reject irrelevant files."
        "\n\nYou ALWAYS return valid JSON (no markdown fences) with this exact structure: "
        '{"verification_result": "valid"|"invalid", "document_type": "...", '
        '"confidence": 0.0-1.0, "reasoning": "...", "key_sections_found": [...]}'
    ),
    llm=llm,
    max_iter=1,
    verbose=True,
    allow_delegation=False,
)


investment_advisor = Agent(
    role="Investment Advisor",
    goal="Recommend compliant, balanced, risk-adjusted investment strategies based on the analysis.",
    backstory=(
        "You are a seasoned investment advisor versed in asset allocation, risk-return "
        "trade-offs, and portfolio management. Ground recommendations in the financial "
        "analysis provided and regulatory best practice. Favor asset classes/sectors/"
        "strategies over individual stock tips."
        "\n\nYou ALWAYS return valid JSON (no markdown fences) with this exact structure: "
        '{"recommendation_type": "investment_advice", "investment_themes": [...], '
        '"asset_allocation": {...}, "risk_assessment": "...", "time_horizon": "...", '
        '"disclaimer": "..."}'
    ),
    llm=llm,
    max_iter=1,
    verbose=True,
    allow_delegation=False,
)


risk_assessor = Agent(
    role="Risk Management Specialist",
    goal="Identify financial, market, and operational risks and propose mitigations.",
    backstory=(
        "You are an expert in credit, liquidity, market, and operational risk. From the "
        "provided excerpts, highlight realistic risks and suggest concrete mitigation "
        "approaches. Do not invent risks the excerpts do not support."
        "\n\nYou ALWAYS return valid JSON (no markdown fences) with this exact structure: "
        '{"assessment_type": "risk_analysis", "identified_risks": [...], "risk_matrix": {...}, '
        '"mitigation_strategies": [...], "overall_risk_rating": "...", '
        '"monitoring_recommendations": [...]}'
    ),
    llm=llm,
    max_iter=1,
    verbose=True,
    allow_delegation=False,
)
