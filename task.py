"""
Task graph for the Financial Document Analyzer crew (sequential process).

Flow:  verify -> analyze -> invest -> risk   (final JSON assembled in Python, see
celery_tasks.py — no LLM "compiler" call).

Retrieve-then-generate RAG: the relevant passages are retrieved BEFORE the crew runs
and injected into these prompts via kickoff inputs:
  {doc_preview}        -> start of the document (for verification)
  {financial_context}  -> passages about revenue/margins/cash flow/guidance
  {risk_context}       -> passages about risks/litigation/debt/competition
Each agent therefore makes a single tool-free LLM call.
"""

from crewai import Task

from agents import financial_analyst, verifier, investment_advisor, risk_assessor

# --- 1. Verification ----------------------------------------------------------
verification_task = Task(
    description=(
        "Decide whether this is a genuine financial document (10-Q, 10-K, annual report, "
        "earnings update, investor presentation) suitable for analysis.\n\n"
        "Document excerpt:\n\"\"\"\n{doc_preview}\n\"\"\"\n\n"
        "Return valid JSON only: verification_result, document_type, confidence, "
        "reasoning, key_sections_found."
    ),
    expected_output=(
        "JSON: {verification_result: 'valid'|'invalid', document_type, confidence (0-1), "
        "reasoning, key_sections_found: [...]}"
    ),
    agent=verifier,
    async_execution=False,
)

# --- 2. Financial analysis ----------------------------------------------------
analyze_financial_document = Task(
    description=(
        "Analyse the financial document using the excerpts below.\n"
        "1. Extract concrete figures, ratios, and growth trends (revenue, profit, margins, "
        "expenses, cash flow, guidance).\n"
        "2. Answer the user's query: {query}\n"
        "3. If verification marked the document invalid, say so in executive_summary and "
        "keep other fields minimal.\n\n"
        "Relevant financial excerpts:\n\"\"\"\n{financial_context}\n\"\"\"\n\n"
        "Return valid JSON only with: analysis_type, executive_summary, key_metrics, "
        "growth_trends, risks, recommendations."
    ),
    expected_output=(
        "JSON: {analysis_type: 'financial_analysis', executive_summary, key_metrics: {...}, "
        "growth_trends: {...}, risks: [...], recommendations: [...]}"
    ),
    agent=financial_analyst,
    context=[verification_task],
    async_execution=False,
)

# --- 3. Investment recommendations --------------------------------------------
investment_analysis = Task(
    description=(
        "Using the financial analysis from the previous step, provide compliant investment "
        "recommendations. Focus on asset classes, sectors, and general strategies rather "
        "than individual stock tips.\n"
        "Return valid JSON only with: recommendation_type, investment_themes, "
        "asset_allocation, risk_assessment, time_horizon, disclaimer."
    ),
    expected_output=(
        "JSON: {recommendation_type: 'investment_advice', investment_themes: [...], "
        "asset_allocation: {...}, risk_assessment, time_horizon, disclaimer}"
    ),
    agent=investment_advisor,
    context=[analyze_financial_document],
    async_execution=False,
)

# --- 4. Risk assessment -------------------------------------------------------
risk_assessment = Task(
    description=(
        "Identify financial, market, and operational risks using the excerpts below. "
        "Highlight vulnerabilities and propose mitigations.\n\n"
        "Relevant risk-related excerpts:\n\"\"\"\n{risk_context}\n\"\"\"\n\n"
        "Return valid JSON ONLY in exactly this schema (no extra fields):\n"
        "{\n"
        '  "assessment_type": "risk_analysis",\n'
        '  "identified_risks": [\n'
        '    {"risk": "…", "description": "…", "severity": "High|Medium|Low", '
        '"likelihood": "High|Medium|Low", "strategy": "…"}\n'
        "  ]\n"
        "}\n"
        "Valid JSON, no markdown fences, no redundancy."
    ),
    expected_output=(
        "JSON: {assessment_type: 'risk_analysis', identified_risks: [{risk, description, "
        "severity, likelihood, strategy}]}"
    ),
    agent=risk_assessor,
    context=[analyze_financial_document],
    async_execution=False,
)
