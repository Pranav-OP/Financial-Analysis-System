## Importing libraries and files
from crewai import Task
from agents import financial_analyst, verifier, investment_advisor, risk_assessor, report_compiler
from tools import read_financial_document, analyze_investment_tool, create_risk_assessment_tool

## Creating a task to help solve user's query
analyze_financial_document = Task(
    description=(
        "1. Read and extract the content of the document stored at path {document_path}"
        "2. Analyze the extracted financial data. Extract key figures, ratios, and insights. "
        "3. Summarize revenue, profit, expenses, and growth trends."
        "4. Answer the user query: {query}"
        "5. Format your response as valid JSON with analysis_type, executive_summary, key_metrics, growth_trends, risks, and recommendations"
    ),
    expected_output=(
        "A structured JSON report including:\n"
        "- analysis_type: 'financial_analysis'\n"
        "- executive_summary: Brief overview\n"
        "- key_metrics: Financial figures\n"
        "- growth_trends: Growth indicators\n"
        "- risks: Identified risks\n"
        "- recommendations: Action items"
    ),
    agent=financial_analyst,
    tools=[read_financial_document, analyze_investment_tool],
    async_execution=False,
)

## Creating an investment analysis task
investment_analysis = Task(
    description=(
        "1. Use the read_financial_document tool to get the document content stored at path {document_path}"
        "2. Based on the financial analysis, provide compliant investment recommendations. "
        "3. Focus on asset classes, sectors, or general strategies rather than stock tips."
        "4. Format your response as valid JSON with recommendation_type, investment_themes, asset_allocation, risk_assessment, time_horizon, and disclaimer"
    ),
    expected_output=(
        "JSON recommendations including:\n"
        "- recommendation_type: 'investment_advice'\n"
        "- investment_themes: List of themes\n"
        "- asset_allocation: Portfolio suggestions\n"
        "- risk_assessment: Risk evaluation\n"
        "- time_horizon: Investment timeline\n"
        "- disclaimer: Legal disclaimer"
    ),
    agent=investment_advisor,
    tools=[read_financial_document, analyze_investment_tool],
    async_execution=False,
)

## Creating a risk assessment task
risk_assessment = Task(
    description=(
        "1. Read and extract the content of the document stored at path {document_path}"
        "2. Identify financial and market risks mentioned in the document. "
        "3. Highlight vulnerabilities and propose mitigation strategies."
        "4. Provide a concise JSON ONLY response in exactly this schema with no extra fields:\n"
        "{\n"
        '  "assessment_type": "risk_analysis",\n'
        '  "identified_risks": [\n'
        "    {\n"
        '      "risk": "…",\n'
        '      "description": "…",\n'
        '      "severity": "High|Medium|Low",\n'
        '      "likelihood": "High|Medium|Low",\n'
        '      "strategy": "…"\n'
        "    }\n"
        "  ]\n"
        "}\n"
        "Ensure valid JSON, no markdown fences, and avoid redundancy."
    ),
    expected_output=(
        "JSON risk assessment including:\n"
        "- assessment_type: 'risk_analysis'\n"
        "- identified_risks: List of risks with description/severity/likelihood/stratergy\n"
    ),
    agent=risk_assessor,
    tools=[read_financial_document, create_risk_assessment_tool],
    async_execution=False,
)

# Creating a file verification task
verification_task = Task(
    description=(
        "1. Read and extract the content of the document stored at path {document_path}"
        "2. Verify whether the uploaded file is a valid financial document before analysis."
        "3. Format your response as valid JSON with verification_result, document_type, confidence, reasoning, and key_sections_found"
    ),
    expected_output=(
        "JSON validation result:\n"
        "- verification_result: 'valid' or 'invalid'\n"
        "- document_type: Type of financial document\n"
        "- confidence: Confidence score (0.0-1.0)\n"
        "- reasoning: Explanation of validation\n"
        "- key_sections_found: List of identified sections"
    ),
    agent=verifier,
    tools=[read_financial_document],
    async_execution=False
)


# final compiler task combines all three
final_report = Task(
    description=(
        "Combine the prior tasks' outputs into one final JSON object ONLY. "
        'The EXACT output schema: {"summary": <financial_analysis JSON or string>, '
        '"investment_insights": <investment JSON>, '
        '"risk_assessment": {"assessment_type":"risk_analysis","identified_risks":[...]}}'
    ),
    expected_output=(
        '{"summary": {... or string}, "investment_insights": {...}, '
        '"risk_assessment":{"assessment_type":"risk_analysis","identified_risks":[...]}}'
    ),
    agent=report_compiler,
    context=[analyze_financial_document, investment_analysis, risk_assessment],
    async_execution=False,
)