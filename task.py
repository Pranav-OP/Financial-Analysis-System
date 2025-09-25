## Importing libraries and files
from crewai import Task
from agents import financial_analyst, verifier, investment_advisor, risk_assessor
from tools import read_financial_document, analyze_investment_tool, create_risk_assessment_tool

## Creating a task to help solve user's query
analyze_financial_document = Task(
    description=(
        "Analyze the uploaded financial document. Extract key figures, ratios, and insights. "
        "Summarize revenue, profit, expenses, and growth trends. Answer the user query: {query}"
    ),
    expected_output=(
        "A structured report including:\n"
        "- Executive summary\n"
        "- Key financial highlights (revenue, profit, margins, debt)\n"
        "- Growth trends\n"
        "- Notable risks or red flags\n"
        "- Clear and professional language"
    ),
    agent=financial_analyst,
    tools=[read_financial_document,analyze_investment_tool],
    async_execution=False,
)

## Creating an investment analysis task
investment_analysis = Task(
    description=(
        "Based on financial analysis, provide compliant investment recommendations. "
        "Focus on asset classes, sectors, or general strategies rather than stock tips."
    ),
    expected_output=(
        "Recommendations including:\n"
        "- Investment themes/sectors\n"
        "- Risk-return trade-offs\n"
        "- Portfolio allocation suggestions\n"
        "- Supporting rationale"
    ),
    agent=investment_advisor,
    tools=[analyze_investment_tool],
    async_execution=False,
)

## Creating a risk assessment task
risk_assessment = Task(
    description=(
        "Identify financial and market risks mentioned in the document. "
        "Highlight vulnerabilities and propose mitigation strategies."
    ),
    expected_output=(
        "Structured risk assessment including:\n"
        "- Identified risks\n"
        "- Severity and likelihood\n"
        "- Mitigation strategies\n"
        "- Industry benchmarks if relevant"
    ),
    agent=risk_assessor,
    tools=[read_financial_document, create_risk_assessment_tool],
    async_execution=False,
)

    
# Creating a file verification task
verification_task = Task(
    description="Verify whether the uploaded file is a valid financial document before analysis.",
    expected_output="A validation result (valid/invalid) with reasoning.",
    agent=verifier,
    tools=[read_financial_document],
    async_execution=False
)