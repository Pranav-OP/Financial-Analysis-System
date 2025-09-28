# --- Importing libraries and files ---
import os
from dotenv import load_dotenv
from crewai import Agent
from tools import (
    read_financial_document,
    analyze_investment_tool,
    create_risk_assessment_tool,
)

load_dotenv()

# --- Import and initialize LLM with LiteLLM ---
from litellm import completion

# Set up environment variable for Gemini
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
os.environ["GEMINI_API_KEY"] = GOOGLE_API_KEY

if not GOOGLE_API_KEY:
    raise ValueError("Google API key not found in environment variables")

# Create a LiteLLM wrapper class for CrewAI compatibility
class LiteLLMWrapper:
    def __init__(self, model_name, temperature=0.3):
        self.model_name = model_name
        self.temperature = temperature
    
    def __call__(self, messages, **kwargs):
        try:
            response = completion(
                model=self.model_name,
                messages=messages,
                temperature=kwargs.get('temperature', self.temperature),
                **kwargs
            )
            return response
        except Exception as e:
            print(f"LiteLLM Error: {e}")
            raise e
    
    def invoke(self, prompt, **kwargs):
        """Alternative method for compatibility"""
        messages = [{"role": "user", "content": prompt}]
        return self.__call__(messages, **kwargs)

# Create the LLM instance with correct model format
llm = LiteLLMWrapper(
    model_name="gemini/gemini-2.0-flash", 
    #model_name="gemini/gemini-2.5-pro", 
    temperature=0.3
)

# Verify LLM is properly initialized
if llm is None:
    raise ValueError("An LLM instance must be provided to create agents.")

# --- Agent Definitions ---

financial_analyst = Agent(
    role="Senior Financial Analyst",
    goal="Provide accurate, compliant, and data-driven analysis of financial documents and market trends.",
    backstory=(
        "The document is stored at path {document_path}"
        "You are an experienced financial analyst specializing in corporate earnings, macroeconomic indicators,"
        "and investment trends. You carefully read reports, extract key financial ratios, assess performance,"
        "and provide professional, compliant insights based on relevant financial data found in document."
        "You ALWAYS format your final analysis as valid JSON with the following structure: "
        "{'analysis_type': 'financial_analysis', 'executive_summary': '...', 'key_metrics': {...}, "
        "'growth_trends': {...}, 'risks': [...], 'recommendations': [...]}"
    ),
    tools=[read_financial_document, analyze_investment_tool, create_risk_assessment_tool],
    llm=llm,
    max_iter=1,
    max_rpm=10,
    verbose=True,
    allow_delegation=False
)


verifier = Agent(
    role="Financial Document Verifier",
    goal="Validate that uploaded files are genuine financial documents and suitable for analysis.",
    verbose=True,
    backstory=(
        "Input parameter for the document is {document_path}"
        "You are responsible for verifying document integrity and its type. "
        "Your task is to ensure uploaded documents are relevant financial files "
        "Categorize the given document as either financial or non-financial documents"
        "(e.g., 10-Q, annual reports, investor presentations) and reject irrelevant ones."
        "You ALWAYS return your verification result as valid JSON with this structure: "
        "{'verification_result': 'valid'|'invalid', 'document_type': '...', 'confidence': 0.0-1.0, "
        "'reasoning': '...', 'key_sections_found': [...]}"
    ),
    tools=[read_financial_document],
    llm=llm,
    max_iter=1,
    max_rpm=10,
    allow_delegation=True
)


investment_advisor = Agent(
    role="Investment Advisor",
    goal="Recommend compliant, balanced, and risk-adjusted investment strategies based on analysis.",
    verbose=True,
    backstory=(
        "You are a seasoned investment advisor with knowledge of asset allocation, "
        "risk-return trade-offs, and portfolio management. Your recommendations are "
        "grounded in the analysis results and follow regulatory best practices."
        "You ALWAYS format your recommendations as valid JSON with this structure: "
        "{'recommendation_type': 'investment_advice', 'investment_themes': [...], "
        "'asset_allocation': {...}, 'risk_assessment': '...', 'time_horizon': '...', "
        "'disclaimer': '...'}"
    ),
    tools=[analyze_investment_tool],
    llm=llm,
    max_iter=1,
    max_rpm=10,
    allow_delegation=False
)


risk_assessor = Agent(
    role="Risk Management Specialist",
    goal="Identify financial, market, and operational risks from documents and provide mitigation strategies.",
    verbose=True,
    backstory=(
        "You are an expert in financial risk management, focusing on credit, liquidity, "
        "market, and operational risks. Your task is to highlight realistic risks in "
        "the analyzed documents and suggest mitigation approaches."
        "You ALWAYS format your risk assessment as valid JSON with this structure: "
        "{'assessment_type': 'risk_analysis', 'identified_risks': [...], 'risk_matrix': {...}, "
        "'mitigation_strategies': [...], 'overall_risk_rating': '...', 'monitoring_recommendations': [...]}"
    ),
    tools=[create_risk_assessment_tool],
    llm=llm,
    max_iter=1,
    max_rpm=10,
    allow_delegation=False
)


document_processor = Agent(
    role="Document Processing Specialist",
    goal="Handle file processing, path resolution, and ensure documents are accessible to other agents. Always return output in valid JSON format.",
    verbose=True,
    backstory=(
        "Input parameter for the document is {document_path}"
        "You are responsible for processing uploaded documents and ensuring they are "
        "properly accessible to other agents. You handle file path resolution, "
        "document format validation, and initial content extraction. "
        "You ALWAYS return processing results as valid JSON with this structure: "
        "{'processing_status': 'success'|'failure', 'file_path': '...', 'document_content': '...', "
        "'file_size': 0, 'pages': 0, 'error_message': null}"
    ),
    tools=[read_financial_document],
    llm=llm,
    max_iter=1,
    max_rpm=10,
    allow_delegation=False
)


report_compiler = Agent(
    role="Report Compiler",
    goal="Combine prior agents' outputs into one final JSON object with summary, investment insights, and risk assessment.",
    backstory=(
        "You consolidate the outputs from Financial Analyst, Investment Advisor, and Risk Specialist. "
        "You must output a single valid JSON with exactly these keys: "
        '{"summary": {... or string}, "investment_insights": {...}, "risk_assessment": {"assessment_type":"risk_analysis","identified_risks":[...]}} '
        "No markdown fences, no extra text."
    ),
    llm=llm,
    max_iter=1,
    max_rpm=10,
    allow_delegation=False
)
