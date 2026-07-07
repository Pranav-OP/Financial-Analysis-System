from celery_app import app
# Import project modules at top level so they resolve during worker startup (when the
# project root is on sys.path). A lazy import inside the task fails on some Celery/
# Windows setups because the worker's sys.path no longer includes the cwd at run time.
from tools import read_financial_document, search_financial_document
from main import crew
from pymongo import MongoClient
from gridfs import GridFS
from bson import ObjectId
import json
import re
from datetime import datetime
import os
import io
import uuid
from celery.exceptions import Retry

# MongoDB connection (synchronous)
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "finanalyzer")
mongo_client = MongoClient(MONGO_URI)
db = mongo_client[DB_NAME]

# GridFS bucket (synchronous)
gridfs = GridFS(db, collection="documents")


# @app.task(bind=True, max_retries=3, default_retry_delay=60)
# def process_analysis_task(self, doc_id, query="Analyze this financial document"):
#     try:
#         # Update job status → processing
#         db.jobs.update_one(
#             {"job_id": self.request.id},
#             {"$set": {"status": "processing", "updated_at": datetime.utcnow()}}
#         )

#         # Fetch document
#         doc = db.documents.find_one({"_id": doc_id})
#         if not doc:
#             raise ValueError(f"Document {doc_id} not found")

#         file_obj = gridfs.get(doc["gridfs_file_id"])
#         staged_path = f"data/{doc_id}_{doc['filename']}"
#         os.makedirs("data", exist_ok=True)
#         with open(staged_path, "wb") as f:
#             f.write(file_obj.read())

#         from main import crew
#         result = crew.kickoff(inputs={"document_path": staged_path, "query": query})

#         combined = _first_json_block(result.raw)
#         if not combined:
#             raise ValueError("Failed to parse analysis result")

#         # Save analysis
#         analysis_id = str(uuid.uuid4())
#         analysis_result = {
#             "_id": analysis_id,
#             "analysis_id": analysis_id,
#             "document_id": doc_id,
#             "query": query,
#             "summary": json.dumps(combined.get("summary", {}), indent=2, ensure_ascii=False),
#             "investment_insights": json.dumps(combined.get("investment_insights", {}), indent=2, ensure_ascii=False),
#             "risk_assessment": json.dumps(combined.get("risk_assessment", {}), indent=2, ensure_ascii=False),
#             "raw_excerpt": combined.get("raw_excerpt", ""),
#             "created_at": datetime.utcnow(),
#             "status": "completed",
#         }
#         db.analyses.insert_one(analysis_result)

#         # Update job → completed
#         db.jobs.update_one(
#             {"job_id": self.request.id},
#             {"$set": {
#                 "status": "completed",
#                 "analysis_id": analysis_id,
#                 "updated_at": datetime.utcnow()
#             }}
#         )

#         if os.path.exists(staged_path):
#             os.remove(staged_path)

#         return {"status": "completed", "analysis_id": analysis_id}

#     except Exception as e:
#         print(f"Error in process_analysis_task: {str(e)}")

#         # Mark job failed
#         db.jobs.update_one(
#             {"job_id": self.request.id},
#             {"$set": {
#                 "status": "failed",
#                 "error": str(e),
#                 "updated_at": datetime.utcnow()
#             }}
#         )
#         raise


# def _first_json_block(text: str):
#     """Extract first valid JSON block from raw LLM output."""
#     if not text:
#         return None

#     # Step 1: Strip markdown code fences (```json ... ```)
#     code_fence_match = re.search(r"```(?:json)?(.*?)```", text, re.DOTALL | re.IGNORECASE)
#     if code_fence_match:
#         candidate = code_fence_match.group(1).strip()
#         try:
#             return json.loads(candidate)
#         except Exception as e:
#             print(f"Failed parsing fenced JSON: {e}")

#     # Step 2: Look for first {...} block in text
#     json_match = re.search(r"\{.*\}", text, re.DOTALL)
#     if json_match:
#         candidate = json_match.group()
#         try:
#             return json.loads(candidate)
#         except Exception as e:
#             print(f"Failed parsing brace JSON: {e}")

#     # Step 3: Try whole text
#     try:
#         return json.loads(text)
#     except Exception as e:
#         print(f"Failed parsing full text JSON: {e}")
#         return None
    

@app.task(bind=True, max_retries=3, default_retry_delay=60)
def process_analysis_task(self, doc_id, query="Analyze this financial document"):
    try:
        # Update job → processing
        db.jobs.update_one(
            {"job_id": self.request.id},
            {"$set": {"status": "processing", "updated_at": datetime.utcnow()}}
        )

        # Fetch document
        doc = db.documents.find_one({"_id": doc_id})
        if not doc:
            raise ValueError(f"Document {doc_id} not found")

        # Stage file
        file_obj = gridfs.get(doc["gridfs_file_id"])
        staged_path = f"data/{doc_id}_{doc['filename']}"
        os.makedirs("data", exist_ok=True)
        with open(staged_path, "wb") as f:
            f.write(file_obj.read())

        # Retrieve-then-generate: pull the relevant passages ONCE (local RAG) and inject
        # them into the crew, so each agent makes a single tool-free LLM call.
        doc_preview = read_financial_document.func(staged_path)
        financial_context = search_financial_document.func(
            staged_path, "revenue, profit, gross margin, operating income, expenses, cash flow, guidance, growth"
        )
        risk_context = search_financial_document.func(
            staged_path, "risks, litigation, regulatory, debt, liquidity, competition, supply chain, uncertainty"
        )

        # Run CrewAI pipeline
        result = crew.kickoff(inputs={
            "document_path": staged_path,
            "query": query,
            "doc_preview": doc_preview,
            "financial_context": financial_context,
            "risk_context": risk_context,
        })

        def _first_json(text):
            """Best-effort parse of a JSON object out of an LLM's raw text output."""
            if isinstance(text, (dict, list)):
                return text
            if not isinstance(text, str):
                return None
            if "```" in text:  # fenced code blocks first
                for b in re.findall(r"```(?:json)?\s*([\s\S]*?)```", text, re.IGNORECASE):
                    try:
                        return json.loads(b.strip())
                    except Exception:
                        continue
            m = re.search(r"\{[\s\S]*\}", text)  # first {...} block
            if m:
                try:
                    return json.loads(m.group(0))
                except Exception:
                    pass
            try:
                return json.loads(text)
            except Exception:
                return None

        # Assemble the final result in Python from each task's output instead of a
        # dedicated LLM "compiler" call. Task order matches main.crew.tasks:
        #   0 = verification, 1 = analysis, 2 = investment, 3 = risk
        def _task_raw(idx):
            outs = getattr(result, "tasks_output", None) or []
            if 0 <= idx < len(outs):
                return getattr(outs[idx], "raw", None) or str(outs[idx])
            return None

        summary_val = _first_json(_task_raw(1)) or _task_raw(1)
        investment_val = _first_json(_task_raw(2)) or _task_raw(2)
        risk_val = _first_json(_task_raw(3)) or _task_raw(3)

        # summary
        if isinstance(summary_val, (dict, list)):
            summary = json.dumps(summary_val, ensure_ascii=False, indent=2)
        else:
            summary = str(summary_val) if summary_val is not None else "No summary produced."

        # investment insights
        if investment_val is not None:
            investment_insights = (
                json.dumps(investment_val, ensure_ascii=False, indent=2)
                if isinstance(investment_val, (dict, list))
                else str(investment_val)
            )
        else:
            investment_insights = None

        # risk assessment
        if risk_val is not None:
            risk_assessment = (
                json.dumps(risk_val, ensure_ascii=False, indent=2)
                if isinstance(risk_val, (dict, list))
                else str(risk_val)
            )
        else:
            risk_assessment = None

        # Get user_id from the job entry
        job = db.jobs.find_one({"job_id": self.request.id})
        user_id = job.get("user_id") if job else None

        # Save analysis
        analysis_id = str(uuid.uuid4())
        analysis_doc = {
            "_id": analysis_id,
            "analysis_id": analysis_id,
            "document_id": doc_id,
            "user_id": user_id,
            "query": query,
            "summary": summary,
            "investment_insights": investment_insights,
            "risk_assessment": risk_assessment,
            "created_at": datetime.utcnow(),
            "completed_at": datetime.utcnow(),
            "status": "completed",
        }
        db.analyses.insert_one(analysis_doc)

        # Update job → completed
        db.jobs.update_one(
            {"job_id": self.request.id},
            {"$set": {
                "status": "completed",
                "analysis_id": analysis_id,
                "updated_at": datetime.utcnow()
            }}
        )

        # cleanup
        if os.path.exists(staged_path):
            os.remove(staged_path)

        return {"status": "completed", "analysis_id": analysis_id}

    except Exception as e:
        print(f"Error in process_analysis_task: {str(e)}")
        db.jobs.update_one(
            {"job_id": self.request.id},
            {"$set": {
                "status": "failed",
                "error": str(e),
                "updated_at": datetime.utcnow()
            }}
        )
        raise