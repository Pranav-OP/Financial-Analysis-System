from celery_app import app
from tools import read_financial_document, analyze_investment_tool, create_risk_assessment_tool
from task import final_report
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

        # Run CrewAI pipeline
        from main import crew
        result = crew.kickoff(inputs={"document_path": staged_path, "query": query}, tasks=[final_report])

        out_text = getattr(result, "raw", None) or getattr(result, "output", None) or str(result)

        def _first_json(text: str):
            if not isinstance(text, str):
                return None
            # fenced code blocks first
            if "```" in text:
                blocks = re.findall(r"```(?:json)?\s*([\s\S]*?)```", text, re.IGNORECASE)
                for b in blocks:
                    try:
                        return json.loads(b.strip())
                    except Exception:
                        continue
            # fallback: first {...}
            m = re.search(r"\{[\s\S]*\}", text)
            if m:
                try:
                    return json.loads(m.group(0))
                except Exception:
                    return None
            # last resort: parse full text
            try:
                return json.loads(text)
            except Exception:
                return None

        combined = _first_json(out_text) or {}

        # Extract + pretty format fields
        summary_val = combined.get("summary")
        investment_val = combined.get("investment_insights")
        risk_val = combined.get("risk_assessment")

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