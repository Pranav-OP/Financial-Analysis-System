from celery_app import app
from tools import read_financial_document, analyze_investment_tool, create_risk_assessment_tool
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


@app.task(bind=True, max_retries=3, default_retry_delay=60)
def process_analysis_task(self, doc_id, query="Analyze this financial document"):
    try:
        # Update job status → processing
        db.jobs.update_one(
            {"job_id": self.request.id},
            {"$set": {"status": "processing", "updated_at": datetime.utcnow()}}
        )

        # Fetch document
        doc = db.documents.find_one({"_id": doc_id})
        if not doc:
            raise ValueError(f"Document {doc_id} not found")

        file_obj = gridfs.get(doc["gridfs_file_id"])
        staged_path = f"data/{doc_id}_{doc['filename']}"
        os.makedirs("data", exist_ok=True)
        with open(staged_path, "wb") as f:
            f.write(file_obj.read())

        from main import crew
        result = crew.kickoff(inputs={"document_path": staged_path, "query": query})

        combined = _first_json_block(result.raw)
        if not combined:
            raise ValueError("Failed to parse analysis result")

        # Save analysis
        analysis_id = str(uuid.uuid4())
        analysis_result = {
            "_id": analysis_id,
            "analysis_id": analysis_id,
            "document_id": doc_id,
            "query": query,
            "summary": json.dumps(combined.get("summary", {}), indent=2, ensure_ascii=False),
            "investment_insights": json.dumps(combined.get("investment_insights", {}), indent=2, ensure_ascii=False),
            "risk_assessment": json.dumps(combined.get("risk_assessment", {}), indent=2, ensure_ascii=False),
            "raw_excerpt": combined.get("raw_excerpt", ""),
            "created_at": datetime.utcnow(),
            "status": "completed",
        }
        db.analyses.insert_one(analysis_result)

        # Update job → completed
        db.jobs.update_one(
            {"job_id": self.request.id},
            {"$set": {
                "status": "completed",
                "analysis_id": analysis_id,
                "updated_at": datetime.utcnow()
            }}
        )

        if os.path.exists(staged_path):
            os.remove(staged_path)

        return {"status": "completed", "analysis_id": analysis_id}

    except Exception as e:
        print(f"Error in process_analysis_task: {str(e)}")

        # Mark job failed
        db.jobs.update_one(
            {"job_id": self.request.id},
            {"$set": {
                "status": "failed",
                "error": str(e),
                "updated_at": datetime.utcnow()
            }}
        )
        raise


def _first_json_block(text):
    """Extract first JSON block from text"""
    if not text:
        return None
    
    # Try to find JSON in the text
    json_match = re.search(r'\{.*\}', text, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group())
        except:
            pass
    
    # Fallback: try to parse the entire text as JSON
    try:
        return json.loads(text)
    except:
        return None