import asyncio
import os
import json
from datetime import datetime
from bson import ObjectId

from main import mongo_client, REDIS_URI, crew
from redis import Redis
from tools import ( read_financial_document, analyze_investment_tool, create_risk_assessment_tool )

# Connect to Redis
redis_client = Redis.from_url(REDIS_URI, decode_responses=True)
DB_NAME = os.getenv("DB_NAME", "finanalyzer")
db = mongo_client[DB_NAME]

# Job polling interval (seconds)
POLL_INTERVAL = 2

async def process_job(job: dict):
    analysis_id = job["analysis_id"]
    doc_id = job["doc_id"]
    query = job.get("query", "Analyze this document")

    print(f"[Worker] Processing analysis_id={analysis_id}, doc_id={doc_id}")

    # Update analysis status to running
    await db.analyses.update_one(
        {"_id": ObjectId(analysis_id)},
        {"$set": {"status": "running", "started_at": datetime.utcnow()}}
    )

    # Fetch document path from MongoDB
    doc = await db.documents.find_one({"_id": ObjectId(doc_id)})
    if not doc:
        await db.analyses.update_one(
            {"_id": ObjectId(analysis_id)},
            {"$set": {"status": "failed", "error": "Document not found"}}
        )
        return

    file_path = os.path.join("data/uploads", doc["filename"])
    if not os.path.exists(file_path):
        await db.analyses.update_one(
            {"_id": ObjectId(analysis_id)},
            {"$set": {"status": "failed", "error": "File missing"}}
        )
        return

    try:
        # ---------- Step 1: Read & preprocess PDF ----------
        raw_text = read_financial_document(file_path)

        # Optional: trim large text for preview
        raw_excerpt = raw_text[:2000]

        # ---------- Step 2: Investment analysis ----------
        investment_results = analyze_investment_tool(raw_text)

        # ---------- Step 3: Risk assessment ----------
        risk_results = create_risk_assessment_tool(raw_text)

        # ---------- Step 4: CrewAI agent analysis ----------
        crew_input = {"query": query, "document_path": file_path}
        crew_response = crew.kickoff(crew_input)  # can be async if needed

        # ---------- Step 5: Store results ----------
        result_doc = {
            "status": "completed",
            "completed_at": datetime.utcnow(),
            "summary": crew_response.get("summary") if isinstance(crew_response, dict) else str(crew_response),
            "investment_insights": investment_results,
            "risk_assessment": risk_results,
            "raw_excerpt": raw_excerpt,
            "query": query
        }

        await db.analyses.update_one(
            {"_id": ObjectId(analysis_id)},
            {"$set": result_doc}
        )

        # ---------- Step 6: Cache results in Redis ----------
        redis_client.setex(f"analysis:{analysis_id}", 3600, json.dumps(result_doc))
        print(f"[Worker] Analysis completed for {analysis_id}")

    except Exception as e:
        await db.analyses.update_one(
            {"_id": ObjectId(analysis_id)},
            {"$set": {"status": "failed", "error": str(e)}}
        )
        print(f"[Worker] Analysis failed for {analysis_id}: {str(e)}")


async def worker_loop():
    print("[Worker] Started worker loop...")
    while True:
        job_json = redis_client.lpop("analysis_jobs")
        if job_json:
            job = json.loads(job_json)
            await process_job(job)
        else:
            await asyncio.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    asyncio.run(worker_loop())
