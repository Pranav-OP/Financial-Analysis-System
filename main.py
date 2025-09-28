# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
import os, io, csv, uuid, shutil, json, re
import redis.asyncio as aioredis
from dotenv import load_dotenv
from bson import ObjectId
from crewai import Crew
from celery_app import app as celery_app
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorGridFSBucket

from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Depends, Body, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi_limiter import FastAPILimiter,RateLimiter

from typing import Optional, List
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet

from models import (
    UserRegister, UserLogin, UserResponse, UserCreate, UserOut, Token,
    DocumentUploadResponse, DocumentListResponse, DocumentMeta,
    AnalysisRequest, AnalysisResult
)

load_dotenv()

# -----------------------------------------------------------------------------
# CrewAI SETUP
# -----------------------------------------------------------------------------

from agents import financial_analyst, verifier, investment_advisor, risk_assessor, report_compiler
from task import analyze_financial_document, investment_analysis, risk_assessment, verification_task, final_report

crew = Crew(
    agents=[financial_analyst, verifier, investment_advisor, risk_assessor, report_compiler],
    tasks=[verification_task, analyze_financial_document, investment_analysis, risk_assessment, final_report]
)

# -----------------------------------------------------------------------------
# FastAPI APP SETUP
# -----------------------------------------------------------------------------
app = FastAPI(title="Financial Document Analyzer")

@app.on_event("startup")
async def startup():
    redis = await aioredis.from_url("redis://localhost:6379", encoding="utf8", decode_responses=True)
    await FastAPILimiter.init(redis)

# Allow CORS for local frontend during development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "http://localhost:5174"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------------------------------------------------------
# ENV CONFIG
# -----------------------------------------------------------------------------
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "finanalyzer")
REDIS_URI = os.getenv("REDIS_URI", "redis://localhost:6379")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "supersecret")

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# -----------------------------------------------------------------------------
# DB CLIENTS
# -----------------------------------------------------------------------------
mongo_client = AsyncIOMotorClient(MONGO_URI)
db = mongo_client[DB_NAME]
#redis = aioredis.from_url(REDIS_URI, decode_responses=True)

# -----------------------------------------------------------------------------
# SECURITY HELPERS
# -----------------------------------------------------------------------------
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def create_refresh_token(data: dict):
    expire = datetime.utcnow() + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    to_encode = {**data, "exp": expire, "scope": "refresh_token"}
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Decode JWT and fetch user from DB"""
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = await db.users.find_one({"_id": user_id})
    if not user:
        raise credentials_exception
    return user


def require_role(required_roles: List[str]):
    """Factory for role-based dependency"""
    async def role_checker(user=Depends(get_current_user)):
        roles = user.get("roles", [])
        if not any(r in roles for r in required_roles):
            raise HTTPException(status_code=403, detail="Not enough permissions")
        return user
    return role_checker


# -----------------------------------------------------------------------------
# API ENDPOINTS
# -----------------------------------------------------------------------------

@app.get("/")
async def root():
    """Health check endpoint"""
    return {"message": "Financial Document Analyzer API is running"}

# ------------------ AUTH ------------------

@app.post("/auth/register", response_model=UserOut)
async def register(user: UserCreate):
    """Register a new user"""
    existing = await db.users.find_one({"email": user.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_pw = get_password_hash(user.password)
    user_doc = {
        "_id": str(uuid.uuid4()),
        "email": user.email,
        "username": user.username,
        "password_hash": hashed_pw,
        "full_name": user.full_name,
        "roles": ["viewer"],
        "is_active": True,
        "created_at": datetime.utcnow(),
    }
    await db.users.insert_one(user_doc)
    return UserOut(
        id=user_doc["_id"],
        email=user_doc["email"],
        username=user_doc["username"],
        full_name=user_doc["full_name"],
        roles=user_doc["roles"],
        created_at=user_doc["created_at"],
    )


@app.post("/auth/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Authenticate user and return JWT tokens"""
    user = await db.users.find_one({"username": form_data.username})
    if not user or not verify_password(form_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    claims = {"sub": user["_id"], "roles": user["roles"]}
    access_token = create_access_token(claims)
    refresh_token = create_refresh_token(claims)

    return {"access_token": access_token, "token_type": "bearer", "refresh_token": refresh_token}


@app.get("/auth/me", response_model=UserOut)
async def get_current_user_info(current_user=Depends(get_current_user)):
    """
    Return current logged-in user's info.
    Used by frontend to fetch roles and permissions.
    """
    return UserOut(
        id=current_user["_id"],
        email=current_user["email"],
        username=current_user["username"],
        full_name=current_user.get("full_name"),
        roles=current_user.get("roles", []),
        created_at=current_user.get("created_at")
    )

# ------------------ DOCUMENTS ------------------

@app.post("/documents/upload", response_model=DocumentMeta)
async def upload_document(
    file: UploadFile = File(...),
    current_user=Depends(require_role(["analyst", "admin"]))
):
    """Upload a financial document (PDF, DOCX, XLSX, CSV, Image)"""

    file_id = str(uuid.uuid4())
    content = await file.read()

    # Save file into GridFS
    gridfs_file_id = await gridfs_bucket.upload_from_stream(file.filename, content)

    doc = {
        "_id": file_id,
        "filename": file.filename,
        "gridfs_file_id": gridfs_file_id,  # Store as ObjectId, not string
        "uploader_id": current_user["_id"],
        "size_bytes": len(content),
        "status": "uploaded",
        "created_at": datetime.utcnow(),
    }
    await db.documents.insert_one(doc)

    return DocumentMeta(
        id=doc["_id"],
        filename=doc["filename"],
        status=doc["status"],
        size_bytes=doc["size_bytes"],
        uploader_id=doc["uploader_id"],
        created_at=doc["created_at"],
    )


@app.get("/documents", response_model=List[DocumentMeta])
async def list_documents(
    page: int = 1,
    limit: int = 20,
    q: str = None,
    current_user=Depends(get_current_user),
):
    query_filter = {}
    if "admin" not in current_user.get("roles", []):
        query_filter = {"uploader_id": current_user["_id"]}
    if q:
        query_filter["filename"] = {"$regex": q, "$options": "i"}

    cursor = (
        db.documents.find(query_filter)
        .sort("created_at", -1)
        .skip((page - 1) * limit)
        .limit(limit)
    )
    docs = await cursor.to_list(limit)

    return [DocumentMeta(
        id=d["_id"],
        filename=d["filename"],
        status=d["status"],
        size_bytes=d["size_bytes"],
        uploader_id=d["uploader_id"],
        created_at=d["created_at"],
    ) for d in docs]


@app.get("/documents/{doc_id}/download")
async def download_document(doc_id: str, current_user=Depends(get_current_user)):
    doc = await db.documents.find_one({"_id": doc_id})
    if not doc:
        raise HTTPException(404, "Document not found")
    if "admin" not in current_user.get("roles", []) and doc["uploader_id"] != current_user["_id"]:
        raise HTTPException(403, "Forbidden")

    # gridfs_file_id is already an ObjectId, no conversion needed
    grid_out = await gridfs_bucket.open_download_stream(doc["gridfs_file_id"])

    async def file_iterator():
        while chunk := await grid_out.readchunk():
            yield chunk

    return StreamingResponse(
        file_iterator(),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename={doc['filename']}"},
    )


@app.delete("/documents/{doc_id}")
async def delete_document(doc_id: str, current_user=Depends(get_current_user)):
    doc = await db.documents.find_one({"_id": doc_id})
    if not doc:
        raise HTTPException(404, "Document not found")
    if "admin" not in current_user.get("roles", []) and doc["uploader_id"] != current_user["_id"]:
        raise HTTPException(403, "Forbidden")

    # gridfs_file_id is already an ObjectId, no conversion needed
    await gridfs_bucket.delete(doc["gridfs_file_id"])
    await db.documents.delete_one({"_id": doc_id})
    await db.analyses.delete_many({"document_id": doc_id})  # cleanup analyses
    return {"status": "deleted"}

# ------------------ ANALYSES ------------------

@app.post("/analyses/{doc_id}", dependencies=[Depends(RateLimiter(times=3, seconds=60))])
async def request_analysis(
    doc_id: str,
    req: AnalysisRequest,
    current_user: dict = Depends(get_current_user)
):
    """Start a background analysis job"""
    # Check access
    query_filter = {"_id": doc_id}
    if "admin" not in current_user.get("roles", []):
        query_filter["uploader_id"] = current_user["_id"]

    doc = await db.documents.find_one(query_filter)
    if not doc:
        raise HTTPException(404, "Document not found or access denied")

    from celery_tasks import process_analysis_task

    # Start Celery task
    task = process_analysis_task.delay(doc_id, req.query)

    # Insert job entry in Mongo
    job_entry = {
        "job_id": task.id,
        "document_id": doc_id,
        "user_id": current_user["_id"],
        "status": "queued",
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    await db.jobs.insert_one(job_entry)

    return {
        "job_id": task.id,
        "status": "queued",
        "message": "Analysis started. Use job_id to check status."
    }


@app.get("/analyses/job/{job_id}")
async def get_job_status(job_id: str):
    """Get the status of a background analysis job from Mongo"""

    job = await db.jobs.find_one({"job_id": job_id})
    if not job:
        raise HTTPException(404, "Job not found")

    response = {
        "job_id": job["job_id"],
        "status": job["status"],
        "created_at": job["created_at"],
        "updated_at": job["updated_at"],
    }

    if job.get("analysis_id"):
        response["analysis_id"] = job["analysis_id"]
    if job.get("error"):
        response["error"] = job["error"]

    return response


@app.get("/analyses/status/{doc_id}")
async def check_analysis_status(doc_id: str, current_user=Depends(get_current_user)):
    """Check if analysis is complete by looking in database"""
    
    # Check if user is admin
    is_admin = "admin" in current_user.get("roles", [])
    
    # Find the most recent analysis for this document
    query_filter = {"document_id": doc_id}
    if not is_admin:
        query_filter["user_id"] = current_user["_id"]
    
    analysis = await db.analyses.find_one(
        query_filter,
        sort=[("created_at", -1)]
    )
    
    if not analysis:
        return {"status": "not_found", "message": "No analysis found for this document"}
    
    return {
        "status": analysis["status"],
        "analysis_id": str(analysis["_id"]),
        "message": "Analysis found" if analysis["status"] == "completed" else "Analysis in progress"
    }


@app.get("/analyses/{analysis_id}", response_model=AnalysisResult)
async def get_analysis(analysis_id: str, current_user=Depends(get_current_user)):
    """Get analysis result by ID or by job ID"""

    # 🔹 Check if it's actually a job_id
    job = await db.jobs.find_one({"job_id": analysis_id})
    if job and job.get("analysis_id"):
        analysis_id = job["analysis_id"]

    # Now fetch the real analysis
    analysis = await db.analyses.find_one({"_id": analysis_id})
    if not analysis:
        raise HTTPException(404, "Analysis not found")

    # Permission check
    if "admin" not in current_user.get("roles", []) and analysis.get("user_id") != current_user["_id"]:
        raise HTTPException(403, "Access denied")

    return AnalysisResult(
        id=str(analysis["_id"]),
        document_id=analysis["document_id"],
        status=analysis["status"],
        created_at=analysis["created_at"],
        completed_at=analysis.get("completed_at"),
        query=analysis.get("query"),
        summary=analysis.get("summary"),
        investment_insights=analysis.get("investment_insights"),
        risk_assessment=analysis.get("risk_assessment"),
        raw_excerpt=analysis.get("raw_excerpt")
    )


@app.get("/analyses", response_model=List[AnalysisResult])
async def list_analyses(
    document_id: str = None,
    current_user=Depends(get_current_user),
):
    query = {}
    if document_id:
        query["document_id"] = document_id
    if "admin" not in current_user.get("roles", []):
        query["uploader_id"] = current_user["_id"]

    cursor = db.analyses.find(query).sort("created_at", -1)
    analyses = await cursor.to_list(100)
    return [AnalysisResult(**a, id=str(a["_id"])) for a in analyses]

# ------------------ EXPORT ------------------

@app.get("/analyses/{analysis_id}/export")
async def export_analysis(analysis_id: str, format: str = "pdf", current_user=Depends(get_current_user)):
    analysis = await db.analyses.find_one({"_id": analysis_id})
    if not analysis:
        raise HTTPException(404, "Analysis not found")

    if format == "pdf":
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer)
        story = build_analysis_pdf_story({
            "query": analysis["query"],
            "summary": analysis["summary"],
            "investment_insights": analysis.get("investment_insights"),
            "risk_assessment": analysis.get("risk_assessment"),
        })
        doc.build(story)
        buffer.seek(0)
        return StreamingResponse(buffer, media_type="application/pdf", headers={
            "Content-Disposition": f"attachment; filename=analysis_{analysis_id}.pdf"
        })
    
    elif format == "csv":
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["Query", "Summary"])
        writer.writerow([analysis["query"], analysis["summary"]])
        buffer.seek(0)
        return StreamingResponse(io.BytesIO(buffer.read().encode()), media_type="text/csv", headers={
            "Content-Disposition": f"attachment; filename=analysis_{analysis_id}.csv"
        })
    
    else:
        raise HTTPException(400, "Unsupported format")

# -----------------------------------------------------------------------------
# DOCUMENT STAGING HELPERS
# -----------------------------------------------------------------------------

UPLOAD_DIR = "data"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# init GridFS bucket 
gridfs_bucket = AsyncIOMotorGridFSBucket(db, bucket_name="documents")

async def stage_file_for_analysis(doc_id: str, filename: str, gridfs_file_id: str) -> str:
    """Fetch file from GridFS and save locally for analysis."""

    staged_path = os.path.join(UPLOAD_DIR, f"{doc_id}_{filename}")

    # Open GridFS download stream
    download_stream = await gridfs_bucket.open_download_stream(ObjectId(gridfs_file_id))

    with open(staged_path, "wb") as f:
        while True:
            chunk = await download_stream.readchunk()
            if not chunk:
                break
            f.write(chunk)

    return staged_path

def cleanup_staged_file(path: str):
    """Remove staged file after analysis."""
    if os.path.exists(path):
        os.remove(path)

# -----------------------------------------------------------------------------
# EXPORT ANALYSES HELPERS
# -----------------------------------------------------------------------------

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from reportlab.lib import colors
from reportlab.lib.units import inch

def _fmt_alloc_value(v):
    # Normalize cell values for the "Allocation" column
    if v is None:
        return ""
    if isinstance(v, (int, float)):
        return f"{v:g}%"
    if isinstance(v, str):
        return v
    if isinstance(v, dict):
        # Prefer the descriptive text if present
        for key in ("description", "desc", "text", "allocation"):
            if key in v and isinstance(v[key], (str, int, float)):
                return _fmt_alloc_value(v[key])
        # Fallback: key: value pairs
        parts = []
        for k, vv in v.items():
            vv_str = _fmt_alloc_value(vv)
            if vv_str:
                parts.append(f"{k.replace('_',' ').title()}: {vv_str}")
        return "; ".join(parts)
    if isinstance(v, list):
        return "; ".join(_fmt_alloc_value(x) for x in v if x is not None)
    return str(v)

def _alloc_table_from_mapping(mapping: dict):
    # Wrapping style for table cells
    wrap = ParagraphStyle(
        name="Wrap9", parent=getSampleStyleSheet()["BodyText"],
        fontSize=9, leading=12, wordWrap="CJK"
    )
    data = [
        [Paragraph("Asset Class", wrap), Paragraph("Allocation", wrap)]
    ]
    for k, v in mapping.items():
        left = Paragraph(k.replace("_", " ").title(), wrap)
        right = Paragraph(_fmt_alloc_value(v), wrap)
        data.append([left, right])
    tbl = Table(
        data, hAlign="LEFT", colWidths=[1.6*inch, 4.8*inch], repeatRows=1
    )
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return tbl

def _parse_json_maybe(text):
    if not text:
        return None
    try:
        cleaned = text.replace("```json", "").replace("```", "").strip()
        import json
        return json.loads(cleaned)
    except Exception:
        return None

def _kv_table_from_dict(d: dict, col1="Metric", col2="Value"):
    data = [[col1, col2]]
    for k, v in d.items():
        data.append([str(k).replace("_", " ").title(), str(v)])
    tbl = Table(data, hAlign="LEFT")
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
    ]))
    return tbl

def _bullet_list(items, styles):
    story = []
    if not items:
        return story
    for it in items:
        story.append(Paragraph(f"• {it}", styles["BodyText"]))
        story.append(Spacer(1, 4))
    return story

def build_analysis_pdf_story(analysis: dict):
    """
    Returns a list of Flowables for ReportLab PDF with all three sections.
    analysis expects keys: query, summary(str JSON), investment_insights(str JSON), risk_assessment(str JSON)
    """
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="H1", parent=styles["Heading1"], alignment=TA_LEFT, spaceAfter=10))
    styles.add(ParagraphStyle(name="H2", parent=styles["Heading2"], alignment=TA_LEFT, spaceAfter=8))
    styles.add(ParagraphStyle(name="Mono", parent=styles["BodyText"], fontName="Courier", fontSize=9, leading=12))

    story = []
    # Title and meta
    story.append(Paragraph("Financial Document Analysis", styles["H1"]))
    story.append(Paragraph(f"Query: {analysis.get('query') or '-'}", styles["BodyText"]))
    story.append(Spacer(1, 10))

    # ---------- Summary ----------
    story.append(Paragraph("Summary", styles["H2"]))
    parsed_summary = _parse_json_maybe(analysis.get("summary"))
    if isinstance(parsed_summary, dict):
        # Executive summary
        exec_sum = parsed_summary.get("executive_summary")
        if exec_sum:
            story.append(Paragraph(exec_sum, styles["BodyText"]))
            story.append(Spacer(1, 8))
        # Key metrics table
        metrics = parsed_summary.get("key_metrics")
        if isinstance(metrics, dict) and metrics:
            story.append(Paragraph("Key Metrics", styles["H2"]))
            story.append(_kv_table_from_dict(metrics))
            story.append(Spacer(1, 8))
        # Growth trends bullets
        growth = parsed_summary.get("growth_trends")
        if isinstance(growth, dict) and growth:
            story.append(Paragraph("Growth Trends", styles["H2"]))
            story.extend(_bullet_list([f"{k.replace('_',' ').title()}: {v}" for k, v in growth.items()], styles))
            story.append(Spacer(1, 8))
        # Risks bullets (from summary block)
        risks = parsed_summary.get("risks")
        if isinstance(risks, list) and risks:
            story.append(Paragraph("Summary Risks", styles["H2"]))
            story.extend(_bullet_list(risks, styles))
            story.append(Spacer(1, 8))
        # Recommendations bullets
        recs = parsed_summary.get("recommendations")
        if isinstance(recs, list) and recs:
            story.append(Paragraph("Recommendations", styles["H2"]))
            story.extend(_bullet_list(recs, styles))
            story.append(Spacer(1, 12))
    else:
        # Fallback to raw text
        raw = analysis.get("summary") or "No summary available."
        story.append(Paragraph(raw, styles["BodyText"]))
        story.append(Spacer(1, 12))

    # ---------- Investment Insights ----------
    story.append(Paragraph("Investment Insights", styles["H2"]))
    parsed_inv = _parse_json_maybe(analysis.get("investment_insights"))
    if isinstance(parsed_inv, dict):
        # Themes
        themes = parsed_inv.get("investment_themes")
        if isinstance(themes, list) and themes:
            story.append(Paragraph("Themes", styles["H2"]))
            story.extend(_bullet_list(themes, styles))
        # Asset allocation table
        alloc = parsed_inv.get("asset_allocation")
        if isinstance(alloc, dict) and alloc:
            story.append(Spacer(1, 6))
            story.append(_alloc_table_from_mapping(alloc))
        # Risk assessment text
        inv_risk = parsed_inv.get("risk_assessment")
        if inv_risk:
            story.append(Spacer(1, 6))
            story.append(Paragraph(f"Risk Assessment: {inv_risk}", styles["BodyText"]))
        # Time horizon and disclaimer
        th = parsed_inv.get("time_horizon")
        if th:
            story.append(Spacer(1, 4))
            story.append(Paragraph(f"Time Horizon: {th}", styles["BodyText"]))
        disc = parsed_inv.get("disclaimer")
        if disc:
            story.append(Spacer(1, 6))
            story.append(Paragraph(f"Disclaimer: {disc}", styles["BodyText"]))
        story.append(Spacer(1, 12))
    else:
        raw = analysis.get("investment_insights")
        story.append(Paragraph(raw or "No investment insights.", styles["BodyText"]))
        story.append(Spacer(1, 12))

    # ---------- Risk Assessment ----------
    story.append(Paragraph("Risk Assessment", styles["H2"]))
    parsed_risk = _parse_json_maybe(analysis.get("risk_assessment"))
    if isinstance(parsed_risk, dict):
        risks = parsed_risk.get("identified_risks") or []
        if risks:
            # wrapping style for table cells
            wrap = ParagraphStyle(
                name="Wrap9",
                parent=styles["BodyText"],
                fontSize=9,
                leading=12,
                wordWrap="CJK"  # forces wrapping even for long words/URLs
            )

            # header
            risk_rows = [
                [
                    Paragraph("Risk", wrap),
                    Paragraph("Severity", wrap),
                    Paragraph("Likelihood", wrap),
                    Paragraph("Strategy", wrap),
                ]
            ]

            # rows
            for r in risks:
                risk_rows.append([
                    Paragraph((r.get("risk") or r.get("risk_name") or ""), wrap),
                    Paragraph(r.get("severity") or "", wrap),
                    Paragraph(r.get("likelihood") or "", wrap),
                    Paragraph(r.get("strategy") or "", wrap),
                ])

            # set reasonable column widths and enable top-alignment + grid
            tbl = Table(
                risk_rows,
                hAlign="LEFT",
                colWidths=[2.2*inch, 0.9*inch, 0.9*inch, 3.0*inch],  # adjust if needed
                repeatRows=1  # repeat header on page breaks
            )
            tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ALIGN", (1, 1), (2, -1), "CENTER"),  # center severity/likelihood
            ]))
            story.append(tbl)
        else:
            story.append(Paragraph("No risks identified.", styles["BodyText"]))
    else:
        raw = analysis.get("risk_assessment")
        story.append(Paragraph(raw or "No risk assessment.", styles["BodyText"]))

    return story

# -----------------------------------------------------------------------------
# ENTRYPOINT
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
