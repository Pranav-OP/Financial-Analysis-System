# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
import os, io, csv, uuid, shutil
from motor.motor_asyncio import AsyncIOMotorGridFSBucket
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient
from typing import Optional, List
import redis.asyncio as aioredis
from dotenv import load_dotenv
from crewai import Crew

from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Depends, Body, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

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
from redis_utils import enqueue_analysis_job, get_cache, set_cache

load_dotenv()

from agents import financial_analyst, verifier, investment_advisor, risk_assessor
from task import analyze_financial_document, investment_analysis, risk_assessment, verification_task

# -----------------------------------------------------------------------------
# CrewAI SETUP
# -----------------------------------------------------------------------------

crew = Crew(
    agents=[financial_analyst, verifier, investment_advisor, risk_assessor],
    tasks=[analyze_financial_document, investment_analysis, risk_assessment, verification_task]
)

# -----------------------------------------------------------------------------
# FastAPI APP SETUP
# -----------------------------------------------------------------------------
app = FastAPI(title="Financial Document Analyzer")

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
redis = aioredis.from_url(REDIS_URI, decode_responses=True)

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

    # file_path = f"data/{file_id}_{file.filename}"
    # os.makedirs("data", exist_ok=True)
    # with open(file_path, "wb") as f:
    #     f.write(content)

    # Save file into GridFS
    gridfs_file_id = await gridfs_bucket.upload_from_stream(file.filename, content)

    doc = {
        "_id": file_id,
        "filename": file.filename,
        "gridfs_file_id": str(gridfs_file_id),
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

    grid_out = await gridfs_bucket.open_download_stream(ObjectId(doc["gridfs_file_id"]))

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

    await gridfs_bucket.delete(ObjectId(doc["gridfs_file_id"]))
    await db.documents.delete_one({"_id": doc_id})
    await db.analyses.delete_many({"document_id": doc_id})  # cleanup analyses
    return {"status": "deleted"}

# ------------------ ANALYSES ------------------

@app.post("/analyses/{doc_id}", response_model=AnalysisResult)
async def request_analysis(
    doc_id: str,
    req: AnalysisRequest = Body(...),
    background_tasks: BackgroundTasks = None,
    current_user=Depends(get_current_user)
):
    """Run analysis immediately without queueing"""

    # Check if user is admin
    is_admin = "admin" in current_user.get("roles", [])
    
    # Check if document exists and belongs to user (Exception : admin)
    query_filter = {"_id": doc_id} if is_admin else {"_id": doc_id, "uploader_id": current_user["_id"]}

    doc = await db.documents.find_one(query_filter)
    if not doc:
        raise HTTPException(404, "Document not found or access denied")

    # Stage file for analysis
    try:
        staged_path = await stage_file_for_analysis(doc_id, doc["filename"], doc["gridfs_file_id"])
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))

    # Kick off CrewAI
    try:
        #print("PRINTING PATH & QUERY BEFORE CREW KICKOFF:", staged_path, req.query)
        result = crew.kickoff(
            inputs={"document_path": staged_path, "query": req.query}
        )

    except Exception as e:
        cleanup_staged_file(staged_path)
        raise HTTPException(500, f"Analysis failed: {str(e)}")

    # Schedule cleanup (background task after response)
    if background_tasks:
        background_tasks.add_task(cleanup_staged_file, staged_path)
    else:
        cleanup_staged_file(staged_path)

    # Save analysis result to DB
    analysis_id = str(uuid.uuid4())
    analysis_doc = {
        "_id": analysis_id,
        "document_id": doc_id,
        "status": "completed",
        "query": req.query,
        "summary": result.output.get("summary") if hasattr(result, "output") else str(result),
        "investment_insights": result.output.get("investment_insights", []) if hasattr(result, "output") else [],
        "risk_assessment": result.output.get("risk_assessment", []) if hasattr(result, "output") else [],
        "raw_excerpt": result.raw if hasattr(result, "raw") else None,
        #"confidence": result.output.get("confidence", 0.0),
        "created_at": datetime.utcnow(),
        "completed_at": datetime.utcnow()
    }
    await db.analyses.insert_one(analysis_doc)

    return AnalysisResult(
        id=analysis_id,
        document_id=doc_id,
        status="completed",
        created_at=analysis_doc["created_at"],
        completed_at=analysis_doc["completed_at"],
        query=analysis_doc["query"],
        summary=analysis_doc["summary"],
        investment_insights=analysis_doc["investment_insights"],
        risk_assessment=analysis_doc["risk_assessment"],
        raw_excerpt=analysis_doc["raw_excerpt"]
    )


@app.get("/analyses/{analysis_id}", response_model=AnalysisResult)
async def get_analysis(analysis_id: str):
    
    # cache = get_cache(f"analysis:{analysis_id}")
    # if cache:
    #     return AnalysisResult(**cache)

    db = mongo_client[DB_NAME]
    analysis = db.analyses.find_one({"_id": ObjectId(analysis_id)})
    if not analysis:
        raise HTTPException(404, "Analysis not found")

    result = AnalysisResult(
        id=str(analysis["_id"]),
        document_id=analysis["document_id"],
        status=analysis["status"],
        created_at=analysis["created_at"],
        completed_at=analysis.get("completed_at"),
        query=analysis.get("query"),
        summary=analysis.get("summary"),
        investment_insights=analysis.get("investment_insights", []),
        risk_assessment=analysis.get("risk_assessment", []),
        raw_excerpt=analysis.get("raw_excerpt")
    )

    # set cache
    # set_cache(f"analysis:{analysis_id}", result.dict())
    return result


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
    return [AnalysisResult(**a, id=a["_id"]) for a in analyses]

# ------------------ EXPORT ------------------

@app.get("/analyses/{analysis_id}/export")
async def export_analysis(analysis_id: str, format: str = "pdf", current_user=Depends(get_current_user)):
    analysis = await db.analyses.find_one({"_id": analysis_id})
    if not analysis:
        raise HTTPException(404, "Analysis not found")

    if format == "pdf":
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer)
        styles = getSampleStyleSheet()
        story = [
            Paragraph(f"Query: {analysis['query']}", styles["Normal"]),
            Paragraph(f"Summary: {analysis['summary']}", styles["BodyText"]),
        ]
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
# ENTRYPOINT
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
