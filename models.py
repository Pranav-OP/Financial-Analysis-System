from datetime import datetime
from typing import List, Optional, Literal
from pydantic import BaseModel, Field, EmailStr

# ---------- AUTH MODELS ----------

class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)
    role: Literal["user", "analyst", "admin"] = "user"

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: str
    username: str
    role: str
    created_at: datetime

class UserCreate(BaseModel):
    email: EmailStr
    username: str
    password: str
    full_name: Optional[str] = None

class UserOut(BaseModel):
    id: str
    email: EmailStr
    username: str
    full_name: Optional[str]
    roles: List[str]
    created_at: datetime

class Token(BaseModel):
    access_token: str
    token_type: str
    refresh_token: str


# ---------- DOCUMENT MODELS ----------
class DocumentUploadResponse(BaseModel):
    id: str
    filename: str
    status: Literal["uploaded", "analyzing", "completed", "failed"]
    uploaded_at: datetime

class DocumentListResponse(BaseModel):
    id: str
    filename: str
    size: int
    status: str
    uploaded_at: datetime

class DocumentMeta(BaseModel):
    id: str
    filename: str
    status: str
    size_bytes: int
    uploader_id: str
    created_at: datetime

# ---------- ANALYSIS MODELS ----------
class AnalysisRequest(BaseModel):
    query: Optional[str] = "Summarize this document"

class AnalysisResult(BaseModel):
    id: str
    document_id: str
    status: Literal["queued", "running", "completed", "failed"]
    created_at: datetime
    completed_at: Optional[datetime] = None
    query: Optional[str] = None
    summary: Optional[str] = None
    investment_insights: Optional[str] = None
    risk_assessment: Optional[str] = None
    raw_excerpt: Optional[str] = None   