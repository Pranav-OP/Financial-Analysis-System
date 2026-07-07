"""
Document tooling for the Financial Document Analyzer.

Two responsibilities:
  1. Robust text extraction from financial PDFs (numbers/tables PRESERVED).
  2. Retrieval-Augmented Generation: chunk -> embed (Gemini) -> ChromaDB -> similarity search, exposed to the agents as `search_financial_document`.

Design notes
------------
* The old preprocessor deleted every "mostly numeric" line and every ALL-CAPS header. 
  In a *financial* document that throws away exactly the data we need (revenue, margins, EPS, balance-sheet figures, section titles). 
  The new cleaner only normalises whitespace/encoding and de-hyphenates line breaks.
* Each document is extracted and embedded ONCE, then cached by (path, mtime).
  Every agent queries the same vector store instead of re-parsing the PDF.
"""

import os
import re
import hashlib
import logging
import unicodedata
import warnings
from collections import OrderedDict
from typing import List

from dotenv import load_dotenv
from crewai.tools import tool
import pdfplumber

load_dotenv()

# Suppress noisy pdfplumber warnings
warnings.filterwarnings("ignore", category=UserWarning, module="pdfplumber")
logging.getLogger("pdfplumber").setLevel(logging.ERROR)
logger = logging.getLogger("finanalyzer.tools")

# --- Tunables -----------------------------------------------------------------
CHUNK_SIZE = int(os.getenv("CHUNK_SIZE", "700"))
CHUNK_OVERLAP = 100
TOP_K = int(os.getenv("TOP_K", "3"))
# Embeddings provider:
#   "local"  -> ChromaDB's built-in MiniLM (offline, free, no API/quota)   [default]
#   "gemini" -> Google embeddings (needs GOOGLE_API_KEY, uses free-tier quota)
EMBED_PROVIDER = os.getenv("EMBED_PROVIDER", "local").lower()
EMBED_MODEL = os.getenv("EMBED_MODEL", "models/gemini-embedding-001")  # only for gemini
# Cap the full-text tool (used by the verifier) — kept small to conserve chat tokens.
MAX_FULLTEXT_CHARS = int(os.getenv("MAX_FULLTEXT_CHARS", "4000"))


# -----------------------------------------------------------------------------
# Text extraction + light cleaning (numbers are KEPT)
# -----------------------------------------------------------------------------
def preprocess_financial_text(raw: str) -> str:
    """Normalise text without discarding financial figures or table rows."""
    # 1) Unicode normalise + strip BOM / normalise line endings
    txt = unicodedata.normalize("NFKC", raw)
    txt = txt.replace("\r\n", "\n").replace("\r", "\n").replace("﻿", "")

    # 2) De-hyphenate words split across a line break: "reve-\nnue" -> "revenue"
    txt = re.sub(r"(\w)-\n(\w)", r"\1\2", txt)

    # 3) Collapse runs of spaces/tabs, trim trailing spaces per line
    txt = re.sub(r"[ \t]{2,}", " ", txt)
    lines = [ln.rstrip() for ln in txt.split("\n")]

    # 4) Drop blank lines and de-duplicate consecutive/repeated lines
    #    (headers/footers repeat every page) while preserving order.
    lines = [ln for ln in lines if ln.strip()]
    deduped = list(OrderedDict((ln, None) for ln in lines).keys())

    return "\n".join(deduped).strip()


def _extract_text(path: str) -> str:
    """Extract raw text from a PDF (or plain-text file) and clean it."""
    path = os.path.normpath(path)
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")

    chunks: List[str] = []
    if path.lower().endswith(".pdf"):
        try:
            with pdfplumber.open(path) as pdf:
                for page_num, page in enumerate(pdf.pages, 1):
                    try:
                        text = page.extract_text() or ""
                        if text:
                            chunks.append(text)
                    except Exception as e:  # keep going on a bad page
                        logger.warning("Page %s extraction failed: %s", page_num, e)
                        continue
        except Exception as e:
            raise RuntimeError(f"Failed to open PDF file: {e}") from e
    else:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            chunks.append(f.read())

    raw_text = "\n".join(chunks)
    if not raw_text.strip():
        raise RuntimeError("No text could be extracted from the document")

    cleaned = preprocess_financial_text(raw_text)
    logger.info("Extracted %d chars -> %d cleaned chars", len(raw_text), len(cleaned))
    return cleaned


# -----------------------------------------------------------------------------
# RAG index (lazy-initialised so importing this module never needs a key)
# -----------------------------------------------------------------------------
_gemini_embeddings = None   # langchain GoogleGenerativeAIEmbeddings (gemini provider)
_local_ef = None            # chromadb DefaultEmbeddingFunction (local provider)
_splitter = None            # RecursiveCharacterTextSplitter
_chroma_client = None       # in-process chromadb client
_index_cache: dict = {}     # cache_key -> collection_name


def _get_gemini_embeddings():
    global _gemini_embeddings
    if _gemini_embeddings is None:
        from langchain_google_genai import GoogleGenerativeAIEmbeddings
        _gemini_embeddings = GoogleGenerativeAIEmbeddings(model=EMBED_MODEL)
    return _gemini_embeddings


def _get_local_ef():
    """Lazy-load ChromaDB's built-in MiniLM ONNX model (downloads once, ~80MB)."""
    global _local_ef
    if _local_ef is None:
        from chromadb.utils import embedding_functions
        _local_ef = embedding_functions.DefaultEmbeddingFunction()
    return _local_ef


def _to_floats(vec):
    """Coerce a (possibly numpy) vector to a plain list of Python floats."""
    if hasattr(vec, "tolist"):
        return vec.tolist()
    return [float(x) for x in vec]


def _embed_documents(texts):
    if EMBED_PROVIDER == "local":
        return [_to_floats(v) for v in _get_local_ef()(texts)]
    return _get_gemini_embeddings().embed_documents(texts)


def _embed_query(text):
    if EMBED_PROVIDER == "local":
        return _to_floats(_get_local_ef()([text])[0])
    return _get_gemini_embeddings().embed_query(text)


def _get_splitter():
    global _splitter
    if _splitter is None:
        from langchain_text_splitters import RecursiveCharacterTextSplitter
        _splitter = RecursiveCharacterTextSplitter(
            chunk_size=CHUNK_SIZE,
            chunk_overlap=CHUNK_OVERLAP,
            separators=["\n\n", "\n", ". ", " ", ""],
        )
    return _splitter


def _get_chroma():
    global _chroma_client
    if _chroma_client is None:
        import chromadb
        # In-process, ephemeral store — rebuilt per worker. Enough for retrieval.
        _chroma_client = chromadb.Client()
    return _chroma_client


def _cache_key(path: str) -> str:
    """Stable key for a document's current bytes (path + mtime + size)."""
    st = os.stat(path)
    raw = f"{os.path.abspath(path)}::{int(st.st_mtime)}::{st.st_size}"
    return hashlib.sha1(raw.encode()).hexdigest()[:24]


def _get_or_build_index(path: str) -> str:
    """Return the Chroma collection name for `path`, building it on first use."""
    path = os.path.normpath(path)
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")

    key = _cache_key(path)
    if key in _index_cache:
        return _index_cache[key]

    text = _extract_text(path)
    chunks = _get_splitter().split_text(text)
    if not chunks:
        raise RuntimeError("Document produced no chunks to index")

    embeddings = _embed_documents(chunks)

    collection_name = f"doc_{key}"
    client = _get_chroma()
    # Fresh collection (drop any stale one with the same name)
    try:
        client.delete_collection(collection_name)
    except Exception:
        pass
    collection = client.create_collection(collection_name)
    collection.add(
        ids=[f"{key}_{i}" for i in range(len(chunks))],
        documents=chunks,
        embeddings=embeddings,
    )

    _index_cache[key] = collection_name
    logger.info("Indexed %s into %d chunks", os.path.basename(path), len(chunks))
    return collection_name


# -----------------------------------------------------------------------------
# Tools exposed to the agents
# -----------------------------------------------------------------------------
@tool("read_financial_document")
def read_financial_document(document_path: str) -> str:
    """Read and return the full cleaned text of a financial document.

    Use this to get an overview of a document (e.g. to verify its type).
    Numbers and tables are preserved. Very large documents are truncated to a
    safe length — use `search_financial_document` for targeted retrieval.

    Args:
        document_path: Filesystem path to the PDF/text file.
    """
    text = _extract_text(document_path)
    if len(text) > MAX_FULLTEXT_CHARS:
        text = text[:MAX_FULLTEXT_CHARS] + "\n\n[... truncated; use search_financial_document for details ...]"
    return text


@tool("search_financial_document")
def search_financial_document(document_path: str, query: str) -> str:
    """Retrieve the passages of a financial document most relevant to a query.

    Runs vector similarity search (Gemini embeddings + ChromaDB) over the
    document and returns the top matching chunks. Prefer this over reading the
    whole document — it is faster, cheaper, and scales to very large filings.

    Args:
        document_path: Filesystem path to the PDF/text file.
        query: A focused question, e.g. "revenue and gross margin trend".
    """
    try:
        collection_name = _get_or_build_index(document_path)
        collection = _get_chroma().get_collection(collection_name)
        q_emb = _embed_query(query)
        res = collection.query(query_embeddings=[q_emb], n_results=TOP_K)
        docs = (res.get("documents") or [[]])[0]
        if not docs:
            return "No relevant passages found in the document."
        return "\n\n---\n\n".join(docs)
    except Exception as e:
        # Fail soft: agents should still be able to fall back to full text.
        logger.exception("search_financial_document failed")
        return f"Retrieval error: {type(e).__name__}: {e}"
