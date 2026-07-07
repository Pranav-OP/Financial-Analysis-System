# 🏛️ Architecture & Flow Guide

This document explains **how the Financial Document Analyzer works end to end**, and
gives short, plain-English explanations of the modern concepts it relies on (RAG,
embeddings, vector databases, LLM agents, async task queues, etc.). Read it top to
bottom to understand the system, or jump to the [Concepts Glossary](#-concepts-glossary)
for definitions.

---

## 1. What the system does

You upload a financial document (a 10-Q, annual report, earnings update…). A crew of
AI agents reads it, extracts the real figures, and produces three things:

1. **A financial summary** — key metrics, growth trends, headline risks.
2. **Investment insights** — themes, suggested asset allocation, time horizon.
3. **A risk assessment** — a risk matrix with severity, likelihood, and mitigations.

You can then browse past analyses, re-run them, and export any result to PDF.

---

## 2. Architecture at a glance

```
                        ┌────────────────────────┐
                        │   React SPA (Vite/MUI) │   finanalyzerUI/
                        │  login · upload · view │
                        └───────────┬────────────┘
                                    │  HTTPS + JWT (Bearer token)
                                    ▼
        ┌───────────────────────────────────────────────────────────┐
        │                 FastAPI  (main.py)                        │
        │  auth · documents · analyses · export · rate limiting     │
        └───┬───────────────┬────────────────────┬──────────────────┘
            │               │                    │
     write file       enqueue job          read/write metadata
            ▼               ▼                    ▼
   ┌──────────────┐  ┌──────────────┐   ┌──────────────────────┐
   │  MongoDB     │  │   Redis      │   │  MongoDB collections │
   │  GridFS      │  │ (broker +    │   │ users · documents ·  │
   │ (file bytes) │  │  rate limit) │   │ jobs · analyses      │
   └──────────────┘  └──────┬───────┘   └──────────────────────┘
                            │ pulls task
                            ▼
        ┌───────────────────────────────────────────────────────────┐
        │            Celery worker  (celery_tasks.py)               │
        │  stages file → runs the CrewAI pipeline → saves result    │
        └───────────────────────────┬───────────────────────────────┘
                                     ▼
        ┌───────────────────────────────────────────────────────────┐
        │        CrewAI multi-agent pipeline  (agents/tasks)        │
        │  verify → analyze → invest → risk   (compile in Python)   │
        │  relevant passages retrieved up front & injected (tools.py)│
        └───────────────────────────┬───────────────────────────────┘
                                     ▼
           Groq/Gemini chat LLM  +  local (or Gemini) embeddings  +  ChromaDB
```

**Why this shape?** The API must answer instantly, but LLM analysis takes 30s–minutes.
So the API only *enqueues* a job and returns a `job_id`; a separate **Celery worker**
does the slow work in the background while the frontend **polls** for completion. This
keeps the UI responsive and lets analysis scale independently of the web server.

---

## 3. End-to-end flow

### A. Upload
1. User picks a file in the React dashboard → `POST /documents/upload`.
2. FastAPI validates the **type and size** server-side (`ALLOWED_UPLOAD_EXTENSIONS`, 50 MB cap).
3. The raw bytes are stored in **MongoDB GridFS** (a way to store large files in Mongo),
   and a metadata record goes into the `documents` collection.

### B. Requesting an analysis
1. User clicks **Analyze** → `POST /analyses/{doc_id}` (rate-limited to 3/min).
2. FastAPI enqueues a **Celery task** onto Redis and inserts a `jobs` record with
   status `queued`. It returns a `job_id` immediately.
3. The frontend starts **polling** `GET /analyses/job/{job_id}` every 10s (bounded to
   ~10 minutes so it can never loop forever).

### C. Background processing (the Celery worker)
1. The worker pulls the job, marks it `processing`.
2. It pulls the file out of GridFS and **stages it** to a local path under `data/`.
3. It **retrieves** the relevant passages (local RAG) and runs `crew.kickoff(...)` with
   them injected — the AI pipeline (section 4).
4. The worker takes each agent's task output and **assembles** the final record in Python
   — `summary`, `investment_insights`, `risk_assessment` — and saves an `analyses` record
   with status `completed`. The job is marked `completed` with the `analysis_id`.

### D. Displaying results
1. On the next poll, the frontend sees `completed`, fetches `GET /analyses/{job_id}`,
   and renders the result as **structured sections** (metric grid, chips, risk table) —
   not raw JSON.
2. Results persist in **Analysis history**; any completed analysis can be **exported to
   PDF** (`/analyses/{id}/export`, built with ReportLab).

---

## 4. The AI pipeline in depth

This is the heart of the system and where the "must-know" concepts live.

### 4.1 The crew (CrewAI)
We use **CrewAI**, a framework for orchestrating multiple LLM **agents**. Instead of one
giant prompt, we split the work across specialists that run **sequentially**, each
feeding the next:

| # | Agent (`agents.py`) | Task (`task.py`) | Context it receives |
|---|---------------------|------------------|---------------------|
| 1 | **Verifier** | Is this really a financial document? | Start of the document (`doc_preview`) |
| 2 | **Financial Analyst** | Extract metrics, trends, risks | Retrieved financial passages (`financial_context`) |
| 3 | **Investment Advisor** | Recommend allocation & themes | The analyst's output (prior task) |
| 4 | **Risk Specialist** | Build a risk matrix | Retrieved risk passages (`risk_context`) |

Each agent has a **role**, **goal**, and **backstory** (its system prompt), and is
instructed to return strict JSON. Outputs flow forward via CrewAI **`context`** — e.g.
the investment advisor sees the analyst's result. A fifth "compiler" step is **not** an
LLM agent: merging the three JSON blobs into one is pure data assembly, so we do it in
**Python** (`celery_tasks.py`) — one fewer LLM call, and no place for the model to mangle
the merge.

> **Retrieve-then-generate (not tool-calling).** Each agent makes **one tool-free LLM
> call** (`max_iter=1`). The passages it needs are retrieved *before* the crew runs and
> injected straight into its prompt (§4.2). This is still genuinely RAG and still
> multi-agent — we only changed *how the context reaches each agent*: injected up front
> rather than fetched via a tool the agent decides to call. Compared to agentic
> tool-calling it means ~half the LLM calls (faster, far fewer tokens for free-tier
> limits) and no ReAct loop for a model to derail into truncated / non-JSON output.

### 4.2 How a document becomes searchable — the RAG pipeline (`tools.py`)

Rather than dumping a whole 50-page PDF into the prompt (expensive, and impossible for
huge filings), we use **Retrieval-Augmented Generation (RAG)**. The steps:

```
PDF ──extract──► clean text ──split──► chunks ──embed──► vectors ──store──► ChromaDB
                                                                              │
"revenue, margins…" ──embed──► query vector ──similarity search──► top-k chunks ──► prompt
```

1. **Extraction** (`_extract_text`): pdfplumber pulls text page-by-page. Cleaning is
   deliberately *light* — we keep numbers and tables (the old code deleted them, which
   is fatal for a *financial* analyzer).
2. **Chunking** (`RecursiveCharacterTextSplitter`): the text is cut into ~700-character
   overlapping pieces. LLMs and embedding models have size limits, and smaller pieces
   make retrieval more precise (and keep prompts small for free-tier token limits).
3. **Embedding** — each chunk is turned into a **vector** (a list of numbers that captures
   its meaning; similar meaning → nearby vectors). By default this runs **locally** with
   ChromaDB's built-in MiniLM model (offline, free, no API/quota). Setting
   `EMBED_PROVIDER=gemini` switches to Google's hosted embeddings instead.
4. **Indexing** (**ChromaDB**): vectors are stored in a **vector database**. Each document
   is indexed **once** and cached by `(path, mtime, size)`, so it is never re-parsed.
5. **Retrieval** (`search_financial_document`, called from `celery_tasks.py` before the
   crew starts): themed queries (financial metrics; risks) are embedded and ChromaDB
   returns the **top-k most similar chunks** (`TOP_K`, default 3). Those passages are
   injected into the relevant agents' prompts.

**Why RAG matters:** it makes analysis *scale to large documents*, *cost less* (you send
a few relevant chunks instead of the whole file), and *stay grounded* (the LLM answers
from retrieved source text, reducing hallucination).

### 4.3 The LLM
All agents talk to their chat model through CrewAI's `LLM` abstraction (LiteLLM under the
hood). The provider is chosen entirely by the `LLM_MODEL` env var — no code change:

- `groq/llama-3.3-70b-versatile` — **Groq**, the recommended default (generous free tier,
  fast).
- `gemini/gemini-2.5-flash` — **Google Gemini** (free tier is only ~5 req/min).

**Rate limits:** free tiers cap requests- or tokens-per-minute (Groq = 12k TPM). We stay
under them three ways: (1) retrieve-then-generate means only ~4 tool-free calls per run
(~7k tokens total); (2) prompts are kept small (top-k=3 retrieval, capped verifier
preview); (3) a light `step_callback` delay (`STEP_DELAY_SECONDS`) spreads calls in time.
`LLM_NUM_RETRIES` adds a best-effort retry on `429`s as a backstop.

---

## 5. Concepts Glossary

Short definitions of the important terms, for quick reference.

- **LLM (Large Language Model):** an AI model (here, a Groq- or Gemini-hosted model) that
  generates text from a prompt. It has no memory of your document unless you put the
  relevant text *in* the prompt.

- **Agent:** an LLM given a role, a goal, and a system prompt (its "backstory"). Here each
  agent makes a single call that returns JSON for its slice of the analysis.

- **Retrieve-then-generate vs. tool-calling:** two ways to give an agent the facts it
  needs. *Tool-calling* lets the model itself request a function (e.g. "search the
  document") mid-reasoning; flexible, but it's an extra round-trip per call and a model
  can derail the loop. *Retrieve-then-generate* (what we use) fetches the relevant
  passages **before** the call and injects them into the prompt — fewer calls, fewer
  tokens, and more reliable structured output. Both are equally "RAG".

- **CrewAI:** a framework for coordinating several agents into a **crew** with a defined
  process (here, **sequential** — one after another, passing context forward).

- **RAG (Retrieval-Augmented Generation):** instead of stuffing an entire document into
  the prompt, you *retrieve* only the passages relevant to the question and give the LLM
  those. "Augmenting" the model's generation with retrieved facts.

- **Embedding:** a numeric vector representing the *meaning* of a piece of text. Texts
  with similar meaning have vectors that are close together.

- **Chunking:** splitting a long document into smaller overlapping pieces so they fit
  size limits and can be retrieved individually. Overlap avoids cutting an idea in half.

- **Vector database (ChromaDB):** a store optimized for finding the vectors nearest to a
  query vector — i.e. **similarity search** / **semantic search** (matching by meaning,
  not exact keywords).

- **top-k retrieval:** returning the *k* most similar chunks (we use k=3).

- **Prompt engineering:** carefully writing an agent's role/goal/instructions (e.g.
  "always return valid JSON with these keys, never fabricate numbers") to get reliable,
  structured output.

- **Async task queue (Celery + Redis):** Celery runs slow jobs in a background worker;
  **Redis** is the message broker that hands jobs from the API to the worker. This keeps
  the API fast and lets heavy work scale separately.

- **Polling:** the frontend repeatedly asks "is it done yet?" until the job completes —
  simple and robust for background jobs (an alternative would be WebSockets).

- **JWT (JSON Web Token):** a signed token the server issues at login; the browser sends
  it on every request as proof of identity. We also carry the user's **roles** in it for
  **role-based access control** (analyst/admin can upload & analyze).

- **Rate limiting:** capping how often an endpoint can be called (3 analyses/min) to
  protect the system and the LLM quota.

- **GridFS:** MongoDB's mechanism for storing files (the raw PDF bytes) inside the
  database, alongside the metadata.

---

## 6. File map

**Backend (Python / FastAPI)**
| File | Responsibility |
|------|----------------|
| `main.py` | FastAPI app: auth, documents, analyses, export, rate limiting, PDF builder |
| `models.py` | Pydantic request/response schemas |
| `agents.py` | LLM setup (Groq/Gemini, env-swappable) + the 4 agent definitions |
| `task.py` | The 5 tasks and how their outputs chain together |
| `tools.py` | PDF extraction + the **RAG** stack (chunk → embed → ChromaDB → search) |
| `celery_app.py` | Celery/Redis configuration |
| `celery_tasks.py` | The background worker: stage file → run crew → save result |
| `.env` / `.env.example` | Secrets & config (never commit real `.env`) |

**Frontend (React / Vite / MUI)** — `finanalyzerUI/src/`
| File | Responsibility |
|------|----------------|
| `main.jsx` | App bootstrap + theme provider + light/dark mode |
| `theme.js` | MUI theme tokens and color-mode context |
| `App.jsx` | Routing, navbar, landing page |
| `pages/Login.jsx`, `Register.jsx` | Auth screens |
| `pages/Dashboard.jsx` | Upload, documents, run/poll analysis, history |
| `components/AnalysisResult.jsx` | Renders results as structured sections/tables |
| `components/ProtectedRoute.jsx` | Guards routes by auth + role |
| `api/axios.js` | Axios client that attaches the JWT automatically |

---

## 7. Data model (MongoDB collections)

- **`users`** — `_id`, email, username, `password_hash` (bcrypt), `roles[]`, `created_at`.
- **`documents`** — `_id`, filename, `gridfs_file_id`, `uploader_id`, `size_bytes`, status.
- **`jobs`** — `job_id` (Celery id), `document_id`, `user_id`, status, `analysis_id`, timestamps.
- **`analyses`** — `_id`, `document_id`, `user_id`, `query`, `summary`,
  `investment_insights`, `risk_assessment`, status, timestamps.
- **GridFS `documents` bucket** — the raw file bytes.

---

## 8. Running it

```bash
# 1. Redis (broker + rate limiter)
sudo service redis-server start        # WSL/Ubuntu

# 2. Backend API
uvicorn main:app --reload              # http://127.0.0.1:8000  (docs at /docs)

# 3. Celery worker (new terminal)
celery -A celery_app worker --loglevel=info --pool=solo

# 4. Frontend (new terminal, in finanalyzerUI/)
npm install && npm run dev             # http://localhost:5173
```

You also need **MongoDB** running and a `.env` file (see `.env.example`). At minimum set
`LLM_MODEL` and its provider key (e.g. `GROQ_API_KEY`). With the default
`EMBED_PROVIDER=local`, **no `GOOGLE_API_KEY` is required** — embeddings run offline.

---

## 9. Key design decisions & trade-offs

- **Async over sync:** analysis is queued to Celery so the API stays responsive and heavy
  work scales independently. Cost: a little polling complexity on the frontend.
- **RAG over prompt-stuffing:** scales to large filings, cheaper, better grounded. Cost:
  an embedding step and a vector store to manage.
- **Multiple specialist agents over one prompt:** clearer responsibilities and easier to
  reason about each step's output. Cost: more LLM calls — mitigated by retrieve-then-
  generate (one tool-free call per agent) and by assembling the final report in Python
  instead of via a fifth LLM "compiler" agent.
- **Retrieve-then-generate over agentic tool-calling:** context is fetched up front and
  injected, so each agent makes a single call. Halves the calls (faster, fits free-tier
  token limits) and removes the ReAct loop that could produce truncated/non-JSON output.
  Trade-off: the agent can't adaptively issue follow-up searches mid-reasoning — fine
  here, since the queries are known ("financial metrics", "risks").
- **Provider-swappable LLM (Groq by default):** the chat model is chosen by `LLM_MODEL`,
  so moving between Groq, Gemini (or later Claude/OpenAI) is a config change, not a
  rewrite. Groq's generous free tier makes it the pragmatic default for demos.
- **Local embeddings by default:** RAG embeddings run offline (ChromaDB MiniLM) so the
  system needs no embedding API key or quota. Swappable to Gemini via `EMBED_PROVIDER`.
  Trade-off: a small local model is slightly less accurate than a large hosted one, but
  more than enough for passage retrieval — and it never rate-limits.
- **In-process ChromaDB:** simple and dependency-free for a single worker. For a
  multi-worker deployment you'd point Chroma (or another vector DB) at shared storage.
