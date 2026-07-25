# 📈 Financial Analysis System

## About the Project
This is a full-stack financial analysis system designed to process complex financial data asynchronously and present the results through a modern, responsive user interface. The system leverages a powerful **Python-based backend (FastAPI)** for computation and a dynamic **React frontend** for visualization with the LLMs.

### 🎥 Video Demo
You can see a live demonstration of the system's functionality here:
[Video Demo on YouTube](https://youtu.be/ycMetWY3AzA)

---

## ✨ Features

* **Multi-Agent AI Analysis:** A **CrewAI** pipeline of specialist agents (verifier → analyst → investment advisor → risk specialist) produces a financial summary, investment insights, and a risk matrix. Their outputs are merged into the final report in **Python** — no extra LLM call.
* **Retrieval-Augmented Generation (RAG):** Documents are chunked, embedded, and indexed in **ChromaDB**. The relevant passages are retrieved up front and injected into each agent's prompt (**retrieve-then-generate**), so every agent makes a single tool-free call. Scales to large filings and keeps answers grounded in the source.
* **Local, free embeddings by default:** Embeddings run **offline** via ChromaDB's built-in MiniLM model — no API key or quota required. Swappable to Gemini embeddings via one env var.
* **Swappable LLM provider:** Chat runs on **Groq** (generous free tier) or **Google Gemini**, selected with a single `LLM_MODEL` env variable — no code changes.
* **Asynchronous Processing:** Utilizes **Celery** to offload long-running analysis tasks, keeping the API responsive; the frontend polls for completion.
* **Modern UI/UX:** Built with **React** and **MaterialUI** — light/dark mode, structured result rendering (metric grids, risk tables), and PDF export.
* **Security:** JWT auth with refresh tokens, role-based access control, rate limiting, and server-side upload validation.
* **Data Persistence:** Stores users, documents (via **GridFS**), jobs, and analyses in a **MongoDB** document database.
* **Scalable Backend:** The API is built with **FastAPI** and served by **Uvicorn**, providing high performance and robust data validation.

---

## 💻 Tech Stack

This project is built using a modern, decoupled architecture:

| Component | Technology | Role |
| :--- | :--- | :--- |
| **Backend Language** | **Python** | Primary development language for backend logic. |
| **API Framework** | **FastAPI** & **Uvicorn** | High-performance API server. |
| **AI Orchestration** | **CrewAI** | Coordinates the multi-agent analysis pipeline. |
| **Chat LLM** | **Groq** (default) / **Google Gemini** | The reasoning engine, selected via `LLM_MODEL`. |
| **Embeddings** | **ChromaDB MiniLM** (local) / **Gemini** | Turn text into vectors for RAG retrieval. |
| **Vector DB** | **ChromaDB** | Stores document embeddings for similarity search. |
| **Database** | **MongoDB** | NoSQL database + **GridFS** for file storage. |
| **Caching/Broker** | **Redis** | Message broker for Celery + rate-limiter backend. |
| **Worker** | **Celery** | Distributed task queue for asynchronous jobs. |
| **Frontend Framework** | **React** & **Vite** | Library/build tool for the user interface. |
| **Styling** | **MaterialUI** | Component library for polished design. |
| **Dependencies** | `requirements.txt` | Defines all necessary Python packages. |

> 📐 For a full walkthrough of the flow and the concepts (RAG, embeddings, agents, async queues, JWT…), see **[ARCHITECTURE.md](./ARCHITECTURE.md)**.

---

## 🐳 Quick start with Docker (recommended)

The whole stack — MongoDB, Redis, the API, the Celery worker, and the frontend — runs
with **one command**. You only need [Docker Desktop](https://www.docker.com/products/docker-desktop/)
installed (no local Python, Node, Redis, or Mongo setup).

```bash
cp .env.example .env      # then add your GROQ_API_KEY (and a JWT_SECRET_KEY)
docker compose up --build
```

Then open **http://localhost:5173**. The API is at **http://localhost:8000** (`/docs` for
Swagger). First build takes a few minutes; the ~80 MB local embedding model downloads
once and is cached in a volume. Stop with `Ctrl+C`; wipe all data with `docker compose down -v`.

> On Windows, Docker Desktop uses the WSL2 backend under the hood — so Redis/Mongo run in
> containers automatically and you never start WSL or those services by hand.

---

## 🛠️ Manual setup (without Docker)

Follow these steps to run each piece yourself.

### Step 1: Clone the Repository

Start by cloning the project repository and navigating into the directory:

```bash
git clone [https://github.com/Pranav-OP/Financial-Analysis-System.git](https://github.com/Pranav-OP/Financial-Analysis-System.git)
cd Financial-Analysis-System
```

### Step 2: Backend Setup (Virtual Environment & Dependencies)

This step covers creating the virtual environment and installing backend requirements.

Create Virtual Environment:
```bash
python -m venv venv
```
Activate Virtual Environment (For Windows):
```bash
venv\Scripts\activate
```

Install Python Dependencies:
```bash
pip install -r requirements.txt
```

### Step 3: Configure Environment Variables

Copy the example file and fill in your values:
```bash
cp .env.example .env          # Windows PowerShell: copy .env.example .env
```

Key settings in `.env`:

| Variable | Purpose | Default |
| :--- | :--- | :--- |
| `LLM_MODEL` | Chat model. Groq: `groq/llama-3.1-8b-instant` (fast, larger daily quota) or `groq/llama-3.3-70b-versatile` (higher quality). Also `gemini/gemini-2.5-flash`. | `gemini/gemini-2.5-flash` |
| `GROQ_API_KEY` | Required if `LLM_MODEL` is a `groq/*` model. Get one at [console.groq.com/keys](https://console.groq.com/keys). | — |
| `GOOGLE_API_KEY` | Required only for Gemini chat **or** `EMBED_PROVIDER=gemini`. | — |
| `EMBED_PROVIDER` | `local` (offline, free — no key needed) or `gemini`. | `local` |
| `STEP_DELAY_SECONDS` | Pause between agent steps to stay under free-tier per-minute token limits. | `7` |
| `JWT_SECRET_KEY` | Secret for signing auth tokens — use a long random string. | — |
| `MONGO_URI`, `REDIS_URI` | Database + broker connections. | localhost |

Also set the frontend API URL in `finanalyzerUI/.env`:
```bash
VITE_API_URL=http://localhost:8000
```

> **Free-tier note:** Groq caps tokens **per minute** *and* **per day**, and the daily
> limit is **per model**. The pipeline keeps runs small (retrieve-then-generate + local
> embeddings) and paces calls via `STEP_DELAY_SECONDS` to respect the per-minute cap. If
> you exhaust one model's daily budget, switch `LLM_MODEL` to another Groq model for a
> fresh bucket — e.g. `groq/llama-3.1-8b-instant` has a much larger daily allowance than
> `groq/llama-3.3-70b-versatile`.

> On the first analysis, `EMBED_PROVIDER=local` downloads a small (~80MB) embedding
> model once and caches it — subsequent runs are instant.

### Step 4: Start Redis Server
The system requires a running Redis instance. If you are using Windows with WSL2/Ubuntu, run the following commands in your WSL terminal:

Start the Redis Service:
```bash
sudo service redis-server start
```

### Step 5: Run Backend API
Ensure your virtual environment is active. This starts the FastAPI application:
```bash
uvicorn main:app --reload
```

The API is now running, typically at http://127.0.0.1:8000 (interactive docs at `/docs`).

### Step 6: Run Celery Worker
Open a NEW terminal window (keep the API terminal running) and activate your virtual environment again. The Celery worker handles background processing:

```bash
celery -A celery_app worker --loglevel=info --pool=solo
```

### Step 7: Run Frontend
You will need Node.js and npm installed. Run these commands from the `finanalyzerUI/` directory (where `package.json` lives):

Install Node Dependencies:
```bash
npm install
```

Start the Frontend Development Server:
```bash
npm run dev
```

The frontend runs on the Vite dev server, typically at http://localhost:5173.
