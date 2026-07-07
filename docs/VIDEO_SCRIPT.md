# 🎬 Video Walkthrough Script — Financial Document Analyzer

A spoken-narration script for the demo video. Each section has **[SHOW]** cues (what to
put on screen) and **"spoken"** lines you can read aloud or paraphrase. Target length
~8–12 minutes. Speak naturally — these are talking points, not a word-for-word cage.

> Tip: kick off one analysis *before* you start recording the "how it works" part, so the
> ~30–60s of processing overlaps with your code explanation and there's no dead air.

---

## 0. Cold open (15–20s)

**[SHOW]** The dashboard with a document already uploaded.

> "This is a Financial Document Analyzer — you upload a company's financial report, like
> Tesla's quarterly update, and a team of AI agents reads it and produces three things: a
> financial summary, investment insights, and a risk assessment. Let me show you it
> working, and then walk through how it's built and the decisions behind it."

---

## 1. The live demo (60–90s)

**[SHOW]** Log in → upload the Tesla PDF → set a query → click **Analyze**.

> "I'll log in — authentication is JWT-based with refresh tokens. I upload a PDF; the file
> is validated on the server and stored in MongoDB. Now I type an analysis query — this
> steers what the agents focus on — and hit Analyze."

**[SHOW]** The "Running" chip / progress; kick this off, then move to the code sections
while it processes.

> "Notice the request comes back **instantly** with a job ID, and the UI starts polling
> for the result. The actual analysis is happening in the background — I'll explain why
> that matters in a second. While it runs, let me walk through the architecture."

---

## 2. Tech stack (60–90s)

**[SHOW]** `README.md` tech-stack table, or `ARCHITECTURE.md` diagram.

> "The stack is a decoupled full-stack app:
> - **Frontend** is **React** with **Material UI** — light/dark mode, and it renders the
>   results as structured tables and cards, not raw JSON.
> - **Backend API** is **FastAPI**, a modern high-performance Python framework, served by
>   Uvicorn.
> - The AI part is orchestrated with **CrewAI**, which coordinates multiple LLM agents.
> - The language model runs on **Groq** — it hosts open models like Llama and is extremely
>   fast, with a usable free tier. The provider is swappable with one env variable.
> - For retrieval we use **ChromaDB**, a vector database, with a **local** embedding model
>   so that part is completely free and offline.
> - **MongoDB** stores users, documents, jobs, and analysis results. Files themselves go
>   into **GridFS**, Mongo's system for storing large binaries.
> - And **Redis** + **Celery** handle background processing — that's the piece that keeps
>   the API fast."

---

## 3. Why background processing? (Celery + Redis) (45–60s)

**[SHOW]** `celery_tasks.py`, and the `POST /analyses/{doc_id}` endpoint in `main.py`.

> "Here's a key design decision. Running the AI pipeline takes tens of seconds to a couple
> of minutes. If the API did that work *inside* the HTTP request, the request would hang,
> the browser might time out, and the server couldn't handle other users.
>
> So instead: when you click Analyze, the API just **enqueues a job** onto **Redis** and
> immediately returns a job ID. A separate process — the **Celery worker** — picks up that
> job and does the slow work in the background. **Celery** is a distributed task queue;
> **Redis** is the message broker that hands jobs from the API to the worker.
>
> The frontend then **polls** a status endpoint every few seconds until the job is done.
> This keeps the UI responsive and lets the heavy AI work scale independently of the web
> server."

---

## 4. The multi-agent pipeline (CrewAI) (60–90s)

**[SHOW]** `agents.py` and `task.py`, and the celery worker terminal showing the agents
running one after another.

> "The analysis isn't one giant prompt — it's a **crew of specialist agents** that run in
> sequence, using CrewAI:
> 1. A **Verifier** checks the file really is a financial document.
> 2. A **Financial Analyst** extracts the metrics, growth trends, and headline risks.
> 3. An **Investment Advisor** turns that into themes and an asset-allocation view.
> 4. A **Risk Specialist** builds a risk matrix with severity and likelihood.
>
> Each agent has a **role**, a **goal**, and a **backstory** — that's its system prompt —
> and each is told to return strict JSON. Outputs flow forward: the investment advisor
> sees the analyst's results.
>
> One decision worth calling out: there's **no fifth 'compiler' agent**. Merging the three
> JSON outputs into one is pure data assembly, so we do it in **Python** in the worker.
> That saves an LLM call and removes a place where the model could mangle the merge."

---

## 5. RAG — how we give the agents context (90–120s)

**[SHOW]** `tools.py` — the extraction, chunking, embedding, and search functions; then
the retrieval calls in `celery_tasks.py`.

> "Now the most important concept: how do the agents actually *know* what's in a 50-page
> PDF? A language model has no memory of your document — you have to put the relevant text
> into the prompt. But you can't just dump the whole PDF in: it's expensive, and huge
> filings won't even fit in the context window.
>
> So we use **RAG — Retrieval-Augmented Generation**. The idea is to retrieve *only* the
> passages relevant to each question and give the model those. Here's the pipeline:
>
> - First we **extract** the text from the PDF. Importantly, we keep the numbers and
>   tables — an earlier version stripped them out, which is fatal for a *financial*
>   analyzer.
> - Then we **chunk** it into small overlapping pieces.
> - Each chunk is turned into an **embedding** — a vector of numbers that captures its
>   *meaning*. Text with similar meaning ends up close together in vector space.
> - Those vectors go into **ChromaDB**, our vector database.
> - When we need context, we embed the *question* — say 'revenue and margins' — and ask
>   ChromaDB for the **most similar chunks**. That's **semantic search**: matching by
>   meaning, not keywords.
>
> And a nice detail — the embedding model runs **locally**, on-device, so this whole step
> is free and needs no API key."

---

## 6. Design decision: how context reaches the agents (60–90s)

**[SHOW]** `task.py` prompts with the injected `{financial_context}` / `{risk_context}`,
and the retrieval calls at the top of the task in `celery_tasks.py`.

> "There are two ways to combine RAG with agents, and which one you pick really matters.
>
> The first is **agentic tool-calling**: you give the agent a 'search' tool and let it
> *decide* when to call it mid-reasoning. It's flexible — but it's an extra round-trip per
> agent, it burns more tokens, and the model can get stuck in its reasoning loop and spit
> out truncated or broken output. I actually hit exactly that.
>
> The second — what we use — is **retrieve-then-generate**: we run the retrieval *up front*
> in the worker, then **inject** those passages straight into each agent's prompt. So every
> agent makes **one clean call**, no tools.
>
> It's still genuinely RAG, and still multi-agent — I only changed *how the context reaches
> each agent*: injected up front, rather than fetched via a tool. The payoff was big: about
> half the LLM calls, far fewer tokens — which matters a lot on a free tier — and much more
> reliable JSON output."

---

## 7. Design decision: free-tier rate limits (45–60s)

**[SHOW]** `.env` (`LLM_MODEL`, `EMBED_PROVIDER`), and the `step_callback` pacing in
`main.py`.

> "Because we're on a free tier, the model caps how many tokens you can use per minute and
> per day. We handle that three ways:
> - retrieve-then-generate keeps the whole run to just a handful of small calls;
> - embeddings are local, so they never touch the API quota at all;
> - and we pace the calls slightly so a burst doesn't trip the per-minute limit.
>
> The model itself is swappable with one line — I can point it at a bigger model for
> quality or a lighter one for speed and higher daily limits, with no code change."

---

## 8. Back to the result (45–60s)

**[SHOW]** The completed analysis in the UI — the Financial Summary section, the metric
grid, the investment insights, and the risk table with color-coded severity. Then click
**Export PDF**.

> "And here's the finished analysis. The summary is rendered as readable sections — key
> metrics, growth trends — the investment view shows themes and a suggested allocation, and
> the risk assessment is a proper table with severity and likelihood color-coded. Every
> figure here — revenue down 12%, operating income down 42% — is pulled straight from the
> document, not made up.
>
> Results are saved, so I can revisit any past analysis from the history, and **export** it
> to PDF with one click."

---

## 9. Wrap-up (20–30s)

**[SHOW]** The dashboard, or the `ARCHITECTURE.md` diagram.

> "So to recap: a FastAPI backend with JWT auth and role-based access; heavy AI work
> offloaded to Celery so the API stays responsive; a CrewAI multi-agent pipeline; RAG with
> a local vector database to keep answers grounded and cheap; and a React dashboard that
> turns it all into something you can actually read and export. Thanks for watching."

---

## Quick reference — one-liners if asked

- **What is Celery?** A background task queue — it runs slow jobs outside the web request
  so the API stays fast. Redis is the broker that passes jobs to it.
- **What is RAG?** Retrieval-Augmented Generation — fetch only the relevant passages and
  feed them to the LLM, instead of the whole document.
- **What is an embedding?** A list of numbers representing a piece of text's meaning;
  similar meanings sit close together, which lets us find relevant chunks.
- **What is a vector database?** (ChromaDB) A store built for finding the vectors most
  similar to a query vector — i.e. semantic search.
- **Why CrewAI / multiple agents?** Splitting the work across focused specialists gives
  clearer, more reliable outputs than one giant prompt.
- **Why retrieve-then-generate instead of a search tool?** Fewer LLM calls, fewer tokens,
  and more reliable structured output — the context is injected up front.
- **Why Groq?** Very fast inference on open models with a usable free tier; provider is
  swappable via one env variable.
- **Why local embeddings?** Free, offline, no quota — the retrieval step costs nothing.
- **Why MongoDB + GridFS?** Flexible document store for users/analyses; GridFS holds the
  uploaded files.
