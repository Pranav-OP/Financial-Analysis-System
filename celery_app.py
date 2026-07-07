from celery import Celery
import os
from dotenv import load_dotenv

load_dotenv()

# Redis URL for Celery broker
REDIS_URL = os.getenv("REDIS_URI", "redis://localhost:6379")

# Create Celery instance
app = Celery(
    "financial_analyzer",
    broker=REDIS_URL,
    include=["celery_tasks"]  # Include worker tasks
)

# Simplified Celery configuration
app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30 * 60,  # 30 minutes
    task_soft_time_limit=25 * 60,  # 25 minutes
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    # Remove result backend to avoid serialization issues
    result_backend=None, # Explicitly disables storing task results in backend (Redis)
    # Disable result persistence
    task_ignore_result=True,
    result_expires=3600,
)

# commands to run the project
# npm run dev
# uvicorn main:app --reload
# celery -A celery_app worker --loglevel=info --pool=solo
# sudo service redis-server start

# See .env.example for the required environment variables (backend + frontend).
# Never commit real API keys or secrets — keep them only in your local .env.