import redis, os, json

redis_client = redis.Redis(host="localhost", port=6379, db=0, decode_responses=True)

def enqueue_analysis_job(analysis_id: str, doc_id: str, query: str):
    job = {"analysis_id": analysis_id, "doc_id": doc_id, "query": query}
    redis_client.rpush("analysis_jobs", json.dumps(job))

def dequeue_analysis_job():
    job = redis_client.lpop("analysis_jobs")
    return json.loads(job) if job else None

def set_cache(key: str, value: dict, ttl: int = 300):
    redis_client.setex(key, ttl, json.dumps(value))

def get_cache(key: str):
    data = redis_client.get(key)
    return json.loads(data) if data else None
