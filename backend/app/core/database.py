"""
MongoDB async database layer using Motor.
"""

from motor.motor_asyncio import AsyncIOMotorClient
from app.core.config import settings
from app.schemas.models import ScanResponse

_client: AsyncIOMotorClient = None


def get_client() -> AsyncIOMotorClient:
    global _client
    if _client is None:
        _client = AsyncIOMotorClient(settings.MONGO_URI, serverSelectionTimeoutMS=3000)
    return _client


def get_db():
    return get_client()[settings.MONGO_DB]


async def save_scan(scan: ScanResponse) -> str:
    """Persist scan results to MongoDB. Returns scan_id."""
    try:
        db = get_db()
        doc = {
            "scan_id": scan.scan_id,
            "timestamp": scan.timestamp,
            "results": [r.model_dump() for r in scan.results],
            "summary": scan.summary.model_dump(),
        }
        await db.scans.insert_one(doc)
        return scan.scan_id
    except Exception as e:
        # Non-fatal: log and continue without persistence
        print(f"[DB] Save failed (non-fatal): {e}")
        return scan.scan_id


async def get_scan(scan_id: str) -> dict | None:
    try:
        db = get_db()
        doc = await db.scans.find_one({"scan_id": scan_id}, {"_id": 0})
        return doc
    except Exception:
        return None


async def list_scans(limit: int = 20) -> list:
    try:
        db = get_db()
        cursor = db.scans.find({}, {"_id": 0, "results": 0}).sort("timestamp", -1).limit(limit)
        return await cursor.to_list(length=limit)
    except Exception:
        return []
