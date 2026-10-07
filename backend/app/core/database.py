"""
MongoDB async database layer using Motor with in-memory fallback.
"""

from typing import Optional, Dict, Any, List
from app.core.config import settings
from app.schemas.models import ScanResponse

_in_memory_scans: Dict[str, Dict[str, Any]] = {}

try:
    from motor.motor_asyncio import AsyncIOMotorClient
    _has_motor = True
except ImportError:
    _has_motor = False

_client = None


def get_client():
    global _client
    if not _has_motor:
        return None
    if _client is None:
        _client = AsyncIOMotorClient(settings.MONGO_URI, serverSelectionTimeoutMS=3000)
    return _client



def get_db():
    return get_client()[settings.MONGO_DB]


async def save_scan(scan: ScanResponse) -> str:
    """Persist scan results to MongoDB or in-memory fallback. Returns scan_id."""
    doc = {
        "scan_id": scan.scan_id,
        "timestamp": scan.timestamp,
        "results": [r.model_dump() for r in scan.results],
        "summary": scan.summary.model_dump(),
    }
    _in_memory_scans[scan.scan_id] = doc
    if _has_motor:
        try:
            db = get_db()
            if db is not None:
                await db.scans.insert_one(doc)
        except Exception as e:
            pass
    return scan.scan_id


async def get_scan(scan_id: str) -> Optional[dict]:
    if _has_motor:
        try:
            db = get_db()
            if db is not None:
                doc = await db.scans.find_one({"scan_id": scan_id}, {"_id": 0})
                if doc:
                    return doc
        except Exception:
            pass
    return _in_memory_scans.get(scan_id)


async def list_scans(limit: int = 20) -> List[dict]:
    if _has_motor:
        try:
            db = get_db()
            if db is not None:
                cursor = db.scans.find({}, {"_id": 0, "results": 0}).sort("timestamp", -1).limit(limit)
                return await cursor.to_list(length=limit)
        except Exception:
            pass
    return list(_in_memory_scans.values())[-limit:]

