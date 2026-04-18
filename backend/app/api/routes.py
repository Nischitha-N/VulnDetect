"""
FastAPI API routes for vulnerability scanning.
"""

from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse

from app.core.file_scanner import scan_single_file, scan_zip_folder
from app.core.database import save_scan, get_scan, list_scans
from app.schemas.models import ScanResponse

router = APIRouter(prefix="/api/v1", tags=["scanner"])

ALLOWED_EXTENSIONS = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".zip"}


@router.post("/scan", response_model=ScanResponse)
async def scan_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
):
    """
    Upload a C/C++ source file or a .zip folder for vulnerability analysis.
    Returns structured results with risk scores and fix suggestions.
    """
    import os
    ext = os.path.splitext(file.filename)[1].lower()

    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Upload .c, .cpp, .h, or .zip files.",
        )

    content = await file.read()
    if len(content) > 50 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (max 50 MB).")

    if ext == ".zip":
        result = await scan_zip_folder(content)
    else:
        result = await scan_single_file(file.filename, content)

    background_tasks.add_task(save_scan, result)
    return result


@router.get("/scan/{scan_id}")
async def get_scan_result(scan_id: str):
    """Retrieve a previously stored scan result by ID."""
    doc = await get_scan(scan_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return doc


@router.get("/scans")
async def list_recent_scans(limit: int = 20):
    """List recent scans (summaries only)."""
    scans = await list_scans(limit=min(limit, 100))
    return {"scans": scans}


@router.get("/health")
async def health():
    return {"status": "ok", "service": "vuln-detector"}
