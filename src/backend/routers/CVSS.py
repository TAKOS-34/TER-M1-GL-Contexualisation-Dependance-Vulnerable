"""CVSS metric endpoints - deprecated but kept for backward compatibility."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from core.logger import get_logger
from models import get_db, CveItem

logger = get_logger(__name__)
router = APIRouter(prefix="/api/cvss", tags=["CVSS"])


@router.get("/{cve_id}")
async def get_cvss_metrics(cve_id: str, db: Session = Depends(get_db)):
    """Get CVSS metrics for a CVE (backward compatibility endpoint)."""
    cve = db.query(CveItem).filter(CveItem.cve_id == cve_id).first()
    
    if not cve:
        return {"error": f"CVE {cve_id} not found"}
    
    if not cve.cvss_metrics:
        return {"error": f"No CVSS metrics found for {cve_id}"}
    
    metrics = []
    for m in cve.cvss_metrics:
        metrics.append({
            "version": m.version,
            "cvssData": m.cvssData,
            "exploitabilityScore": float(m.exploitabilityScore) if m.exploitabilityScore else None,
            "impactScore": float(m.impactScore) if m.impactScore else None,
            "source": m.source,
            "type": m.type,
        })
    
    return {
        "cve_id": cve_id,
        "metrics": metrics,
    }
