"""Cache reader - retrieve cached vulnerability data."""
import logging
from typing import List, Optional
from sqlalchemy.orm import Session
from models import CveItem, CvssMetric, Description, Reference

logger = logging.getLogger(__name__)


def get_cached_vulnerabilities(
    cpe: str,
    db: Session,
    limit: int = 100,
) -> List[dict]:
    """
    Retrieve vulnerabilities for a CPE from cache.
    
    Args:
        cpe: CPE string to search for
        db: Database session
        limit: Maximum results to return
        
    Returns:
        List of vulnerability dictionaries
    """
    try:
        # Query CVEs with basic info
        query = db.query(CveItem).limit(limit)
        cves = query.all()
        
        results = []
        for cve in cves:
            # Get CVSS metric
            cvss = db.query(CvssMetric).filter(
                CvssMetric.cve_id == cve.cve_id
            ).first()
            
            # Get descriptions
            descriptions = db.query(Description).filter(
                Description.cve_id == cve.cve_id
            ).all()
            
            # Get references
            references = db.query(Reference).filter(
                Reference.cve_id == cve.cve_id
            ).all()
            
            # Build result dict
            result = {
                "cve_id": cve.cve_id,
                "euvd_id": cve.euvd_id,
                "status": cve.vulnStatus,
                "published": cve.published.isoformat() if cve.published else None,
                "modified": cve.lastModified.isoformat() if cve.lastModified else None,
                "description": descriptions[0].value if descriptions else None,
                "references": [ref.url for ref in references],
                "cvss": {
                    "version": cvss.version,
                    "baseScore": float(cvss.exploitabilityScore) if cvss.exploitabilityScore else None,
                    "vector": cvss.cvssData.get("vectorString") if cvss.cvssData else None,
                } if cvss else None,
            }
            results.append(result)
        
        logger.debug(f"Retrieved {len(results)} cached vulnerabilities for {cpe}")
        return results
        
    except Exception as e:
        logger.error(f"Error retrieving cached vulnerabilities: {e}")
        return []


def get_cve_by_id(cve_id: str, db: Session) -> Optional[dict]:
    """
    Get a specific CVE from cache by ID.
    
    Args:
        cve_id: CVE identifier (e.g., "CVE-2021-44228")
        db: Database session
        
    Returns:
        CVE dictionary or None if not found
    """
    try:
        cve = db.query(CveItem).filter(CveItem.cve_id == cve_id).first()
        if not cve:
            return None
        
        # Get related data
        cvss = db.query(CvssMetric).filter(CvssMetric.cve_id == cve_id).first()
        descriptions = db.query(Description).filter(
            Description.cve_id == cve_id
        ).all()
        references = db.query(Reference).filter(
            Reference.cve_id == cve_id
        ).all()
        
        return {
            "cve_id": cve.cve_id,
            "euvd_id": cve.euvd_id,
            "status": cve.vulnStatus,
            "published": cve.published.isoformat() if cve.published else None,
            "modified": cve.lastModified.isoformat() if cve.lastModified else None,
            "description": descriptions[0].value if descriptions else None,
            "references": [ref.url for ref in references],
            "cvss": {
                "version": cvss.version,
                "baseScore": float(cvss.exploitabilityScore) if cvss.exploitabilityScore else None,
                "vector": cvss.cvssData.get("vectorString") if cvss.cvssData else None,
            } if cvss else None,
        }
        
    except Exception as e:
        logger.error(f"Error retrieving CVE {cve_id}: {e}")
        return None
