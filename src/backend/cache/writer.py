import logging
from datetime import datetime
from sqlalchemy.orm import Session
from models import CveItem, CvssMetric, Node, CpeMatch, Description, Reference

logger = logging.getLogger(__name__)


def write_normalized(result: dict, db: Session, original_cpe: str | None = None):
    """
    Writes a normalized vulnerability result (from any source) into the cache.
    """
    for cve_id in result.get("cve_ids", []):
        cve = db.query(CveItem).filter(CveItem.cve_id == cve_id).first()
        if not cve:
            cve = CveItem(
                cve_id=cve_id,
                euvd_id=result.get("euvd_id"),
                published=datetime.utcnow(),
                lastModified=datetime.utcnow(),
                sourceIdentifier=result.get("source", "UNKNOWN"),
                vulnStatus="PUBLISHED",
            )
            db.add(cve)
            db.flush()
        elif result.get("euvd_id") and not cve.euvd_id:
            cve.euvd_id = result["euvd_id"]

        desc = result.get("description", "")
        if desc and not db.query(Description).filter(
            Description.cve_id == cve_id, Description.lang == "en"
        ).first():
            db.add(Description(cve_id=cve_id, lang="en", value=desc))

        for url in result.get("references", []):
            url = url.strip()
            if url and not db.query(Reference).filter(
                Reference.cve_id == cve_id, Reference.url == url
            ).first():
                db.add(Reference(
                    cve_id=cve_id, url=url,
                    source=result.get("source", ""), tags=[]
                ))

        base_score = result.get("base_score")
        if base_score is not None and float(base_score) >= 0:
            if not db.query(CvssMetric).filter(CvssMetric.cve_id == cve_id).first():
                db.add(CvssMetric(
                    cve_id=cve_id,
                    version=str(result.get("base_version") or "3.1"),
                    cvssData={
                        "baseScore":    base_score,
                        "vectorString": result.get("base_vector"),
                        "version":      result.get("base_version", "3.1"),
                    },
                    exploitabilityScore=None,
                    impactScore=None,
                    source=result.get("source", ""),
                ))

        node_obj = db.query(Node).filter(Node.cve_id == cve_id).first()
        if not node_obj:
            node_obj = Node(cve_id=cve_id, operator="OR", negate=False)
            db.add(node_obj)
            db.flush()

        if original_cpe and not db.query(CpeMatch).filter(
            CpeMatch.node_id == node_obj.id,
            CpeMatch.criteria == original_cpe
        ).first():
            db.add(CpeMatch(
                node_id=node_obj.id,
                vulnerable=True,
                criteria=original_cpe,
            ))


def store_unknown_marker(cpe_name: str, db: Session):
    marker_id = f"UNKNOWN:{cpe_name[:200]}"
    if db.query(CveItem).filter(CveItem.cve_id == marker_id).first():
        return
    try:
        cve = CveItem(
            cve_id=marker_id, published=datetime.utcnow(),
            lastModified=datetime.utcnow(),
            sourceIdentifier="UNKNOWN", vulnStatus="NOT_FOUND",
        )
        db.add(cve)
        db.flush()
        node_obj = Node(cve_id=marker_id, operator="OR", negate=False)
        db.add(node_obj)
        db.flush()
        db.add(CpeMatch(node_id=node_obj.id, vulnerable=False, criteria=cpe_name))
        db.commit()
    except Exception:
        db.rollback()