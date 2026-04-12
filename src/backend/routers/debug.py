from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from models import get_db, CveItem
from sources.euvd import EUVDSource
from matching.version import item_affects_version
from matching.cpe import parse_cpe, resolve_euvd_names

router = APIRouter(prefix="/debug", tags=["debug"])
_euvd = EUVDSource()


@router.get("/euvd-product")
async def debug_euvd_product(vendor: str, product: str, version: str = ""):
    items = await _euvd.search_by_product(vendor, product)
    return {
        "vendor": vendor, "product": product, "total": len(items),
        "items": [
            {
                "id":        i.get("id"),
                "aliases":   i.get("aliases", "").split("\n")[:3],
                "baseScore": i.get("baseScore"),
                "products":  i.get("enisaIdProduct", []),
                "affected":  item_affects_version(i, version) if version else None,
            }
            for i in items
        ]
    }


@router.get("/trace-cpe")
async def debug_trace_cpe(cpe: str):
    parsed          = parse_cpe(cpe)
    target_version  = parsed["version"]
    name_candidates = resolve_euvd_names(cpe)
    trace           = []

    for vendor, product in name_candidates:
        items = await _euvd.search_by_product(vendor, product, size=20)
        trace.append({
            "vendor": vendor, "product": product,
            "results_count": len(items),
            "items": [
                {
                    "id":        i.get("id"),
                    "aliases":   i.get("aliases", "").split("\n")[:2],
                    "baseScore": i.get("baseScore"),
                    "products":  i.get("enisaIdProduct", []),
                    "affected":  item_affects_version(
                        i, target_version, product_hint=parsed["product"]
                    ),
                }
                for i in items
            ]
        })
        if items:
            break

    return {"cpe": cpe, "target_version": target_version,
            "name_candidates": name_candidates, "trace": trace}


@router.get("/euvd-by-cve")
async def debug_euvd_by_cve(cve_id: str, db: Session = Depends(get_db)):
    cve_item    = db.query(CveItem).filter(CveItem.cve_id == cve_id).first()
    euvd_id     = cve_item.euvd_id if cve_item else None
    euvd_record = await _euvd.fetch_by_id(euvd_id) if euvd_id else None
    return {
        "cve_id":    cve_id,
        "euvd_id":   euvd_id,
        "found":     euvd_record is not None,
        "products":  euvd_record.get("enisaIdProduct", []) if euvd_record else [],
        "baseScore": euvd_record.get("baseScore") if euvd_record else None,
    }