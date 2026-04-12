"""
Pradeo Vulnerability Aggregator - FastAPI Application
Main entry point for the REST API with professional architecture.
"""
import logging
from contextlib import asynccontextmanager
from typing import List

from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from core.config import settings, make_client, EUVD_CSV_DUMP, EUVD_LAST, EUVD_EXPLOITED, EUVD_CRITICAL
from core.logger import get_logger
from models import init_db, get_db, CveItem
from models.schemas import (
    CPEQueryRequest, CPEBulkQueryRequest, ForceSyncRequest,
    SyncStatusResponse, HealthStatusResponse, CveQueryResponse
)
from services.aggregator import Aggregator
from services.vulnerability_service import VulnerabilityService

# For backward compatibility with old routers
try:
    from routers import CVSS, Fix_commits, debug
except ImportError:
    CVSS = Fix_commits = debug = None

# Initialize logging and services
logger = get_logger(__name__)
aggregator = Aggregator()


# ============================================================================
# Startup/Shutdown
# ============================================================================

async def _startup():
    """Initialize database on startup."""
    logger.info("✓ Starting Pradeo Vulnerability Aggregator v%s", settings.app.version)
    init_db()
    logger.info("✓ Database initialized")
    
    # Check sources health
    health = await aggregator.health_check()
    healthy_count = sum(1 for s in health.values() if s["healthy"])
    logger.info(f"✓ Sources health: {healthy_count}/{len(health)} healthy")


async def _shutdown():
    """Cleanup on shutdown."""
    logger.info("🛑 Shutting down Pradeo Vulnerability Aggregator")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan."""
    await _startup()
    yield
    await _shutdown()


# ============================================================================
# FastAPI Application
# ============================================================================

app = FastAPI(
    title=settings.app.title,
    version=settings.app.version,
    description="Multi-source vulnerability aggregator with EUVD, OSV, and NVD support",
    lifespan=lifespan,
)

# Include old routers for backward compatibility
if CVSS:
    app.include_router(CVSS.router)
if Fix_commits:
    app.include_router(Fix_commits.router)
if debug:
    app.include_router(debug.router)


# ============================================================================
# Health & Status Endpoints
# ============================================================================

@app.get("/", tags=["Health"])
async def root():
    """Root endpoint."""
    return {
        "status": "ok",
        "title": settings.app.title,
        "version": settings.app.version,
        "message": "Vulnerability aggregator service"
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """Check health of all vulnerability sources."""
    sources_status = await aggregator.health_check()
    healthy_count = sum(1 for s in sources_status.values() if s["healthy"])
    
    return {
        "status": "healthy" if healthy_count == len(sources_status) else "degraded",
        "sources": sources_status,
    }


@app.get("/sync/status", response_model=SyncStatusResponse, tags=["Sync"])
async def sync_status(db: Session = Depends(get_db)):
    """Get database synchronization status."""
    stats = VulnerabilityService.get_sync_status(db)
    return {
        "status": "synced" if stats["total_cves"] > 0 else "empty",
        **stats,
        "last_update": None,
    }


# ============================================================================
# Query Endpoints
# ============================================================================

@app.post("/query", response_model=CveQueryResponse, tags=["Query"])
async def query_cpe(request: CPEQueryRequest, db: Session = Depends(get_db)):
    """Query vulnerabilities for a single CPE."""
    try:
        # Check cache first
        cves = VulnerabilityService.search_by_cpe(request.cpe, db)
        
        if not cves:
            # Not in cache, fetch from sources
            logger.info(f"CPE {request.cpe} not in cache, querying sources...")
            found, count = await aggregator.fetch_and_sync(request.cpe, db)
            cves = VulnerabilityService.search_by_cpe(request.cpe, db) if found else []
        
        vulnerabilities = [
            {
                "cve_id": cve.cve_id,
                "euvd_id": cve.euvd_id,
                "status": cve.vulnStatus,
                "published": cve.published,
                "base_score": max(
                    (m.cvssData.get("baseScore", 0) for m in cve.cvss_metrics
                     if m.cvssData),
                    default=None
                ),
            }
            for cve in cves
        ]
        
        return {
            "found": len(vulnerabilities) > 0,
            "count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
        }
    except Exception as e:
        logger.exception(f"Query failed for {request.cpe}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/query/bulk", tags=["Query"])
async def query_bulk(request: CPEBulkQueryRequest, db: Session = Depends(get_db)):
    """Query vulnerabilities for multiple CPEs (concurrent)."""
    try:
        results = await aggregator.fetch_bulk(request.cpe_list, db)
        
        output = {}
        for cpe in request.cpe_list:
            found, count = results.get(cpe, (False, 0))
            cves = VulnerabilityService.search_by_cpe(cpe, db) if found else []
            
            output[cpe] = {
                "found": len(cves) > 0,
                "count": len(cves),
                "cve_ids": [cve.cve_id for cve in cves[:10]],
            }
        
        return {
            "status": "completed",
            "total": len(request.cpe_list),
            "results": output,
        }
    except Exception as e:
        logger.exception(f"Bulk query failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# CVE Detail Endpoints
# ============================================================================

@app.get("/cve/{cve_id}", tags=["CVE"])
async def get_cve(cve_id: str, db: Session = Depends(get_db)):
    """Get detailed information about a CVE."""
    detail = VulnerabilityService.get_cve_detail(cve_id, db)
    if not detail:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
    return detail


# ============================================================================
# Frontend Compatibility Endpoints
# ============================================================================

@app.get("/config_nodes_cpe_match/", tags=["Compatibility"])
async def get_cpe_match(cpe_criteria: str = Query(...), db: Session = Depends(get_db)):
    """
    Query vulnerabilities for a CPE (frontend compatibility endpoint).
    Compatible with frontend /config_nodes_cpe_match/?cpe_criteria= format.
    """
    try:
        # Search for CVEs matching this CPE criteria
        cves = VulnerabilityService.search_by_cpe(cpe_criteria, db)
        
        if not cves:
            # Try fetching from sources if not in database
            found, _ = await aggregator.fetch_and_sync(cpe_criteria, db)
            cves = VulnerabilityService.search_by_cpe(cpe_criteria, db) if found else []
        
        # Build response with node and CPE match information
        nodes_data = []
        for cve in cves:
            for node in cve.nodes:
                node_obj = {
                    "node_id": node.id,
                    "cve_id": cve.cve_id,
                    "operator": node.operator,
                    "cpe_matches": [
                        {
                            "cpe_id": match.id,
                            "criteria": match.criteria,
                            "vulnerable": match.vulnerable,
                            "matchCriteriaId": match.matchCriteriaId,
                            "versionStartIncluding": match.versionStartIncluding,
                            "versionEndIncluding": match.versionEndIncluding,
                        }
                        for match in node.cpe_matches
                        if match.vulnerable
                    ]
                }
                nodes_data.append(node_obj)
        
        return {
            "cpe_criteria": cpe_criteria,
            "found": len(cves) > 0,
            "vulnerabilities": [
                {
                    "cve_id": cve.cve_id,
                    "euvd_id": cve.euvd_id,
                    "status": cve.vulnStatus,
                    "published": cve.published.isoformat() if cve.published else None,
                    "base_score": max(
                        (m.cvssData.get("baseScore", 0) for m in cve.cvss_metrics
                         if m.cvssData),
                        default=None
                    )
                }
                for cve in cves
            ],
            "nodes": nodes_data,
        }
    except Exception as e:
        logger.exception(f"CPE match query failed for {cpe_criteria}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/cve/search", tags=["CVE"])
async def search_cves(
    q: str = Query(..., min_length=2),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """Search CVEs by ID or description."""
    results = VulnerabilityService.search_cves(q, db, limit=limit)
    return {
        "query": q,
        "count": len(results),
        "results": results,
    }


# ============================================================================
# Debug Endpoints (Development Only)
# ============================================================================

if settings.app.debug:
    @app.get("/debug/sources", tags=["Debug"])
    async def debug_sources():
        """List available vulnerability sources."""
        return {
            "sources": [
                {"name": s.name, "type": s.__class__.__name__}
                for s in aggregator.sources
            ]
        }


# ============================================================================
# Entry Point
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.app.debug,
        workers=1 if settings.app.debug else settings.app.workers,
        log_level=settings.app.log_level.lower(),
    )