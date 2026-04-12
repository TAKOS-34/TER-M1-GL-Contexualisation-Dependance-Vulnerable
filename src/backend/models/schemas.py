"""Pydantic schemas for API request/response validation."""
from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, validator


# ============================================================================
# Request Schemas
# ============================================================================

class CPEQueryRequest(BaseModel):
    """Request to query vulnerabilities for a CPE."""
    cpe: str = Field(..., description="CPE 2.3 string (e.g., cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*)")
    
    class Config:
        schema_extra = {
            "example": {
                "cpe": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
            }
        }


class CPEBulkQueryRequest(BaseModel):
    """Request to query multiple CPEs."""
    cpe_list: List[str] = Field(..., min_items=1, max_items=1000)
    
    class Config:
        schema_extra = {
            "example": {
                "cpe_list": [
                    "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                    "cpe:2.3:a:java:jdk:1.8.0:*:*:*:*:*:*:*"
                ]
            }
        }


class ForceSyncRequest(BaseModel):
    """Request to force synchronization."""
    sources: Optional[List[str]] = Field(None, description="Specific sources to sync (default: all)")
    limit: Optional[int] = Field(None, description="Limit number of items")


# ============================================================================
# Response Schemas
# ============================================================================

class CvssDataResponse(BaseModel):
    """CVSS scoring data."""
    baseScore: float
    vectorString: Optional[str] = None
    version: str = "3.1"
    
    class Config:
        from_attributes = True


class CvssMetricResponse(BaseModel):
    """CVSS metric response."""
    version: str
    score: float
    source: str
    type: Optional[str] = None
    
    class Config:
        from_attributes = True


class DescriptionResponse(BaseModel):
    """Description response."""
    lang: str
    value: str
    
    class Config:
        from_attributes = True


class ReferenceResponse(BaseModel):
    """Reference response."""
    url: str
    source: Optional[str] = None
    tags: Optional[List[str]] = None
    
    class Config:
        from_attributes = True


class CPEMatchResponse(BaseModel):
    """CPE match response."""
    criteria: str
    vulnerable: bool
    versionStartIncluding: Optional[str] = None
    versionEndIncluding: Optional[str] = None
    versionStartExcluding: Optional[str] = None
    versionEndExcluding: Optional[str] = None
    
    class Config:
        from_attributes = True


class VulnerabilityDetailResponse(BaseModel):
    """Detailed vulnerability response."""
    cve_id: str
    euvd_id: Optional[str] = None
    status: str
    published: datetime
    lastModified: datetime
    descriptions: List[DescriptionResponse]
    references: List[ReferenceResponse]
    cvss_metrics: List[CvssMetricResponse]
    cpe_matches: List[CPEMatchResponse]
    
    class Config:
        from_attributes = True


class VulnerabilitySummaryResponse(BaseModel):
    """Vulnerability summary (minimal response)."""
    cve_id: str
    euvd_id: Optional[str] = None
    status: str
    published: datetime
    base_score: Optional[float] = None
    
    class Config:
        from_attributes = True


class HealthStatusResponse(BaseModel):
    """Health check response."""
    status: str
    timestamp: datetime
    sources: Dict[str, Any]
    
    class Config:
        schema_extra = {
            "example": {
                "status": "healthy",
                "timestamp": "2024-01-15T10:30:00Z",
                "sources": {
                    "EUVD": {"healthy": True, "details": "OK"},
                    "OSV": {"healthy": True, "details": "OK"},
                    "NVD": {"healthy": False, "details": "Connection timeout"}
                }
            }
        }


class SyncStatusResponse(BaseModel):
    """Synchronization status response."""
    status: str
    total_cves: int
    euvd_mappings: int
    mapped_percentage: float
    cpe_entries: int
    unknown_cpes: int
    last_update: Optional[datetime] = None
    
    class Config:
        schema_extra = {
            "example": {
                "status": "synced",
                "total_cves": 150000,
                "euvd_mappings": 145000,
                "mapped_percentage": 96.67,
                "cpe_entries": 50000,
                "unknown_cpes": 1200
            }
        }


class CveQueryResponse(BaseModel):
    """Response from CVE query endpoint."""
    found: bool
    count: int
    vulnerabilities: List[VulnerabilitySummaryResponse]
    
    class Config:
        schema_extra = {
            "example": {
                "found": True,
                "count": 2,
                "vulnerabilities": [
                    {
                        "cve_id": "CVE-2021-44228",
                        "euvd_id": "EUVD-2021-1234",
                        "status": "PUBLISHED",
                        "published": "2021-12-10T00:00:00Z",
                        "base_score": 10.0
                    }
                ]
            }
        }


class ErrorResponse(BaseModel):
    """Error response."""
    error: str
    code: int
    details: Optional[str] = None
    
    class Config:
        schema_extra = {
            "example": {
                "error": "Invalid CPE format",
                "code": 400,
                "details": "Expected cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*"
            }
        }


class FixCommitResponse(BaseModel):
    """Fix commit response."""
    id: int
    cve_id: str
    commit_id: str
    repository: Optional[str] = None
    message: Optional[str] = None
    patch: str
    url: Optional[str] = None
    created_at: datetime
    
    class Config:
        from_attributes = True
