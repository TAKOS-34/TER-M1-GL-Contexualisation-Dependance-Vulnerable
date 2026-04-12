import os

# EUVD
EUVD_BASE      = "https://euvdservices.enisa.europa.eu/api"
EUVD_CSV_DUMP  = f"{EUVD_BASE}/dump/cve-euvd-mapping"
EUVD_SEARCH    = f"{EUVD_BASE}/search"
EUVD_BY_ID     = f"{EUVD_BASE}/enisaid"
EUVD_LAST      = f"{EUVD_BASE}/lastvulnerabilities"
EUVD_EXPLOITED = f"{EUVD_BASE}/exploitedvulnerabilities"
EUVD_CRITICAL  = f"{EUVD_BASE}/criticalvulnerabilities"

# OSV
OSV_API_BASE = "https://api.osv.dev/v1/query"

# NVD
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY  = os.getenv("NVD_API_KEY", "")

# GitHub Advisory
GITHUB_ADVISORY_URL = "https://api.github.com/graphql"
GITHUB_TOKEN        = os.getenv("GITHUB_TOKEN", "")

# JVN
JVN_API_BASE = "https://jvndb.jvn.jp/myjvn"

import httpx

def make_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(follow_redirects=True, timeout=30.0)