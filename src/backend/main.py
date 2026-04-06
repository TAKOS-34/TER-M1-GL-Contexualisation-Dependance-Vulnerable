import os
import csv
import httpx
import asyncio
import logging
import re
from io import StringIO
from datetime import datetime
from contextlib import asynccontextmanager
from packaging.version import Version, InvalidVersion

from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy.orm import Session

from models import (Base, engine, get_db,
                    CveItem, CvssMetric, Node, CpeMatch, Description, Reference)
from routers import CVSS, Fix_commits

Base.metadata.create_all(bind=engine)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# EUVD ENDPOINTS
# ---------------------------------------------------------------------------
EUVD_BASE      = "https://euvdservices.enisa.europa.eu/api"
EUVD_CSV_DUMP  = f"{EUVD_BASE}/dump/cve-euvd-mapping"
EUVD_SEARCH    = f"{EUVD_BASE}/search"
EUVD_BY_ID     = f"{EUVD_BASE}/enisaid"
EUVD_LAST      = f"{EUVD_BASE}/lastvulnerabilities"
EUVD_EXPLOITED = f"{EUVD_BASE}/exploitedvulnerabilities"
EUVD_CRITICAL  = f"{EUVD_BASE}/criticalvulnerabilities"


SHARED_CLIENT = httpx.AsyncClient(
    follow_redirects=True, 
    timeout=45.0,
    headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json"
    }
)

def make_client() -> httpx.AsyncClient:
    return SHARED_CLIENT


# ---------------------------------------------------------------------------
# MAVEN → EUVD NAME MAP
# Maps (maven_vendor, maven_artifact) → (euvd_vendor, euvd_product)
# These are the human-readable names EUVD uses in its vendor= and product= params
# Confirmed working from the debug endpoint above
# ---------------------------------------------------------------------------
MAVEN_TO_EUVD: dict[tuple, tuple] = {
    # Log4j
    ("apache", "log4j-core"):              ("apache", "log4j2"),
    ("apache", "log4j-api"):               ("apache", "log4j2"),
    ("apache", "log4j-slf4j2-impl"):       ("apache", "log4j2"),
    ("org.apache.logging.log4j", "log4j-core"):  ("apache", "log4j2"),
    ("org.apache.logging.log4j", "log4j-api"):   ("apache", "log4j2"),

    # Struts
    ("apache", "struts2-core"):            ("apache", "struts"),
    ("org.apache.struts", "struts2-core"): ("apache", "struts"),

    # Spring
    ("org.springframework", "spring-webmvc"):   ("vmware", "spring framework"),
    ("org.springframework", "spring-core"):     ("vmware", "spring framework"),
    ("org.springframework", "spring-beans"):    ("vmware", "spring framework"),
    ("org.springframework", "spring-context"):  ("vmware", "spring framework"),
    ("spring-cloud-function-context", "spring-cloud-function-context"): ("vmware", "spring cloud function"),
    ("spring-cloud-gateway-server",   "spring-cloud-gateway-server"):   ("vmware", "spring cloud gateway"),

    # Jackson
    ("com.fasterxml.jackson.core", "jackson-databind"):              ("fasterxml", "jackson-databind"),
    ("com.fasterxml.jackson.core", "jackson-annotations"):           ("fasterxml", "jackson-databind"),
    ("com.fasterxml.jackson.dataformat", "jackson-dataformat-yaml"): ("fasterxml", "jackson-databind"),

    # Commons
    ("commons-collections", "commons-collections"): ("apache", "commons collections"),
    ("apache", "commons-collections4"):             ("apache", "commons collections"),
    ("apache", "commons-text"):                     ("apache", "commons text"),
    ("apache", "commons-lang3"):                    ("apache", "commons lang"),
    ("commons-io", "commons-io"):                   ("apache", "commons io"),
    ("org.apache.commons", "commons-text"):         ("apache", "commons text"),
    ("org.apache.commons", "commons-collections4"): ("apache", "commons collections"),
    ("commons-collections", "commons-collections"): ("apache", "commons collections"),
    ("apache", "commons-collections4"):             ("apache", "commons collections"),  

    # Netty
    ("netty-all",    "netty-all"):    ("netty", "netty"),
    ("netty-buffer", "netty-buffer"): ("netty", "netty"),
    ("io.netty",     "netty-all"):    ("netty", "netty"),
    ("io.netty",     "netty-buffer"): ("netty", "netty"),

    # Hibernate
    ("hibernate-core",  "hibernate-core"):  ("red hat", "hibernate orm"),
    ("org.hibernate",   "hibernate-core"):  ("red hat", "hibernate orm"),

    # H2
    ("com.h2database", "h2"): ("h2database", "h2"),

    # SnakeYAML
    ("snakeyaml",  "snakeyaml"): ("snakeyaml project", "snakeyaml"),
    ("org.yaml",   "snakeyaml"): ("snakeyaml project", "snakeyaml"),

    # XStream
    ("com.thoughtworks.xstream", "xstream"): ("xstream project", "xstream"),

    # Shiro
    ("apache",           "shiro-core"): ("apache", "shiro"),
    ("org.apache.shiro", "shiro-core"): ("apache", "shiro"),

    # Fastjson
    ("com.alibaba", "fastjson"): ("alibaba", "fastjson"),

    # Guava
    ("com.google.guava", "guava"): ("google", "guava"),

    # Bouncy Castle
    ("org.bouncycastle", "bcprov-jdk15on"): ("legion of the bouncy castle", "bouncy castle"),
    ("org.bouncycastle", "bcprov-jdk18on"): ("legion of the bouncy castle", "bouncy castle"),

    # Jetty
    ("org.eclipse.jetty", "jetty-server"): ("eclipse", "jetty"),

    # Tomcat
    ("apache",                  "tomcat-embed-core"): ("apache", "tomcat"),
    ("org.apache.tomcat.embed", "tomcat-embed-core"): ("apache", "tomcat"),

    # Woodstox
    ("com.fasterxml.woodstox", "woodstox-core"): ("fasterxml", "woodstox"),


}


def resolve_euvd_names(cpe: str) -> list[tuple[str, str]]:
    parts   = cpe.split(":")
    vendor  = parts[3] if len(parts) > 3 else ""
    product = parts[4] if len(parts) > 4 else ""

    candidates = []

    # 1. Exact map lookup
    key = (vendor, product)
    if key in MAVEN_TO_EUVD:
        candidates.append(MAVEN_TO_EUVD[key])

    # 2. Short vendor prefix
    short_vendor = vendor.split(".")[-1] if "." in vendor else vendor
    short_key    = (short_vendor, product)
    if short_key in MAVEN_TO_EUVD and short_key != key:
        candidates.append(MAVEN_TO_EUVD[short_key])

    # 3. Raw artifact name (hyphen → space)
    raw_vendor  = short_vendor.replace("-", " ")
    raw_product = product.replace("-", " ").replace("_", " ")
    raw_candidate = (raw_vendor, raw_product)
    if raw_candidate not in candidates:
        candidates.append(raw_candidate)

    # NO single-word fallback — "commons", "apache", "spring" etc. are too broad
    # and cause cross-library false positives

    # Deduplicate
    seen, result = set(),[]
    for c in candidates:
        if c not in seen:
            seen.add(c)
            result.append(c)
    
    # queries without vendor
    for c in list(result):
        no_vendor = (None, c[1])
        if no_vendor not in seen:
            seen.add(no_vendor)
            result.append(no_vendor)
            
    return result

# ---------------------------------------------------------------------------
# VERSION MATCHING
# Handles all EUVD product_version formats:
#   "log4j-core <2.17.1"           → strip product name, parse "< 2.17.1"
#   "2.5.x before 2.5.10.1"        → upper bound
#   "2.3.x before 2.3.32"          → upper bound
#   "2.3.x series"                 → matches any 2.3.x
#   "2.5 to 2.5.16"                → range
#   "Struts 2.0.0 - Struts 2.5.25" → strip prefix, parse range
#   "2.0.0 ≤6.1.0"                 → range with Unicode ≤
#   "0 <v8.5"                      → strip v prefix
#   "All versions"                 → always affected
#   "unspecified ≤1.9"             → treat as upper bound
# ---------------------------------------------------------------------------
def _parse_version_safe(v: str) -> Version | None:
    if not v:
        return None
    v = str(v).strip()
    # Strip leading "v" prefix
    v = re.sub(r'^v', '', v, flags=re.IGNORECASE)
    # Extract first version number sequence
    m = re.search(r'(\d+(?:\.\d+)*)', v)
    if not m:
        return None
    try:
        return Version(m.group(1))
    except InvalidVersion:
        return None


def version_is_affected(product_version_str: str, target_version: str) -> bool:
    pv = str(product_version_str).strip()
    tv = str(target_version).strip()

    pv_lower = pv.lower()
    if not pv or pv_lower in ("*", "all", "all versions", "n/a", "unspecified",
                               "unknown", "patch: 0", "any"):
        return True

    if pv_lower.startswith("patch:"):
        fixed_str = pv.split(":", 1)[1].strip()
        if not fixed_str or fixed_str == "0":
            return True
        fixed  = _parse_version_safe(fixed_str)
        target = _parse_version_safe(tv)
        if fixed and target:
            return target < fixed
        return False

    target = _parse_version_safe(tv)
    if not target:
        return False

    # Normalize Unicode operators
    pv = pv.replace("≤", "<=").replace("≥", ">=")

    # KEY FIX: strip leading non-operator text before the first comparator or number
    # Handles: "log4j-core <2.17.1"  → "<2.17.1"
    #          "Struts 2.0.0 - ..."  → "2.0.0 - ..."
    #          "Apache Struts before 2.3.34" → "before 2.3.34"
    #          "0 <v8.5"             → "0 <v8.5"  (already starts with digit)
    pv = re.sub(r'^[A-Za-z][A-Za-z0-9_.\-]*\s+', '', pv).strip()

    # "before X" → "< X"
    pv = re.sub(r'\bbefore\b\s+', '< ', pv, flags=re.IGNORECASE)
    # "X.x before Y" → "X < Y"
    pv = re.sub(r'\.x\s+before\s+', ' < ', pv, flags=re.IGNORECASE)
    # "X to Y" → "X <= Y"
    pv = re.sub(r'\s+to\s+', ' <= ', pv, flags=re.IGNORECASE)
    # "X - Y" (dash range) → "X <= Y"
    pv = re.sub(r'\s+-\s+', ' <= ', pv)
    # Strip trailing product name after version operator
    # "< 2.17.1 something" → "< 2.17.1"
    pv = re.sub(r'(?<=[\d])\s+[A-Za-z].*$', '', pv).strip()
    # Strip leading "v" from version numbers
    pv = re.sub(r'(?<![A-Za-z])v(\d)', r'\1', pv)

    # "2.3.x series" → major.minor match
    series_match = re.match(r'^(\d+\.\d+)(?:\.x)?\s+series$', pv, re.IGNORECASE)
    if series_match:
        base = _parse_version_safe(series_match.group(1))
        if base:
            return target.major == base.major and target.minor == base.minor

    try:
        if "<=" in pv:
            parts = pv.split("<=")
            upper = _parse_version_safe(parts[-1])
            lower = _parse_version_safe(parts[0]) if parts[0].strip() else None
            if upper:
                return (lower <= target <= upper) if lower else (target <= upper)

        if "<" in pv:
            parts = pv.split("<")
            upper = _parse_version_safe(parts[-1])
            lower = _parse_version_safe(parts[0]) if parts[0].strip() else None
            if upper:
                return (lower <= target < upper) if lower else (target < upper)

        if ">=" in pv:
            lower = _parse_version_safe(pv.split(">=")[-1])
            if lower:
                return target >= lower

        if ">" in pv:
            lower = _parse_version_safe(pv.split(">")[-1])
            if lower:
                return target > lower

        exact = _parse_version_safe(pv)
        if exact:
            return target == exact

    except Exception as e:
        logger.debug(f"Version compare error: '{pv}' vs '{tv}' → {e}")

    return False


def item_affects_version_strict(euvd_item: dict, target_version: str,
                                 target_product_hint: str = "") -> bool:
    products = euvd_item.get("enisaIdProduct", [])

    if not products:
        base_score = euvd_item.get("baseScore", -1)
        return base_score is not None and float(base_score) > 0

    hint_lower = target_product_hint.lower()

    for entry in products:
        product_name = entry.get("product", {}).get("name", "").lower()
        pv           = entry.get("product_version", "")

        # Skip FIPS/LTS variant entries when searching for standard library
        # bcprov-jdk15on and bcprov-jdk18on are standard BC, not FIPS variants
        if hint_lower and "bcprov" in hint_lower:
            # Only match standard BC entries, skip FIPS and LTS variants
            if any(variant in product_name for variant in ("fja", "fips", "lts", "bc-fja")):
                continue
            # Also skip if the version string starts with a FIPS/LTS prefix
            pv_lower = pv.lower()
            if any(prefix in pv_lower for prefix in ("bc-fja", "bc-lts", "fja", "bcpkix fips")):
                continue

        # Generic variant filtering for other libraries
        if hint_lower:
            if "fja" in product_name and "fja" not in hint_lower:
                continue
            if "fips" in product_name and "fips" not in hint_lower:
                continue
            if "lts" in product_name and "lts" not in hint_lower:
                continue

        if version_is_affected(pv, target_version):
            return True

    return False

# ---------------------------------------------------------------------------
# STARTUP — seed CVE→EUVD ID mapping from daily CSV
# ---------------------------------------------------------------------------
async def _initial_csv_sync():
    db = next(get_db())
    try:
        if db.query(CveItem).count() > 0:
            logger.info("DB already seeded — skipping CSV sync")
            return

        logger.info("DB empty — seeding from EUVD CSV...")
        async with make_client() as client:
            resp = await client.get(EUVD_CSV_DUMP, timeout=300.0)
            if resp.status_code != 200:
                logger.warning(f"CSV download failed: HTTP {resp.status_code}")
                return

        lines  = resp.text.replace('\r', '').split('\n')
        reader = csv.DictReader(StringIO('\n'.join(lines)), skipinitialspace=True)
        added  = 0

        for row in reader:
            clean   = {k.strip(): v.strip() for k, v in row.items() if k and v}
            cve_id  = clean.get('cve_id')  or clean.get('cveId')
            euvd_id = clean.get('euvd_id') or clean.get('euvdId')

            if not cve_id or "CVE" not in cve_id:
                continue
            if db.query(CveItem).filter(CveItem.cve_id == cve_id).first():
                continue

            db.add(CveItem(
                cve_id=cve_id, euvd_id=euvd_id,
                published=datetime.utcnow(), lastModified=datetime.utcnow(),
                sourceIdentifier="ENISA_DUMP", vulnStatus="MAPPED_FROM_EUVD",
            ))
            added += 1
            if added % 1000 == 0:
                db.commit()
                logger.info(f"  ... {added} CVEs seeded")

        db.commit()
        logger.info(f"CSV sync done: {added} CVEs seeded")

    except Exception as e:
        logger.warning(f"CSV sync failed: {e}")
        db.rollback()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await _initial_csv_sync()
    yield


# ---------------------------------------------------------------------------
# APP
# ---------------------------------------------------------------------------
app = FastAPI(title="Pradeo Analyzer API - EUVD Edition", lifespan=lifespan)
app.include_router(CVSS.router)
app.include_router(Fix_commits.router)


@app.get("/")
def read_root():
    return {"status": "ok", "message": "Pradeo Analyzer - Pure EUVD Edition"}


def parse_cpe(cpe: str) -> dict:
    parts = cpe.split(":")
    return {
        "vendor":  parts[3] if len(parts) > 3 else "*",
        "product": parts[4] if len(parts) > 4 else "*",
        "version": parts[5] if len(parts) > 5 else "*",
    }


# ---------------------------------------------------------------------------
# CACHE WRITE
# ---------------------------------------------------------------------------
def write_to_cache(item: dict, db: Session,
                   source: str = "ENISA",
                   original_cpe: str | None = None):
    euvd_id = item.get("id")
    aliases = [
        a.strip() for a in item.get("aliases", "").split("\n")
        if a.strip().upper().startswith("CVE-")
    ]
    if not aliases:
        return

    for cve_id in aliases:
        cve = db.query(CveItem).filter(CveItem.cve_id == cve_id).first()
        if not cve:
            cve = CveItem(
                cve_id=cve_id, euvd_id=euvd_id,
                published=datetime.utcnow(), lastModified=datetime.utcnow(),
                sourceIdentifier=source, vulnStatus="PUBLISHED",
            )
            db.add(cve)
            db.flush()
        elif not cve.euvd_id and euvd_id:
            cve.euvd_id = euvd_id

        desc = item.get("description", "")
        if desc and not db.query(Description).filter(
            Description.cve_id == cve_id, Description.lang == "en"
        ).first():
            db.add(Description(cve_id=cve_id, lang="en", value=desc))

        for url in item.get("references", "").split("\n"):
            url = url.strip()
            if url and not db.query(Reference).filter(
                Reference.cve_id == cve_id, Reference.url == url
            ).first():
                db.add(Reference(cve_id=cve_id, url=url, source=source, tags=[]))

        base_score   = item.get("baseScore")
        base_vector  = item.get("baseScoreVector")
        base_version = str(item.get("baseScoreVersion") or "3.1")

        if base_score is not None and float(base_score) >= 0:
            if not db.query(CvssMetric).filter(CvssMetric.cve_id == cve_id).first():
                db.add(CvssMetric(
                    cve_id=cve_id, version=base_version,
                    cvssData={
                        "baseScore":    base_score,
                        "vectorString": base_vector,
                        "version":      base_version,
                    },
                    exploitabilityScore=None, impactScore=None, source=source,
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


def _store_unknown_cpe_marker(cpe_name: str, db: Session):
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


# ---------------------------------------------------------------------------
# EUVD FETCHERS
# ---------------------------------------------------------------------------
async def _euvd_search_by_product(vendor: str | None, product: str, size: int = 40) -> list[dict]:
    try:
        params = {"product": product, "size": size}
        if vendor:
            params["vendor"] = vendor

        resp = await SHARED_CLIENT.get(
            EUVD_SEARCH,
            params=params
        )
        if resp.status_code == 200:
            return resp.json().get("items",[])
            
        logger.warning(f"EUVD search vendor={vendor} product={product} "f"→ HTTP {resp.status_code}")
    except httpx.ReadTimeout:
        logger.warning(f"EUVD timeout searching {vendor} {product}. Backend overloaded.")
    except Exception as e:
        logger.error(f"EUVD request failed: {e}")
        
    return[]


async def _euvd_fetch_by_id(euvd_id: str) -> dict | None:
    async with make_client() as client:
        resp = await client.get(EUVD_BY_ID, params={"id": euvd_id})
        if resp.status_code == 200:
            return resp.json()
        logger.warning(f"EUVD enisaid {euvd_id} → HTTP {resp.status_code}")
    return None

# ---------------------------------------------------------------------------
# OSV FALLBACK INTEGRATION
# ---------------------------------------------------------------------------
OSV_QUERY_URL = "https://api.osv.dev/v1/query"

async def _osv_fetch_by_package(vendor: str, product: str, version: str) -> list[dict]:
    queries =[
        {"ecosystem": "Maven", "name": f"{vendor}:{product}"},
        {"ecosystem": "PyPI", "name": product},
        {"ecosystem": "npm", "name": product},
        {"ecosystem": "Go", "name": product},
    ]
    
    for pkg in queries:
        try:
            payload = {"version": version, "package": pkg}
            # Use SHARED_CLIENT directly here too
            resp = await SHARED_CLIENT.post(OSV_QUERY_URL, json=payload)
            if resp.status_code == 200:
                vulns = resp.json().get("vulns",[])
                if vulns:
                    return vulns
        except Exception as e:
            logger.error(f"OSV request failed for {pkg}: {e}")
            
    return[]

def write_osv_to_cache(osv_item: dict, db: Session, original_cpe: str):
    osv_id = osv_item.get("id")
    # Prefer CVE aliases if OSV provides them, otherwise fallback to the OSV/GHSA ID
    aliases =[a for a in osv_item.get("aliases", []) if a.startswith("CVE-")]
    vuln_ids = aliases if aliases else [osv_id]
    
    for v_id in vuln_ids:
        cve = db.query(CveItem).filter(CveItem.cve_id == v_id).first()
        if not cve:
            db.add(CveItem(
                cve_id=v_id, published=datetime.utcnow(),
                lastModified=datetime.utcnow(),
                sourceIdentifier="OSV", vulnStatus="PUBLISHED",
            ))
            db.flush()
        
        desc = osv_item.get("summary") or osv_item.get("details", "")
        if desc and not db.query(Description).filter(
            Description.cve_id == v_id, Description.lang == "en"
        ).first():
            db.add(Description(cve_id=v_id, lang="en", value=desc[:4000]))

        # Cache CVSS score if OSV provides it
        for sev in osv_item.get("severity",[]):
            if sev.get("type") in ("CVSS_V3", "CVSS_V4") and not db.query(CvssMetric).filter(CvssMetric.cve_id == v_id).first():
                db.add(CvssMetric(
                    cve_id=v_id, version="3.1",
                    cvssData={"vectorString": sev.get("score"), "version": "3.1"},
                    source="OSV"
                ))

        node_obj = db.query(Node).filter(Node.cve_id == v_id).first()
        if not node_obj:
            node_obj = Node(cve_id=v_id, operator="OR", negate=False)
            db.add(node_obj)
            db.flush()

        if original_cpe and not db.query(CpeMatch).filter(
            CpeMatch.node_id == node_obj.id, CpeMatch.criteria == original_cpe
        ).first():
            db.add(CpeMatch(node_id=node_obj.id, vulnerable=True, criteria=original_cpe))

# ---------------------------------------------------------------------------
# CORE: fetch_and_sync_cpe — pure EUVD, no NVD
#
# Flow:
#   1. Resolve Maven CPE → (euvd_vendor, euvd_product) via MAVEN_TO_EUVD map
#   2. Call EUVD /api/search?vendor=...&product=...
#   3. For each result, check version range with item_affects_version()
#   4. Write confirmed vulns to cache
#   5. If no results at all → store unknown marker
# ---------------------------------------------------------------------------
async def fetch_and_sync_cpe(cpe_name: str, db: Session) -> bool:
    parsed          = parse_cpe(cpe_name)
    target_version  = parsed["version"]
    target_product  = parsed["product"]  # used as hint for variant filtering
    name_candidates = resolve_euvd_names(cpe_name)
    confirmed       = False

    for vendor, product in name_candidates:
        logger.info(f"EUVD search: vendor='{vendor}' product='{product}' "
                    f"version={target_version}")
        items = await _euvd_search_by_product(vendor, product)

        for item in items:
            # Use strict matching with product hint to avoid variant false positives
            if item_affects_version_strict(item, target_version,
                                           target_product_hint=target_product):
                cve_aliases = [
                    a.strip() for a in item.get("aliases", "").split("\n")
                    if a.strip().upper().startswith("CVE-")
                ]
                logger.info(
                    f"✓ VULNERABLE: {cpe_name} → "
                    f"{cve_aliases} (score={item.get('baseScore')})"
                )
                write_to_cache(item, db, source="ENISA", original_cpe=cpe_name)
                confirmed = True
            else:
                logger.debug(
                    f"✗ Not affected: v{target_version} | "
                    f"{[e.get('product_version') for e in item.get('enisaIdProduct', [])]}"
                )

        try:
            db.commit()
        except Exception as e:
            db.rollback()
            logger.exception(f"DB commit failed: {e}")
            return False

        if confirmed:
            break
        
        await asyncio.sleep(6.0)
    
    if not confirmed:
        logger.info(f"EUVD missed, querying OSV fallback for: {cpe_name}")
        osv_vulns = await _osv_fetch_by_package(parsed["vendor"], parsed["product"], target_version)
        
        if osv_vulns:
            for vuln in osv_vulns:
                logger.info(f"✓ OSV VULNERABLE: {cpe_name} → {vuln.get('id')}")
                write_osv_to_cache(vuln, db, original_cpe=cpe_name)
                confirmed = True
            
            try:
                db.commit()
            except Exception as e:
                db.rollback()
                logger.exception(f"DB commit failed (OSV cache): {e}")
                return False

    if not confirmed:
        _store_unknown_cpe_marker(cpe_name, db)

    return confirmed


# ---------------------------------------------------------------------------
# ENDPOINTS
# ---------------------------------------------------------------------------
@app.get("/config_nodes_cpe_match/")
async def get_cpe_matches(cpe_criteria: str, db: Session = Depends(get_db)):
    results = db.query(CpeMatch).filter(CpeMatch.criteria == cpe_criteria).all()
    if not results:
        logger.info(f"CPE cache miss: {cpe_criteria}")
        await fetch_and_sync_cpe(cpe_criteria, db)
        results = db.query(CpeMatch).filter(CpeMatch.criteria == cpe_criteria).all()
    return [r for r in results if r.vulnerable]


@app.post("/config_nodes_cpe_match/bulk")
async def get_cpe_matches_bulk(cpe_list: list[str], db: Session = Depends(get_db)):
    hits, misses = {}, []
    for cpe in cpe_list:
        results = db.query(CpeMatch).filter(
            CpeMatch.criteria == cpe, CpeMatch.vulnerable == True
        ).all()
        if results:
            hits[cpe] = [{"criteria": r.criteria, "vulnerable": r.vulnerable}
                         for r in results]
        else:
            marker = db.query(CpeMatch).filter(CpeMatch.criteria == cpe).first()
            hits[cpe] = [] if marker else None
            if not marker:
                misses.append(cpe)

    if misses:
        logger.info(f"Bulk: {len(hits)} hits, {len(misses)} misses")
        for cpe in misses:
            try:
                await fetch_and_sync_cpe(cpe, db)
            except Exception as e:
                logger.error(f"Error fetching {cpe}: {e}")
            
            await asyncio.sleep(6.0) 
            
        for cpe in misses:
            results = db.query(CpeMatch).filter(
                CpeMatch.criteria == cpe, CpeMatch.vulnerable == True
            ).all()
            hits[cpe] = [{"criteria": r.criteria, "vulnerable": r.vulnerable}
                         for r in results]
    return hits


@app.post("/sync/euvd-mapping-csv")
async def sync_euvd_csv(db: Session = Depends(get_db)):
    async with make_client() as client:
        try:
            resp = await client.get(EUVD_CSV_DUMP, timeout=300.0)
            resp.raise_for_status()
            lines  = resp.text.replace('\r', '').split('\n')
            reader = csv.DictReader(StringIO('\n'.join(lines)), skipinitialspace=True)
            added  = updated = skipped = 0
            for row in reader:
                clean   = {k.strip(): v.strip() for k, v in row.items() if k and v}
                cve_id  = clean.get('cve_id')  or clean.get('cveId')
                euvd_id = clean.get('euvd_id') or clean.get('euvdId')
                if not cve_id or "CVE" not in cve_id:
                    skipped += 1
                    continue
                existing = db.query(CveItem).filter(CveItem.cve_id == cve_id).first()
                if existing:
                    if existing.euvd_id != euvd_id:
                        existing.euvd_id = euvd_id
                        updated += 1
                else:
                    db.add(CveItem(
                        cve_id=cve_id, euvd_id=euvd_id,
                        published=datetime.utcnow(), lastModified=datetime.utcnow(),
                        sourceIdentifier="ENISA_DUMP", vulnStatus="MAPPED_FROM_EUVD",
                    ))
                    added += 1
                if (added + updated) % 1000 == 0 and (added + updated) > 0:
                    db.commit()
            db.commit()
            return {"status": "success", "added": added,
                    "updated": updated, "skipped": skipped}
        except Exception as e:
            db.rollback()
            raise HTTPException(status_code=500, detail=str(e))


@app.delete("/cache/reset")
def reset_cache(db: Session = Depends(get_db)):
    try:
        db.query(CveItem).filter(
            CveItem.sourceIdentifier.in_(["UNKNOWN", "ENISA", "ENISA_SEARCH"])
        ).delete(synchronize_session=False)
        db.query(CpeMatch).filter(
            CpeMatch.criteria.like("cpe:2.3:%")
        ).delete(synchronize_session=False)
        db.query(Node).filter(
            ~Node.cve_id.in_(db.query(CveItem.cve_id))
        ).delete(synchronize_session=False)
        db.commit()
        return {"status": "cache cleared"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/sync/status")
def sync_status(db: Session = Depends(get_db)):
    return {
        "total_cves":    db.query(CveItem).count(),
        "euvd_mappings": db.query(CveItem).filter(CveItem.euvd_id.isnot(None)).count(),
        "cvss_scores":   db.query(CvssMetric).count(),
        "cpe_entries":   db.query(CpeMatch).filter(CpeMatch.vulnerable == True).count(),
        "unknown_cpes":  db.query(CpeMatch).filter(CpeMatch.vulnerable == False).count(),
    }


# ---------------------------------------------------------------------------
# EUVD PASSTHROUGH
# ---------------------------------------------------------------------------
@app.get("/euvd/latest")
async def euvd_latest():
    async with make_client() as client:
        resp = await client.get(EUVD_LAST)
        resp.raise_for_status()
        return resp.json()


@app.get("/euvd/exploited")
async def euvd_exploited():
    async with make_client() as client:
        resp = await client.get(EUVD_EXPLOITED)
        resp.raise_for_status()
        return resp.json()


@app.get("/euvd/critical")
async def euvd_critical():
    async with make_client() as client:
        resp = await client.get(EUVD_CRITICAL)
        resp.raise_for_status()
        return resp.json()


# ---------------------------------------------------------------------------
# DEBUG
# ---------------------------------------------------------------------------
@app.get("/debug/euvd-product")
async def debug_euvd_product(vendor: str, product: str, version: str = ""):
    items = await _euvd_search_by_product(vendor, product)
    return {
        "vendor": vendor, "product": product,
        "total": len(items),
        "items": [
            {
                "id":        i.get("id"),
                "aliases":   i.get("aliases", "").split("\n")[:3],
                "baseScore": i.get("baseScore"),
                "products":  i.get("enisaIdProduct", []),
                "affected":  item_affects_version_strict(i, version) if version else None,
            }
            for i in items
        ]
    }


@app.get("/debug/trace-cpe")
async def debug_trace_cpe(cpe: str):
    parsed         = parse_cpe(cpe)
    target_version = parsed["version"]
    name_candidates = resolve_euvd_names(cpe)
    trace          = []

    for vendor, product in name_candidates:
        items = await _euvd_search_by_product(vendor, product, size=20)
        step  = {
            "vendor": vendor, "product": product,
            "results_count": len(items),
            "items": [
                {
                    "id":        i.get("id"),
                    "aliases":   i.get("aliases", "").split("\n")[:2],
                    "baseScore": i.get("baseScore"),
                    "products":  i.get("enisaIdProduct", []),
                    "affected":  item_affects_version_strict(i, target_version),
                }
                for i in items
            ]
        }
        trace.append(step)
        if items:
            break  # stop at first successful search

    return {"cpe": cpe, "target_version": target_version,
            "name_candidates": name_candidates, "trace": trace}

@app.get("/config_nodes_cpe_match/")
async def get_cpe_matches(cpe_criteria: str, db: Session = Depends(get_db)):
    results = db.query(CpeMatch).filter(CpeMatch.criteria == cpe_criteria).all()
    if not results:
        logger.info(f"CPE cache miss: {cpe_criteria}")
        await fetch_and_sync_cpe(cpe_criteria, db)
        results = db.query(CpeMatch).filter(CpeMatch.criteria == cpe_criteria).all()

    # Filter vulnerable + deduplicate (one row per unique CVE is enough)
    vulnerable = [r for r in results if r.vulnerable]

    # Return unique node_ids only — frontend only needs to know "is it vulnerable"
    # not the full list of CVEs (that's what /vulnerability/{cve_id} is for)
    seen_nodes = set()
    deduplicated = []
    for r in vulnerable:
        if r.node_id not in seen_nodes:
            seen_nodes.add(r.node_id)
            deduplicated.append(r)

    return deduplicated
