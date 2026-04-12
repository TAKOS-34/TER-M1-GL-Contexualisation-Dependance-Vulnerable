"""NVD (National Vulnerability Database) source implementation."""
import logging
from typing import List, Dict, Tuple, Optional
from core.config import make_client, NVD_API_BASE, NVD_API_KEY, settings
from core.types import NormalizedVulnerabilityDict
from core.logger import get_logger
from matching.cpe import parse_cpe
from matching.version import _parse_version_safe
from sources.base import VulnerabilitySource

logger = get_logger(__name__)

NVD_CPE_MAP: dict[tuple, tuple] = {
    ("apache", "log4j-core"):   ("apache", "log4j2"),
    ("apache", "log4j-api"):    ("apache", "log4j2"),
    ("apache", "struts2-core"): ("apache", "struts"),
    ("com.fasterxml.jackson.core", "jackson-databind"): ("fasterxml", "jackson-databind"),
    ("commons-collections", "commons-collections"):     ("apache", "commons_collections"),
    ("apache", "commons-text"):  ("apache", "commons_text"),
    ("snakeyaml", "snakeyaml"):  ("snakeyaml_project", "snakeyaml"),
    ("org.yaml",  "snakeyaml"):  ("snakeyaml_project", "snakeyaml"),
    ("com.h2database", "h2"):    ("h2database", "h2"),
    ("hibernate-core", "hibernate-core"): ("redhat", "hibernate_orm"),
    ("org.hibernate",  "hibernate-core"): ("redhat", "hibernate_orm"),
    ("com.thoughtworks.xstream", "xstream"): ("xstream_project", "xstream"),
    ("com.alibaba", "fastjson"): ("alibaba", "fastjson"),
    ("com.google.guava", "guava"): ("google", "guava"),
    ("netty-all",    "netty-all"):    ("netty", "netty"),
    ("netty-buffer", "netty-buffer"): ("netty", "netty"),
    ("io.netty",     "netty-all"):    ("netty", "netty"),
    ("org.eclipse.jetty", "jetty-server"): ("eclipse", "jetty"),
    ("apache",                  "tomcat-embed-core"): ("apache", "tomcat"),
    ("org.apache.tomcat.embed", "tomcat-embed-core"): ("apache", "tomcat"),
    ("apache",      "shiro-core"): ("apache", "shiro"),
    ("org.springframework", "spring-webmvc"): ("pivotal_software", "spring_framework"),
    ("spring-cloud-function-context", "spring-cloud-function-context"): ("pivotal_software", "spring_cloud_function"),
    ("spring-cloud-gateway-server",   "spring-cloud-gateway-server"):   ("pivotal_software", "spring_cloud_gateway"),
    ("org.bouncycastle", "bcprov-jdk15on"): ("bouncycastle", "bouncy-castle-crypto-package"),
    ("org.bouncycastle", "bcprov-jdk18on"): ("bouncycastle", "bouncy-castle-crypto-package"),
}


class NVDSource(VulnerabilitySource):
    """
    NVD is used ONLY as a CPE→CVE ID index.
    No vulnerability data is taken from NVD — we only extract CVE IDs,
    then enrich them via EUVD.
    """

    @property
    def name(self) -> str:
        return "NVD"

    async def healthy(self) -> bool:
        async with make_client() as client:
            try:
                resp = await client.get(NVD_API_BASE, params={"resultsPerPage": 1},
                                        timeout=5.0)
                return resp.status_code == 200
            except Exception:
                return False

    def _normalize_cpe(self, cpe: str) -> List[str]:
        """Normalize CPE to try multiple variants from mapping table."""
        parts = cpe.split(":")
        vendor = parts[3] if len(parts) > 3 else ""
        product = parts[4] if len(parts) > 4 else ""
        version = parts[5] if len(parts) > 5 else "*"

        candidates = []
        key = (vendor, product)
        if key in NVD_CPE_MAP:
            v, p = NVD_CPE_MAP[key]
            candidates.append(f"cpe:2.3:a:{v}:{p}:{version}:*:*:*:*:*:*:*")

        short_vendor = vendor.split(".")[-1] if "." in vendor else vendor
        short_key = (short_vendor, product)
        if short_key in NVD_CPE_MAP and short_key != key:
            v, p = NVD_CPE_MAP[short_key]
            candidates.append(f"cpe:2.3:a:{v}:{p}:{version}:*:*:*:*:*:*:*")

        candidates.append(cpe)
        seen, result = set(), []
        for c in candidates:
            if c not in seen:
                seen.add(c)
                result.append(c)
        return result

    def _version_in_range(self, nvd_vuln: dict, target: str) -> bool:
        try:
            t = _parse_version_safe(target)
            for config in nvd_vuln.get("cve", {}).get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        if not match.get("vulnerable"):
                            continue
                        if not t:
                            return target.lower() in match.get("criteria", "").lower()

                        si = _parse_version_safe(match.get("versionStartIncluding", ""))
                        se = _parse_version_safe(match.get("versionStartExcluding", ""))
                        ei = _parse_version_safe(match.get("versionEndIncluding", ""))
                        ee = _parse_version_safe(match.get("versionEndExcluding", ""))

                        if si and t < si: continue
                        if se and t <= se: continue
                        if ee and t >= ee: continue
                        if ei and t > ei:  continue
                        return True
        except Exception:
            pass
        return False

    async def get_cve_ids(self, cpe: str) -> List[str]:
        """
        Query NVD API for CVE IDs affecting a CPE.
        
        Args:
            cpe: CPE 2.3 string
        
        Returns:
            List of CVE IDs (e.g., ["CVE-2021-44228", ...])
        """
        try:
            parsed = parse_cpe(cpe)
            target_version = parsed["version"]
            headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
            cpe_variants = self._normalize_cpe(cpe)

            async with make_client() as client:
                for cpe_try in cpe_variants:
                    try:
                        resp = await client.get(
                            NVD_API_BASE,
                            params={"cpeName": cpe_try, "resultsPerPage": 100},
                            headers=headers,
                            timeout=20.0,
                        )
                        resp.raise_for_status()
                        vulns = resp.json().get("vulnerabilities", [])
                        ids = [
                            v["cve"]["id"] for v in vulns
                            if v.get("cve", {}).get("id")
                            and self._version_in_range(v, target_version)
                        ]
                        if ids:
                            logger.info(f"[NVD] Found {len(ids)} CVEs for {cpe_try}")
                            return ids
                    except Exception as e:
                        logger.warning(f"[NVD] Variant {cpe_try} failed: {e}")
                        continue
        except Exception as e:
            logger.error(f"[NVD] get_cve_ids({cpe}) failed: {e}", exc_info=True)
        return []

    async def query(self, cpe: str) -> List[NormalizedVulnerabilityDict]:
        """
        NVD query returns minimal stubs — just CVE IDs for the aggregator to enrich.
        
        This source serves as a CPE→CVE index only. No vulnerability data
        is stored from NVD; it's enriched from EUVD/OSV later.
        """
        try:
            cve_ids = await self.get_cve_ids(cpe)
            results: List[NormalizedVulnerabilityDict] = []
            
            for cve_id in cve_ids:
                results.append({
                    "cve_ids": [cve_id],
                    "euvd_id": None,
                    "source": self.name,
                    "base_score": None,
                    "base_vector": None,
                    "base_version": "3.1",
                    "description": "",
                    "references": [],
                    "affects_version": True,
                    "raw": {},
                })
            
            logger.info(f"[NVD] Found {len(results)} vulnerabilities for {cpe}")
            return results
        except Exception as e:
            logger.error(f"[NVD] query({cpe}) failed: {e}", exc_info=True)
            return []