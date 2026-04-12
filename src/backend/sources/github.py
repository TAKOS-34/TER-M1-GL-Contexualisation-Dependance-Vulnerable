"""GitHub Advisory source implementation."""
import logging
from typing import List, Optional, Dict, Any
from core.config import make_client, GITHUB_ADVISORY_URL, GITHUB_TOKEN, settings
from core.types import NormalizedVulnerabilityDict
from core.logger import get_logger
from matching.cpe import parse_cpe
from sources.base import VulnerabilitySource, CachingSourceMixin

logger = get_logger(__name__)


class GitHubSource(VulnerabilitySource, CachingSourceMixin):
    """GitHub Security Advisory source for vulnerability data."""

    @property
    def name(self) -> str:
        return "GitHub"

    async def healthy(self) -> bool:
        """Check GitHub API health."""
        if not GITHUB_TOKEN or GITHUB_TOKEN.startswith("ghp_example"):
            # No token or placeholder token - mark as available (optional source)
            logger.debug("[GitHub] API token not configured (optional source, will skip queries)")
            return True
        
        async with make_client() as client:
            try:
                # Simple REST API endpoint check
                resp = await client.get(
                    "https://api.github.com/rate_limit",
                    headers={"Authorization": f"Bearer {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"},
                    timeout=5.0
                )
                is_healthy = resp.status_code == 200
                if not is_healthy:
                    logger.warning(f"[GitHub] Health check failed: status {resp.status_code}")
                return is_healthy
            except Exception as e:
                logger.warning(f"[GitHub] Health check failed: {e}")
                return False

    async def query(self, cpe: str) -> List[NormalizedVulnerabilityDict]:
        """Query GitHub for vulnerabilities affecting a CPE."""
        if not GITHUB_TOKEN:
            logger.debug(f"[GitHub] No token configured, skipping query for {cpe}")
            return []
        
        try:
            parsed = parse_cpe(cpe)
            vendor = parsed["vendor"]
            product = parsed["product"]
            
            # GitHub Advisory search is limited - we'll search by ecosystem and package
            # Map CPE to GitHub ecosystems
            ecosystem = self._get_ecosystem(vendor, product)
            if not ecosystem:
                logger.debug(f"[GitHub] Unknown ecosystem for {vendor}/{product}")
                return []
            
            results = await self._search_advisories(ecosystem, product)
            logger.info(f"[GitHub] Found {len(results)} vulnerabilities for {cpe}")
            return results
        except Exception as e:
            logger.error(f"[GitHub] query({cpe}) failed: {e}", exc_info=True)
            return []

    def _get_ecosystem(self, vendor: str, product: str) -> Optional[str]:
        """Map vendor/product to GitHub ecosystem."""
        # GitHub ecosystems: npm, RubyGems, PyPI, Maven, Nuget, pip, Composer, etc.
        ecosystems = {
            ("apache", "log4j"): "Maven",
            ("apache", "struts"): "Maven",
            ("apache", "commons"): "Maven",
            ("google", "guava"): "Maven",
            ("org.springframework", "spring"): "Maven",
            ("com.fasterxml", "jackson"): "Maven",
            ("org.hibernate", "hibernate"): "Maven",
            ("netty", "netty"): "Maven",
            ("alibaba", "fastjson"): "Maven",
            ("python", "*"): "PyPI",
            ("nodejs", "*"): "npm",
            ("ruby", "*"): "RubyGems",
            ("composer", "*"): "Composer",
            ("nuget", "*"): "Nuget",
        }
        
        # Try exact match first
        key = (vendor, product)
        if key in ecosystems:
            return ecosystems[key]
        
        # Try vendor-only match
        for (v, p), eco in ecosystems.items():
            if p == "*" and v == vendor:
                return eco
        
        return None

    async def _search_advisories(
        self, ecosystem: str, package_name: str
    ) -> List[NormalizedVulnerabilityDict]:
        """Search GitHub advisories using GraphQL."""
        try:
            cache_key = self._get_cache_key("search_advisories", ecosystem, package_name)
            cached = self._get_from_cache(cache_key)
            if cached is not None:
                return cached
            
            # GraphQL query for advisories
            query = """
            query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!) {
                securityAdvisories(first: 100, ecosystem: $ecosystem, package: $package) {
                    nodes {
                        ghsaId
                        cveId
                        summary
                        description
                        severity
                        cvss {
                            score
                            vectorString
                        }
                        publishedAt
                        updatedAt
                        references {
                            url
                        }
                    }
                }
            }
            """
            
            async with make_client() as client:
                resp = await client.post(
                    GITHUB_ADVISORY_URL,
                    json={
                        "query": query,
                        "variables": {
                            "ecosystem": ecosystem.upper(),
                            "package": package_name
                        }
                    },
                    headers={"Authorization": f"Bearer {GITHUB_TOKEN}"},
                    timeout=15.0
                )
                resp.raise_for_status()
                data = resp.json()
                
                if "errors" in data:
                    logger.warning(f"[GitHub] Query error: {data['errors']}")
                    return []
                
                results: List[NormalizedVulnerabilityDict] = []
                advisories = data.get("data", {}).get("securityAdvisories", {}).get("nodes", [])
                
                for advisory in advisories:
                    cve_id = advisory.get("cveId")
                    ghsa_id = advisory.get("ghsaId")
                    
                    if not cve_id:
                        cve_id = ghsa_id  # Use GHSA ID if CVE not available
                    
                    if cve_id:
                        cvss = advisory.get("cvss", {})
                        results.append({
                            "cve_ids": [cve_id],
                            "euvd_id": None,
                            "source": self.name,
                            "base_score": cvss.get("score"),
                            "base_vector": cvss.get("vectorString"),
                            "base_version": "3.1",
                            "description": advisory.get("summary", ""),
                            "references": [r.get("url", "") for r in advisory.get("references", []) if r.get("url")],
                            "affects_version": True,  # GitHub already confirms it
                            "raw": advisory,
                        })
                
                self._set_in_cache(cache_key, results)
                return results
        except Exception as e:
            logger.error(f"[GitHub] _search_advisories failed: {e}", exc_info=True)
            return []
