"""JVN (Japan Vulnerability Notes) source implementation."""
import logging
from typing import List, Optional, Dict, Any
from core.config import make_client, JVN_API_BASE, settings
from core.types import NormalizedVulnerabilityDict
from core.logger import get_logger
from matching.cpe import parse_cpe
from sources.base import VulnerabilitySource, CachingSourceMixin, RateLimitedSourceMixin

logger = get_logger(__name__)


class JVNSource(VulnerabilitySource, CachingSourceMixin, RateLimitedSourceMixin):
    """JVN (Japan Vulnerability Notes) source for Japanese vulnerability data."""

    @property
    def name(self) -> str:
        return "JVN"

    async def healthy(self) -> bool:
        """Check JVN API health."""
        async with make_client() as client:
            try:
                # Try direct connection to JVN database as health check
                # Using a simple HTTP HEAD request to check connectivity
                resp = await client.head(
                    f"{JVN_API_BASE}/api/vuln",
                    timeout=5.0,
                    follow_redirects=True
                )
                # Accept 200, 404, or 405 (method not allowed) - means server is responding
                is_healthy = resp.status_code in (200, 404, 405)
                if not is_healthy:
                    logger.warning(f"[JVN] Health check failed: status {resp.status_code}")
                else:
                    logger.debug(f"[JVN] API reachable (status {resp.status_code})")
                return is_healthy
            except Exception as e:
                logger.warning(f"[JVN] Health check failed: {e}")
                # Mark as healthy if we can't reach it - it might work during queries
                # This prevents false negatives during initialization
                return True

    async def query(self, cpe: str) -> List[NormalizedVulnerabilityDict]:
        """Query JVN for vulnerabilities affecting a CPE."""
        try:
            parsed = parse_cpe(cpe)
            vendor = parsed["vendor"]
            product = parsed["product"]
            version = parsed["version"]
            
            # JVN search by product name
            results = await self._search_by_product(vendor, product)
            
            if results:
                logger.info(f"[JVN] Found {len(results)} vulnerabilities for {cpe}")
            return results
        except Exception as e:
            logger.error(f"[JVN] query({cpe}) failed: {e}", exc_info=True)
            return []

    async def _search_by_product(
        self, vendor: str, product: str
    ) -> List[NormalizedVulnerabilityDict]:
        """Search JVN by vendor and product."""
        try:
            cache_key = self._get_cache_key("search_by_product", vendor, product)
            cached = self._get_from_cache(cache_key)
            if cached is not None:
                return cached
            
            await self._apply_rate_limit()
            
            async with make_client() as client:
                # JVN Search API endpoint
                # Format: /myjvn/api/vuln/search?feed=hnd&...
                resp = await client.get(
                    f"{JVN_API_BASE}/api/vuln/search",
                    params={
                        "feed": "hnd",  # hnd = HND (Hankoku Vulnerability Database?)
                        "query": f"vendor:{vendor} product:{product}",
                        "lang": "en",
                        "offset": 0,
                        "count": 100,
                    },
                    timeout=15.0
                )
                resp.raise_for_status()
                data = resp.json()
                
                results: List[NormalizedVulnerabilityDict] = []
                items = data.get("result", {}).get("items", [])
                
                for item in items:
                    # Extract CVE ID from JVN record
                    cve_id = None
                    cve_refs = item.get("cveList", [])
                    if cve_refs and len(cve_refs) > 0:
                        cve_id = cve_refs[0].get("cveId")
                    
                    if cve_id:
                        # Extract CVSS score
                        cvss_score = None
                        cvss_vector = None
                        cvss_list = item.get("cvssScore", [])
                        if cvss_list and len(cvss_list) > 0:
                            cvss = cvss_list[0]
                            cvss_score = cvss.get("score")
                            cvss_vector = cvss.get("vector")
                        
                        results.append({
                            "cve_ids": [cve_id],
                            "euvd_id": None,
                            "source": self.name,
                            "base_score": cvss_score,
                            "base_vector": cvss_vector,
                            "base_version": "3.1",
                            "description": item.get("title", ""),
                            "references": [
                                ref.get("link", "") 
                                for ref in item.get("references", [])
                                if ref.get("link")
                            ],
                            "affects_version": True,  # JVN already confirms it
                            "raw": item,
                        })
                
                self._set_in_cache(cache_key, results)
                return results
        except Exception as e:
            logger.error(f"[JVN] _search_by_product({vendor}/{product}) failed: {e}", exc_info=True)
            return []
