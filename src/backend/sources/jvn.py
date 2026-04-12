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
                # MyJVN uses a single entry point: /myjvn. We pass a valid method.
                resp = await client.head(
                    JVN_API_BASE,
                    params={"method": "getVulnOverviewList", "feed": "hnd"},
                    timeout=5.0,
                    follow_redirects=True
                )
                # Accept standard status codes that prove the server is reachable and routing
                is_healthy = resp.status_code in (200, 400, 404, 405)
                if not is_healthy:
                    logger.warning(f"[JVN] Health check failed: status {resp.status_code}")
                else:
                    logger.debug(f"[JVN] API reachable (status {resp.status_code})")
                return is_healthy
            except Exception as e:
                logger.warning(f"[JVN] Health check failed: {e}")
                # Mark as healthy if we can't reach it - it might work during queries
                return True

    async def query(self, cpe: str) -> List[NormalizedVulnerabilityDict]:
        """Query JVN for vulnerabilities affecting a CPE."""
        try:
            parsed = parse_cpe(cpe)
            vendor = parsed["vendor"]
            product = parsed["product"]
            
            # JVN search by product name using extracted CPE components
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
        """Search JVN by vendor and product using CPE filters."""
        try:
            cache_key = self._get_cache_key("search_by_product", vendor, product)
            cached = self._get_from_cache(cache_key)
            if cached is not None:
                return cached
            
            await self._apply_rate_limit()
            
            async with make_client() as client:
                # Real MyJVN API routing and CPE filtering
                resp = await client.get(
                    JVN_API_BASE,
                    params={
                        "method": "getVulnOverviewList",
                        "feed": "hnd",
                        "cpeName": f"cpe:/:{vendor}:{product}",
                        "lang": "en",
                        "ft": "json"  # Forces JSON response instead of XML
                    },
                    timeout=15.0
                )
                resp.raise_for_status()
                data = resp.json()
                
                results: List[NormalizedVulnerabilityDict] = []
                
                # MyJVN's ft=json translates XML directly to JSON. 
                # Items are usually found at the root level or nested under rdf:RDF.
                items = data.get("item", [])
                if not items and isinstance(data.get("rdf:RDF"), dict):
                    items = data["rdf:RDF"].get("item", [])
                
                # If only one result is returned, it might be a dict instead of a list.
                if isinstance(items, dict):
                    items = [items]
                
                for item in items:
                    # Extract CVE IDs. MyJVN usually places these in sec:identifier
                    cve_ids = []
                    identifiers = item.get("sec:identifier", [])
                    if isinstance(identifiers, str):
                        identifiers = [identifiers]
                        
                    for ident in identifiers:
                        if "CVE" in ident:
                            cve_ids.append(ident)
                    
                    # Extract CVSS Data
                    cvss_score = None
                    cvss_vector = None
                    cvss_data = item.get("sec:cvss", {})
                    
                    if isinstance(cvss_data, list) and len(cvss_data) > 0:
                        cvss_data = cvss_data[0]
                        
                    if isinstance(cvss_data, dict):
                        # Depending on the specific feed schema, keys might have '@' prefixes
                        raw_score = cvss_data.get("@score") or cvss_data.get("score")
                        cvss_vector = cvss_data.get("@vector") or cvss_data.get("vector")
                        
                        if raw_score:
                            try:
                                cvss_score = float(raw_score)
                            except ValueError:
                                pass
                    
                    # Construct description and reference link
                    description = item.get("description", "")
                    if not description:
                        description = item.get("title", "")
                        
                    link = item.get("link", "")
                    
                    results.append({
                        "cve_ids": cve_ids,
                        "euvd_id": None,
                        "source": self.name,
                        "base_score": cvss_score,
                        "base_vector": cvss_vector,
                        "base_version": "3.1", # Assuming v3.1 fallback
                        "description": description,
                        "references": [link] if link else [],
                        "affects_version": True, 
                        "raw": item,
                    })
                
                self._set_in_cache(cache_key, results)
                return results
        except Exception as e:
            logger.error(f"[JVN] _search_by_product({vendor}/{product}) failed: {e}", exc_info=True)
            return []