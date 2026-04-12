import re
import logging
from packaging.version import Version, InvalidVersion

logger = logging.getLogger(__name__)


def _parse_version_safe(v: str) -> Version | None:
    if not v:
        return None
    v = str(v).strip()
    v = re.sub(r'^v', '', v, flags=re.IGNORECASE)
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

    pv = pv.replace("≤", "<=").replace("≥", ">=")
    pv = re.sub(r'^[A-Za-z][A-Za-z0-9_.\-]*\s+', '', pv).strip()
    pv = re.sub(r'\bbefore\b\s+', '< ', pv, flags=re.IGNORECASE)
    pv = re.sub(r'\.x\s+before\s+', ' < ', pv, flags=re.IGNORECASE)
    pv = re.sub(r'\s+to\s+', ' <= ', pv, flags=re.IGNORECASE)
    pv = re.sub(r'\s+-\s+', ' <= ', pv)
    pv = re.sub(r'(?<=[\d])\s+[A-Za-z].*$', '', pv).strip()
    pv = re.sub(r'(?<![A-Za-z])v(\d)', r'\1', pv)

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


def item_affects_version(euvd_item: dict, target_version: str,
                          product_hint: str = "") -> bool:
    products = euvd_item.get("enisaIdProduct", [])

    if not products:
        base_score = euvd_item.get("baseScore", -1)
        return base_score is not None and float(base_score) > 0

    hint_lower = product_hint.lower()

    for entry in products:
        product_name = entry.get("product", {}).get("name", "").lower()
        pv           = entry.get("product_version", "")

        # Skip FIPS/LTS variants when searching for standard library
        if hint_lower and "bcprov" in hint_lower:
            if any(v in product_name for v in ("fja", "fips", "lts")):
                continue
            if any(p in pv.lower() for p in ("bc-fja", "bc-lts", "bcpkix fips")):
                continue

        if hint_lower:
            if "fja"  in product_name and "fja"  not in hint_lower: continue
            if "fips" in product_name and "fips" not in hint_lower: continue
            if "lts"  in product_name and "lts"  not in hint_lower: continue

        if version_is_affected(pv, target_version):
            return True

    return False