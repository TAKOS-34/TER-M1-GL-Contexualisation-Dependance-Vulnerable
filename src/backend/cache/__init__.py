"""Cache package - caching and persistence utilities."""
from .writer import write_normalized, store_unknown_marker
from .reader import get_cached_vulnerabilities

__all__ = [
    "write_normalized",
    "store_unknown_marker",
    "get_cached_vulnerabilities",
]
