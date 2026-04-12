"""Matching package - CPE and version matching utilities."""
from .cpe import parse_cpe, resolve_euvd_names, cpe_to_osv_package
from .version import version_is_affected, item_affects_version, _parse_version_safe

__all__ = [
    "parse_cpe",
    "resolve_euvd_names",
    "cpe_to_osv_package",
    "version_is_affected",
    "item_affects_version",
    "_parse_version_safe",
]
