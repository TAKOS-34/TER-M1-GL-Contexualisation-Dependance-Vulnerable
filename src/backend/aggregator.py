"""
DEPRECATED: Use services.aggregator.Aggregator instead.

This file is kept for backward compatibility.
"""
from services.aggregator import Aggregator as _Aggregator
from services.aggregator import logger

# Re-export for backward compatibility
Aggregator = _Aggregator

__all__ = ["Aggregator"]
