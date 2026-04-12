"""CVSS Prediction package - machine learning for CVSS scoring."""
from .cvss_prediction import predict_cvss_score
from .parse_nvd_json_to_csv import parse_nvd_json_to_csv

__all__ = [
    "predict_cvss_score",
    "parse_nvd_json_to_csv",
]
