import logging
import os
from typing import List, Dict, Any
from fastapi import FastAPI, HTTPException, Query, APIRouter, Depends
from sqlalchemy.future import select
from sqlalchemy.orm import Session
from models import FixCommit, CveItem, Reference, CvssV30, Node, CpeMatch, Description, get_db
import requests

router = APIRouter()

# Define mappings from model labels to CVSS values
LABEL_MAPPINGS = {
    "attackVector": {
        "LABEL_0": "NETWORK",
        "LABEL_1": "ADJACENT",
        "LABEL_2": "LOCAL",
        "LABEL_3": "PHYSICAL"
    },
    "attackComplexity": {
        "LABEL_0": "LOW",
        "LABEL_1": "HIGH"
    },
    "privilegesRequired": {
        "LABEL_0": "NONE",
        "LABEL_1": "LOW",
        "LABEL_2": "HIGH"
    },
    "userInteraction": {
        "LABEL_0": "NONE",
        "LABEL_1": "REQUIRED"
    },
    "scope": {
        "LABEL_0": "UNCHANGED",
        "LABEL_1": "CHANGED"
    },
    "confidentialityImpact": {
        "LABEL_0": "NONE",
        "LABEL_1": "LOW",
        "LABEL_2": "HIGH"
    },
    "integrityImpact": {
        "LABEL_0": "NONE",
        "LABEL_1": "LOW",
        "LABEL_2": "HIGH"
    },
    "availabilityImpact": {
        "LABEL_0": "NONE",
        "LABEL_1": "LOW",
        "LABEL_2": "HIGH"
    }
}

AV_VALUES = {"NETWORK": 0.85, "ADJACENT": 0.62, "LOCAL": 0.55, "PHYSICAL": 0.2}
AC_VALUES = {"LOW": 0.77, "HIGH": 0.44}
PR_VALUES = {"NONE": 0.85, "LOW": 0.62, "HIGH": 0.27}
UI_VALUES = {"NONE": 0.85, "REQUIRED": 0.62}
IMPACT_VALUES = {"NONE": 0, "LOW": 0.22, "HIGH": 0.56}

METRIC_URLS = {
    "attackVector": "https://api-inference.huggingface.co/models/ahmedbelhout/attackVector",
    "attackComplexity": "https://api-inference.huggingface.co/models/ahmedbelhout/attackComplexity",
    "privilegesRequired": "https://api-inference.huggingface.co/models/ahmedbelhout/privilegesRequired",
    "userInteraction": "https://api-inference.huggingface.co/models/ahmedbelhout/userInteraction",
    "scope": "https://api-inference.huggingface.co/models/ahmedbelhout/scope",
    "confidentialityImpact": "https://api-inference.huggingface.co/models/ahmedbelhout/confidentialityImpact",
    "integrityImpact": "https://api-inference.huggingface.co/models/ahmedbelhout/integrityImpact",
    "availabilityImpact": "https://api-inference.huggingface.co/models/ahmedbelhout/availabilityImpact"
}

HF_API_TOKEN = os.getenv("HF_API_TOKEN", "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")

def calculate_cvss_scores(metrics):
    av = AV_VALUES.get(metrics['attackVector'], 0.85)
    ac = AC_VALUES.get(metrics['attackComplexity'], 0.77)
    pr = PR_VALUES.get(metrics['privilegesRequired'], 0.85)
    ui = UI_VALUES.get(metrics['userInteraction'], 0.85)
    scope = metrics['scope']
    conf_impact = IMPACT_VALUES.get(metrics['confidentialityImpact'], 0)
    integ_impact = IMPACT_VALUES.get(metrics['integrityImpact'], 0)
    avail_impact = IMPACT_VALUES.get(metrics['availabilityImpact'], 0)

    exploitability_score = 8.22 * av * ac * pr * ui
    impact = 1 - ((1 - conf_impact) * (1 - integ_impact) * (1 - avail_impact))
    if scope == "CHANGED":
        impact *= 1.08
    impact_score = round(impact, 1)
    base_score = round(min(impact_score + exploitability_score, 10), 1)
    return base_score, exploitability_score, impact_score

def predict_metric(metric: str, description: str) -> str:
    url = METRIC_URLS.get(metric)
    if not url:
        raise HTTPException(status_code=400, detail=f"Invalid metric: {metric}")
    headers = {"Authorization": f"Bearer {HF_API_TOKEN}"}
    payload = {"inputs": description}
    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        result = response.json()
        top_label = max(result, key=lambda x: x['score'])['label']
        mapped_value = LABEL_MAPPINGS[metric].get(top_label, "UNKNOWN")
        return mapped_value
    except Exception as e:
        return "UNKNOWN"

def predict_metrics(description: str) -> Dict[str, str]:
    return {m: predict_metric(m, description) for m in METRIC_URLS.keys()}

@router.post("/process-cvss-cves/")
async def process_all_cves(db: Session = Depends(get_db)):
    cves = db.query(CveItem).all()
    results = []
    for cve in cves:
        cvss_exists = db.query(CvssV30).filter(CvssV30.cve_item_id == cve.cve_id).first()
        if not cvss_exists:
            results.append(f"CVSS missing for {cve.cve_id}")
        else:
            results.append(f"CVSS exists for {cve.cve_id}")
    return {"results": results}

@router.get("/cve/{cve_id}/base_score/")
async def get_cve_base_score(cve_id: str, db: Session = Depends(get_db)):
    cvss_data = db.query(CvssV30).filter(CvssV30.cve_item_id == cve_id).first()
    if not cvss_data:
        raise HTTPException(status_code=404, detail=f"CVSS data not found for CVE: {cve_id}")
    base_score = cvss_data.cvssData.get("baseScore")
    if base_score is None:
        raise HTTPException(status_code=404, detail=f"Base score not found for CVE: {cve_id}")
    return {"cve_id": cve_id, "base_score": base_score}
