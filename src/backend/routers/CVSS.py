from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from transformers import pipeline
from cvss import CVSS3, CVSS4

router = APIRouter()

classifier = pipeline("zero-shot-classification", model="valhalla/distilbart-mnli-12-1")

class CVEInput(BaseModel):
    description: str

def get_prediction(description: str, label_name: str, options: list):
    res = classifier(description, candidate_labels=options)
    return res['labels'][0].upper()[0]

@router.post("/predict-cvss")
async def predict_cvss(data: CVEInput):
    desc = data.description
    if not desc:
        raise HTTPException(status_code=400, detail="Description manquante")

    m = {
        "AV": get_prediction(desc, "Vector", ["network", "local", "adjacent", "physical"]),
        "AC": get_prediction(desc, "Complexity", ["low", "high"]),
        "PR": get_prediction(desc, "Privileges", ["none", "low", "high"]),
        "UI": get_prediction(desc, "Interaction", ["none", "required"]),
        "S":  get_prediction(desc, "Scope", ["unchanged", "changed"]),
        "C":  get_prediction(desc, "Confidentiality", ["none", "low", "high"]),
        "I":  get_prediction(desc, "Integrity", ["none", "low", "high"]),
        "A":  get_prediction(desc, "Availability", ["none", "low", "high"]),
    }

    vec3 = f"CVSS:3.1/AV:{m['AV']}/AC:{m['AC']}/PR:{m['PR']}/UI:{m['UI']}/S:{m['S']}/C:{m['C']}/I:{m['I']}/A:{m['A']}"
    score3 = CVSS3(vec3).base_score

    ui4 = "A" if m['UI'] == "R" else "N"
    s_impact = "H" if m['S'] == "C" else "N"

    vec4 = (f"CVSS:4.0/AV:{m['AV']}/AC:{m['AC']}/AT:N/PR:{m['PR']}/UI:{ui4}/VC:{m['C']}/VI:{m['I']}/VA:{m['A']}/SC:{s_impact}/SI:{s_impact}/SA:{s_impact}")
    score4 = CVSS4(vec4).base_score

    return {
        "cvss_3.1": {"score": score3, "vector": vec3},
        "cvss_4.0": {"score": score4, "vector": vec4}
    }