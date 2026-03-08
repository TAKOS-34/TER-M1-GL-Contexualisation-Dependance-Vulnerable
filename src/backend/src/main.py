import os
import asyncio
import httpx
import logging
from datetime import datetime
from typing import List, Dict, Any
from fastapi import FastAPI, HTTPException, Query, Depends
from sqlalchemy.orm import Session
from sqlalchemy import or_

from models import Base, engine, get_db, CveItem, Reference, CvssV30, Node, CpeMatch, Description
from routers import CVSS, Fix_commits

# Ensure tables are created
Base.metadata.create_all(bind=engine)

app = FastAPI()
app.include_router(CVSS.router)
app.include_router(Fix_commits.router)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = os.getenv("NVD_API_KEY")

@app.get("/")
def read_root():
    return {"status": "ok", "message": "Pradeo Analyzer API"}

@app.get("/config_nodes_cpe_match/")
def read_data(cpe_criteria: List[str] = Query(...), db: Session = Depends(get_db)):
    try:
        print(f"request : {cpe_criteria}")
        all_results = []
        
        for requested_cpe in cpe_criteria:
            # 1. Tentative de match exact ou par préfixe (vendeur:produit)
            # On extrait le vendeur et le produit pour une recherche plus large
            parts = requested_cpe.split(':')
            if len(parts) >= 5:
                vendor = parts[3]
                product = parts[4]
                # On cherche les CPE qui ont le même vendeur et dont le produit ressemble
                # Ex: 'log4j' matchera 'log4j-core'
                search_pattern = f"cpe:2.3:a:{vendor}:{product.split('-')[0]}%"
                
                query_results = db.query(Node.cve_id, CpeMatch.criteria)\
                    .join(CpeMatch, Node.id == CpeMatch.node_id)\
                    .filter(or_(
                        CpeMatch.criteria == requested_cpe,
                        CpeMatch.criteria.like(search_pattern),
                        CpeMatch.criteria.like(f"cpe:2.3:a:{vendor}:{product}%")
                    ))\
                    .all()
                
                for r in query_results:
                    all_results.append({"cve_id": r[0], "cpe": r[1]})

        # Suppression des doublons
        unique_results = [dict(t) for t in {tuple(d.items()) for d in all_results}]
        print(f"results : {unique_results}")
        return unique_results
        
    except Exception as e:
        logging.error(f"Error in read_data: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

async def process_and_save_cve_data(data, db: Session):
    vulnerabilities = data.get('vulnerabilities', [])
    for vuln in vulnerabilities:
        cve_data = vuln.get('cve', {})
        cve_id = cve_data.get('id')
        if not cve_id: continue

        cve_item = db.query(CveItem).filter(CveItem.cve_id == cve_id).first()
        if not cve_item:
            cve_item = CveItem(
                cve_id=cve_id,
                published=datetime.fromisoformat(cve_data['published'].replace('Z', '+00:00')),
                lastModified=datetime.fromisoformat(cve_data['lastModified'].replace('Z', '+00:00')),
                sourceIdentifier=cve_data.get('sourceIdentifier'),
                vulnStatus=cve_data.get('vulnStatus')
            )
            db.add(cve_item)
            db.flush()

        for config_data in cve_data.get('configurations', []):
            for node_data in config_data.get('nodes', []):
                node = Node(cve_id=cve_id, operator=node_data.get('operator'), negate=node_data.get('negate'))
                db.add(node)
                db.flush()
                for cpe_m in node_data.get('cpeMatch', []):
                    db.add(CpeMatch(
                        node_id=node.id,
                        vulnerable=cpe_m['vulnerable'],
                        criteria=cpe_m['criteria'],
                        matchCriteriaId=cpe_m.get('matchCriteriaId'),
                        versionStartIncluding=cpe_m.get('versionStartIncluding'),
                        versionEndIncluding=cpe_m.get('versionEndIncluding')
                    ))
    db.commit()

@app.get("/initial-population")
async def initial_population(db: Session = Depends(get_db)):
    async with httpx.AsyncClient() as client:
        params = {"resultsPerPage": 50}
        if API_KEY: params["apiKey"] = API_KEY
        resp = await client.get(NVD_API_URL, params=params)
        if resp.status_code == 200:
            await process_and_save_cve_data(resp.json(), db)
            return {"message": "Success"}
    return {"message": "Failed"}
