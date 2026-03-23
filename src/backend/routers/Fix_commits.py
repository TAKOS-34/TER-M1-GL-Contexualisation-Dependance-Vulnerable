import logging
import re
from typing import Union, Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, Query, APIRouter, Depends
import httpx
from pydantic import BaseModel
import requests
from sqlalchemy.orm import Session
from sqlalchemy.sql import text
from models import FixCommit, CveItem, Reference, CvssMetric, Node, CpeMatch, Description, get_db 
import os

router = APIRouter()

GITHUB_API_URL = "https://api.github.com"
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "votre_token") # Utiliser env var

class CommitResponse(BaseModel):
    commit_id: str
    message: str
    patch: str
    issue: Optional[str]

def get_issue_from_commit_message(message):
    if "issue#" in message:
        return message.split("issue#")[1].split()[0]
    return None

def extract_repo_info_from_url(url: str):
    match = re.match(r'https://github.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/commit/(?P<commit_id>[a-f0-9]+)', url)
    if match:
        return match.group('owner'), match.group('repo'), match.group('commit_id')
    raise ValueError("Invalid GitHub URL")

@router.get("/fix_commits/{cve_id}/")
def get_fix_commits_for_cve(cve_id: str, db: Session = Depends(get_db)):
    fix_commits = db.query(FixCommit).filter(FixCommit.cve_item_id == cve_id).all()
    if not fix_commits:
        return []
    return [
        {"id": commit.id, "cve_item_id": commit.cve_item_id, "commit_id": commit.commit_id, "patch": commit.patch}
        for commit in fix_commits
    ]
