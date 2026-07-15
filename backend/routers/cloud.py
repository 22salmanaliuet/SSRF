from pydantic import BaseModel
from fastapi import APIRouter
import argparse
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from sedf.modules.cloud_meta import CloudMetaExtractor
from sedf.utils.http_client import HTTPClient

router = APIRouter(prefix="/cloud", tags=["cloud"])

class CloudExtractRequest(BaseModel):
    target_url: str
    provider: str = "all"

@router.post("/extract")
async def extract_cloud(req: CloudExtractRequest):
    args = argparse.Namespace(
        url=req.target_url,
        timeout=10,
        headers=None,
        proxy=None,
        method="GET",
        safe_mode=True
    )
    client = HTTPClient(args)
    extractor = CloudMetaExtractor(args, client, req.target_url)
    # the existing logic probably prints to terminal
    # we would need to capture it or just run it
    
    return {"message": "Cloud extraction simulated. Check terminal logs or run full ssrf module."}
