from pydantic import BaseModel
from fastapi import APIRouter
import argparse
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from sedf.modules.port_scanner import SSRFPortScanner
from sedf.utils.http_client import HTTPClient

router = APIRouter(prefix="/ports", tags=["ports"])

class PortScanRequest(BaseModel):
    target_url: str
    ports: str = "22,80,443,3306,6379,8080"
    internal_ip: str = "127.0.0.1"

@router.post("/scan")
async def scan_ports(req: PortScanRequest):
    args = argparse.Namespace(
        url=req.target_url,
        ports=req.ports,
        internal_ip=req.internal_ip,
        timeout=10,
        headers=None,
        proxy=None,
        method="GET",
        safe_mode=True
    )
    client = HTTPClient(args)
    scanner = SSRFPortScanner(args, client)
    
    # Run the scanner
    results = scanner.scan(base_url_template=req.target_url)
    
    # Convert results to dictionaries
    data = [
        {
            "port": r.port,
            "state": r.state,
            "service": r.service,
            "evidence": r.evidence,
            "response_time": r.response_time
        }
        for r in results
    ]
    
    open_count = sum(1 for r in results if r.state == "open")
    
    return {
        "status": "success",
        "message": f"Port scan complete. {open_count}/{len(results)} port(s) open.",
        "data": data
    }
