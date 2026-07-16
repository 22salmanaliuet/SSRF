import asyncio
import uuid
import json
import argparse
from datetime import datetime
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, BackgroundTasks, HTTPException
from typing import Dict

from models.scan_models import ScanRequest, ScanResult, Vulnerability
import sys
import os
import socket

# Add parent dir to path so we can import sedf
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from sedf.scanner import Scanner
from sedf.reporting.reporter import Reporter, Finding

router = APIRouter(prefix="/scan", tags=["scan"])

# In-memory store for active scans and their results
active_scans: Dict[str, dict] = {}

class WebSocketReporter(Reporter):
    """Custom reporter that pushes findings to an asyncio queue for WebSocket streaming."""
    def __init__(self, args, queue: asyncio.Queue, loop: asyncio.AbstractEventLoop):
        super().__init__(args)
        self.queue = queue
        self.loop = loop

    def log(self, message: str):
        data = {"type": "log", "message": message}
        asyncio.run_coroutine_threadsafe(self.queue.put(data), self.loop)

    def add_finding(self, finding: Finding):
        super().add_finding(finding)
        # Push to queue for websocket
        data = {
            "type": "result",
            "message": f"[VULN] {finding.severity.value} - {finding.payload}",
            "data": {
                "url": finding.url,
                "payload": finding.payload,
                "category": "Unknown", # Extrapolate if needed
                "severity": finding.severity.value,
                "response_code": finding.response_code,
                "response_time": finding.response_time,
                "evidence": finding.evidence
            }
        }
        asyncio.run_coroutine_threadsafe(self.queue.put(data), self.loop)

    def finalize(self):
        super().finalize()
        data = {"type": "done", "message": "Scan completed."}
        asyncio.run_coroutine_threadsafe(self.queue.put(data), self.loop)

def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]

def build_args_from_request(req: ScanRequest) -> argparse.Namespace:
    return argparse.Namespace(
        url=req.target_url,
        payloads="all" if req.scan_mode == "full" else "default",
        payload_file=None,
        params=None,
        oob_domain=req.oob_callback_url,
        callback_port=get_free_port(),
        blind=req.enable_blind_ssrf,
        exploit=False,
        module=None,
        ports="22,80,443" if req.enable_port_scan else "",
        internal_ip="127.0.0.1",
        exploit_ssrf=False,
        defense=False,
        threads=5,
        timeout=req.timeout,
        delay=0.0,
        proxy=None,
        headers=req.headers,
        method=req.method,
        data=req.data,
        cookies=None,
        output=None,
        format="json",
        verbose=True,
        quiet=False,
        extract=False,
        safe_mode=True,
        no_safe_mode=False,
        confirm=True,
        lab=False
    )

def run_scan_sync(scan_id: str, req: ScanRequest, queue: asyncio.Queue, main_loop: asyncio.AbstractEventLoop):
    try:
        args = build_args_from_request(req)
        reporter = WebSocketReporter(args, queue, main_loop)
        
        asyncio.run_coroutine_threadsafe(queue.put({"type": "log", "message": f"[*] Starting scan on {req.target_url}..."}), main_loop)
        scanner = Scanner(args, reporter)
        scanner.run()
        reporter.finalize()
        
        # Save results to memory
        active_scans[scan_id]["status"] = "complete"
        active_scans[scan_id]["completed_at"] = datetime.now()
        active_scans[scan_id]["vulnerabilities"] = reporter.findings
    except Exception as e:
        asyncio.run_coroutine_threadsafe(queue.put({"type": "error", "message": str(e)}), main_loop)
        active_scans[scan_id]["status"] = "error"

@router.post("/", response_model=Dict[str, str])
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    queue = asyncio.Queue()
    
    active_scans[scan_id] = {
        "request": request,
        "queue": queue,
        "status": "running",
        "started_at": datetime.now(),
        "completed_at": None,
        "vulnerabilities": []
    }
    
    # Get the running event loop before creating the thread
    main_loop = asyncio.get_running_loop()
    
    # Run scanner in background thread so it doesn't block the event loop
    import threading
    thread = threading.Thread(target=run_scan_sync, args=(scan_id, request, queue, main_loop))
    thread.start()
    
    return {"scan_id": scan_id}

@router.websocket("/ws/{scan_id}")
async def websocket_scan(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    if scan_id not in active_scans:
        await websocket.send_json({"type": "error", "message": "Scan ID not found"})
        await websocket.close()
        return

    queue = active_scans[scan_id]["queue"]
    try:
        while True:
            msg = await queue.get()
            await websocket.send_json(msg)
            if msg["type"] in ("done", "error"):
                break
    except WebSocketDisconnect:
        print(f"Client disconnected from scan {scan_id}")
    finally:
        await websocket.close()

@router.get("/{scan_id}", response_model=ScanResult)
async def get_scan_result(scan_id: str):
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    scan_data = active_scans[scan_id]
    vulns = []
    for f in scan_data["vulnerabilities"]:
        vulns.append(Vulnerability(
            url=f.url,
            payload=f.payload,
            category="SSRF",
            severity=f.severity.value,
            response_code=f.response_code,
            response_time=f.response_time,
            evidence=f.evidence
        ))
        
    return ScanResult(
        scan_id=scan_id,
        target_url=scan_data["request"].target_url,
        started_at=scan_data["request"].started_at if "started_at" in scan_data["request"].__dict__ else scan_data["started_at"],
        completed_at=scan_data["completed_at"],
        status=scan_data["status"],
        vulnerabilities=vulns
    )
