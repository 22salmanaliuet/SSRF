from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class Vulnerability(BaseModel):
    url: str
    payload: str
    category: str
    severity: str
    response_code: int
    response_time: float
    evidence: str

class ScanRequest(BaseModel):
    target_url: str
    scan_mode: str = "basic"
    payload_categories: List[str] = []
    timeout: int = 10
    enable_blind_ssrf: bool = False
    enable_port_scan: bool = False
    oob_callback_url: Optional[str] = None

class ScanResult(BaseModel):
    scan_id: str
    target_url: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str
    vulnerabilities: List[Vulnerability]
