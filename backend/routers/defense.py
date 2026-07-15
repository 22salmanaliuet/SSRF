from fastapi import APIRouter
from typing import Dict, Any
import argparse
import sys
import os

from models.report_models import DefenseTestRequest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from sedf.modules.defense import DefenseChecker
from sedf.reporting.reporter import Reporter

router = APIRouter(prefix="/defense", tags=["defense"])

class MockReporter(Reporter):
    def __init__(self, args):
        super().__init__(args)
        self.logs = []
    
    def add_finding(self, finding):
        super().add_finding(finding)

@router.post("/test")
async def test_defense(req: DefenseTestRequest):
    args = argparse.Namespace(
        url=req.target_url,
        defense=True,
        safe_mode=True,
        timeout=10,
        headers=None,
        proxy=None,
        method="GET",
        cookies=None
    )
    reporter = MockReporter(args)
    checker = DefenseChecker(args, reporter)
    # the existing logic probably prints to terminal. 
    # we just run it and return findings (or we can capture stdout).
    checker.run()
    
    # Just returning the findings added to reporter for now.
    vulns = []
    for f in reporter.findings:
        vulns.append({
            "url": f.url,
            "payload": f.payload,
            "severity": f.severity.value,
            "evidence": f.evidence
        })
    
    return {"message": "Defense test complete", "results": vulns}
