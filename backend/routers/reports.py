from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from typing import List
import os
import glob
import json

router = APIRouter(prefix="/reports", tags=["reports"])

@router.get("/")
async def list_reports():
    # Reports are typically saved in the current dir as sedf_report.json, etc.
    # We will look for JSON reports
    report_files = glob.glob("*.json")
    reports = []
    for file in report_files:
        if file == "juiceshop_report.json" or file.startswith("sedf_report"):
            try:
                with open(file, "r") as f:
                    data = json.load(f)
                    findings_count = data.get("total_findings", 0)
                    findings = data.get("findings", [])
                    severities = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
                    for finding in findings:
                        sev = finding.get("severity", "LOW").upper()
                        if sev in severities:
                            severities[sev] += 1
            except Exception:
                findings_count = 0
                severities = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            reports.append({
                "id": file, 
                "name": file, 
                "total_findings": findings_count,
                "severities": severities
            })
    return reports

@router.get("/{report_id}")
async def get_report(report_id: str):
    if not os.path.exists(report_id) or not report_id.endswith(".json"):
        raise HTTPException(status_code=404, detail="Report not found")
    
    with open(report_id, "r") as f:
        data = json.load(f)
    return data

@router.delete("/{report_id}")
async def delete_report(report_id: str):
    if not os.path.exists(report_id):
        raise HTTPException(status_code=404, detail="Report not found")
    os.remove(report_id)
    return {"message": "Report deleted"}

@router.get("/{report_id}/export")
async def export_report(report_id: str, format: str = "json"):
    base = os.path.splitext(report_id)[0]
    target_file = f"{base}.{format}"
    if not os.path.exists(target_file):
        raise HTTPException(status_code=404, detail=f"Report format {format} not found")
    
    return FileResponse(target_file, media_type="application/octet-stream", filename=target_file)
