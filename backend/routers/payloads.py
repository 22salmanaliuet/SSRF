from fastapi import APIRouter
from typing import Dict, List
import argparse
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from sedf.payloads.generator import PayloadGenerator

router = APIRouter(prefix="/payloads", tags=["payloads"])

@router.get("/")
async def get_all_payloads():
    args = argparse.Namespace(payloads="all", payload_file=None)
    gen = PayloadGenerator(args)
    # PayloadGenerator usually gives a list. The cli expects all payloads.
    # Let's map them. The actual code just returns a flat list for "all".
    payloads = gen.get_payloads()
    return {"categories": ["default", "all", "http", "file", "gopher", "cloud", "bypass", "encoded"], "count": len(payloads)}

@router.get("/{category}", response_model=List[str])
async def get_payloads_by_category(category: str):
    args = argparse.Namespace(payloads=category, payload_file=None)
    gen = PayloadGenerator(args)
    return gen.get_payloads()
