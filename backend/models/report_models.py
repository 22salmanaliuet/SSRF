from pydantic import BaseModel
from typing import List

class DefenseTestRequest(BaseModel):
    target_url: str
    defenses: List[str]
