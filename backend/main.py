from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routers import scan, payloads, defense, reports, cloud, ports

app = FastAPI(
    title="SEDF Web API",
    description="API for SSRF Exploitation and Defense Framework",
    version="1.0.0"
)

# Enable CORS for React Frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan.router)
app.include_router(payloads.router)
app.include_router(defense.router)
app.include_router(reports.router)
app.include_router(cloud.router)
app.include_router(ports.router)

@app.get("/")
async def root():
    return {"message": "SEDF API is running. Access /docs for Swagger UI."}
