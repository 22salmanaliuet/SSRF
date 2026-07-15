from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routers import scan, reports, defense, payloads, ports, cloud, exploit

app = FastAPI(
    title="SEDF Backend API",
    description="API for the SSRF Exploitation and Defense Framework",
    version="1.0.0"
)

# Configure CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(scan.router)
app.include_router(reports.router)
app.include_router(defense.router)
app.include_router(payloads.router)
app.include_router(ports.router)
app.include_router(cloud.router)
app.include_router(exploit.router)

@app.get("/")
async def root():
    return {"message": "SEDF API is running. Access /docs for Swagger UI."}
