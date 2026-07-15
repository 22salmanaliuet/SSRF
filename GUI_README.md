# SEDF - Full-Stack Web GUI

This is the full-stack web-based Graphical User Interface for SEDF (SSRF Exploitation and Defense Framework), built with **FastAPI** (Python) and **React** (Vite + TailwindCSS).

## Setup Instructions

### 1. Start the Docker Lab (Optional but recommended)
To test the scanner locally against the vulnerable endpoints:
```bash
docker-compose -f docker/docker-compose.yml up -d
```
*The vulnerable app will be available at `http://localhost:5000`*

### 2. Backend Setup (FastAPI)
The backend wraps the existing SEDF Python classes and provides REST endpoints and WebSockets.

```bash
# From the root of the project:
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```
*API Docs (Swagger UI) available at: `http://localhost:8000/docs`*

### 3. Frontend Setup (React/Vite)
The frontend is a modern dark-themed single-page application.

```bash
# In a new terminal, from the root of the project:
cd frontend
npm install
npm run dev
```
*The GUI will be accessible at: `http://localhost:5173`*

## Features Implemented
- **Dashboard**: High-level statistics and Recharts integration.
- **Active Scanner**: Real-time WebSocket streaming of terminal output and findings.
- **Defense Tester**: Side-by-side comparison of SSRF mitigations.
- **Payload Library**: Browse and copy over 100+ built-in payloads.
- **Cloud Metadata Extractor**: Test extraction of AWS/GCP/Azure instance credentials.
- **Reports**: View and export historical JSON scan data.
