#!/bin/bash

# ==============================================================================
# SEDF (SSRF Exploitation and Defense Framework) - Master Startup Script
# ==============================================================================
# This script starts the entire SEDF project (Lab, Backend, Frontend) with a 
# single command and ensures they are safely shut down when you exit.
# ==============================================================================

# ANSI Color Codes for beautiful output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo "  ███████╗███████╗██████╗ ███████╗  "
echo "  ██╔════╝██╔════╝██╔══██╗██╔════╝  "
echo "  ███████╗█████╗  ██║  ██║█████╗    "
echo "  ╚════██║██╔══╝  ██║  ██║██╔══╝    "
echo "  ███████║███████╗██████╔╝██║       "
echo "  ╚══════╝╚══════╝╚═════╝ ╚═╝       "
echo "  SSRF Exploitation & Defense Framework "
echo -e "${NC}"
echo -e "${YELLOW}[*] Initializing SEDF Master Startup Sequence...${NC}\n"

# ------------------------------------------------------------------------------
# 1. Graceful Shutdown Handler (Trap)
# ------------------------------------------------------------------------------
# This ensures that when you press CTRL+C, it kills backend and frontend,
# and asks if you want to shut down the docker lab.
cleanup() {
    echo -e "\n${RED}[!] Shutting down SEDF Framework...${NC}"
    
    # Kill the background jobs (Backend & Frontend)
    kill $(jobs -p) 2>/dev/null
    
    echo -e "${GREEN}[✓] Backend and Frontend stopped.${NC}"
    exit 0
}

# Bind the cleanup function to SIGINT (CTRL+C)
trap cleanup SIGINT

# ------------------------------------------------------------------------------
# 2. Start Vulnerable Lab (Docker)
# ------------------------------------------------------------------------------
echo -e "${BLUE}[+] Starting Vulnerable Lab (Docker)...${NC}"
if command -v docker &> /dev/null; then
    docker compose -f docker/docker-compose.yml up -d
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓] Vulnerable Lab is running on http://localhost:5000${NC}\n"
    else
        echo -e "${RED}[X] Failed to start Docker Lab. Is Docker running?${NC}\n"
    fi
else
    echo -e "${YELLOW}[!] Docker not found. Skipping Lab startup...${NC}\n"
fi

# ------------------------------------------------------------------------------
# 3. Start FastAPI Backend
# ------------------------------------------------------------------------------
echo -e "${BLUE}[+] Starting FastAPI Backend...${NC}"
if [ -d "backend" ]; then
    (cd backend && uvicorn main:app --reload --port 8000 > ../backend.log 2>&1) &
    # Wait a moment for it to start
    sleep 2
    echo -e "${GREEN}[✓] Backend is running on http://localhost:8000${NC}"
    echo -e "    (Backend logs are being saved to backend.log)\n"
else
    echo -e "${RED}[X] Backend directory not found!${NC}\n"
fi

# ------------------------------------------------------------------------------
# 4. Start React Frontend
# ------------------------------------------------------------------------------
echo -e "${BLUE}[+] Starting React Frontend...${NC}"
if [ -d "frontend" ]; then
    (cd frontend && npm run dev > ../frontend.log 2>&1) &
    # Wait a moment for it to start
    sleep 3
    echo -e "${GREEN}[✓] Frontend is running on http://localhost:5173${NC}"
    echo -e "    (Frontend logs are being saved to frontend.log)\n"
else
    echo -e "${RED}[X] Frontend directory not found!${NC}\n"
fi

# ------------------------------------------------------------------------------
# 5. Success Message
# ------------------------------------------------------------------------------
echo -e "${YELLOW}======================================================${NC}"
echo -e "${GREEN}🚀 SEDF is fully operational!${NC}"
echo -e "🌐 Open your browser and go to: ${CYAN}http://localhost:5173${NC}"
echo -e "${YELLOW}======================================================${NC}"
echo -e "Press ${RED}CTRL+C${NC} at any time to safely shut down all services."

# Wait indefinitely to keep the script running so the trap can catch CTRL+C
wait
