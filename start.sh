#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  RegentClaw — Start (preserves existing data)
#  Starts all services without wiping the database.
#  Use reset.sh for a full wipe + reseed.
#
#  Usage:  ./start.sh
# ─────────────────────────────────────────────────────────────────────────────
set -e

CYAN='\033[0;36m'; GREEN='\033[0;32m'; RED='\033[0;31m'; BOLD='\033[1m'; RESET='\033[0m'

step() { echo -e "\n${CYAN}${BOLD}▶ $1${RESET}"; }
ok()   { echo -e "  ${GREEN}✅ $1${RESET}"; }

echo -e "\n${BOLD}  RegentClaw — Starting${RESET}\n"

cd "$(dirname "$0")"

step "Starting services"
docker compose up -d
ok "Services started"

step "Waiting for backend"
MAX=60; COUNT=0
until curl -sf http://localhost:8000/health > /dev/null 2>&1; do
  COUNT=$((COUNT+1))
  if [ $COUNT -ge $MAX ]; then
    echo -e "\n  ${RED}❌ Backend not ready. Check: docker compose logs backend${RESET}"
    exit 1
  fi
  printf "  Waiting… %ds\r" "$COUNT"
  sleep 1
done
ok "Backend is healthy"

echo ""
echo -e "${GREEN}${BOLD}  ✅ RegentClaw is running!${RESET}"
echo ""
echo -e "  ${BOLD}Frontend:${RESET}  http://localhost:3000"
echo -e "  ${BOLD}Backend:${RESET}   http://localhost:8000"
echo -e "  ${BOLD}API Docs:${RESET}  http://localhost:8000/docs"
echo ""
echo -e "  ${CYAN}Logs:${RESET}  docker compose logs -f"
echo -e "  ${CYAN}Stop:${RESET}  docker compose down"
echo ""
