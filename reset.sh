#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  RegentClaw — Full Reset & Start
#  Wipes all data, rebuilds images, seeds everything fresh.
#
#  Usage:  ./reset.sh
# ─────────────────────────────────────────────────────────────────────────────
set -e

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

step()  { echo -e "\n${CYAN}${BOLD}▶ $1${RESET}"; }
ok()    { echo -e "  ${GREEN}✅ $1${RESET}"; }
warn()  { echo -e "  ${YELLOW}⚠  $1${RESET}"; }
info()  { echo -e "  ${BOLD}$1${RESET}"; }

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e "${BOLD}"
echo "  ██████╗ ███████╗ ██████╗ ███████╗███╗   ██╗████████╗"
echo "  ██╔══██╗██╔════╝██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝"
echo "  ██████╔╝█████╗  ██║  ███╗█████╗  ██╔██╗ ██║   ██║   "
echo "  ██╔══██╗██╔══╝  ██║   ██║██╔══╝  ██║╚██╗██║   ██║   "
echo "  ██║  ██║███████╗╚██████╔╝███████╗██║ ╚████║   ██║   "
echo "  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   "
echo ""
echo -e "  ${CYAN}CLAW${RESET}${BOLD}  Zero Trust Security Ecosystem — Full Reset${RESET}"
echo ""
echo -e "${YELLOW}  ⚠  This will WIPE all data and rebuild from scratch.${RESET}"
echo ""

# ── Confirm ───────────────────────────────────────────────────────────────────
read -p "  Continue? [y/N] " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo -e "  ${RED}Aborted.${RESET}"
  exit 0
fi

cd "$(dirname "$0")"

# ── Step 1: Tear down ─────────────────────────────────────────────────────────
step "Stopping and removing containers + volumes"
docker compose down --volumes --remove-orphans 2>&1 | grep -v "^$" | sed 's/^/  /'
ok "Containers and volumes removed"

# ── Step 2: Build ─────────────────────────────────────────────────────────────
step "Building images"
docker compose build --no-cache 2>&1 | grep -E "(Step|=>|Successfully|ERROR|error)" | sed 's/^/  /' || true
ok "Images built"

# ── Step 3: Start services ────────────────────────────────────────────────────
step "Starting services (db, redis, backend, frontend)"
docker compose up -d
ok "Services started"

# ── Step 4: Wait for backend ──────────────────────────────────────────────────
step "Waiting for backend to be ready"
MAX=60; COUNT=0
until curl -sf http://localhost:8000/health > /dev/null 2>&1; do
  COUNT=$((COUNT+1))
  if [ $COUNT -ge $MAX ]; then
    echo -e "\n  ${RED}❌ Backend did not start after ${MAX}s. Check logs:${RESET}"
    echo -e "     docker compose logs backend"
    exit 1
  fi
  printf "  Waiting… %ds\r" "$COUNT"
  sleep 1
done
ok "Backend is healthy"

# ── Step 5: Migrations ────────────────────────────────────────────────────────
step "Running database migrations"
# Core tables are created by SQLAlchemy on startup.
# These migrations handle column additions and new tables.
docker compose exec -T backend python migrate_connectors_v2.py  2>&1 | sed 's/^/  /'
docker compose exec -T backend python migrate_policy_packs.py   2>&1 | sed 's/^/  /'
docker compose exec -T backend python migrate_workflows.py      2>&1 | sed 's/^/  /'
ok "Migrations complete"

# ── Step 6: Seed data ─────────────────────────────────────────────────────────
step "Seeding all data (--reset)"
echo ""
info "  Policies…"
docker compose exec -T backend python seed_policies_expanded.py --reset 2>&1 | grep -E "(✅|↻|Done|Error)" | sed 's/^/    /'
info "  Agents…"
docker compose exec -T backend python seed_agents.py --reset 2>&1 | grep -E "(✅|↻|Done|Error)" | sed 's/^/    /'
info "  Connectors…"
docker compose exec -T backend python seed_connectors.py --reset 2>&1 | grep -E "(✅|↻|Done|Error)" | sed 's/^/    /'
info "  Policy Packs…"
docker compose exec -T backend python seed_policy_packs.py --reset 2>&1 | grep -E "(✅|↻|Done|Error)" | sed 's/^/    /'
info "  Workflows…"
docker compose exec -T backend python seed_workflows.py --reset 2>&1 | grep -E "(✅|↻|Done|Error)" | sed 's/^/    /'
info "  Example Orchestrations (Cloud Vuln + Compliance Sweep)…"
docker compose exec -T backend python seed_example_orchestrations.py --reset 2>&1 | grep -E "(✅|↻|Created|Updated|Pipeline|Compliance|Error)" | sed 's/^/    /'
ok "All data seeded"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}  ✅ RegentClaw is ready!${RESET}"
echo ""
echo -e "  ${BOLD}Frontend:${RESET}  http://localhost:3000"
echo -e "  ${BOLD}Backend:${RESET}   http://localhost:8000"
echo -e "  ${BOLD}API Docs:${RESET}  http://localhost:8000/docs"
echo ""
echo -e "  ${CYAN}Logs:${RESET}  docker compose logs -f"
echo -e "  ${CYAN}Stop:${RESET}  docker compose down"
echo ""
