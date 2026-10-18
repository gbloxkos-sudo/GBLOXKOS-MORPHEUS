#!/bin/bash
# ============================================================
# GBLOXKOS MORPHEUS V.1 - ADVANCED SAFE STOP
# ============================================================
# Stops the Flask app AND all associated processes (Ollama + model
# runners) safely: graceful SIGTERM first, hard SIGKILL only as a
# fallback. Cleans up pid/port files and verifies nothing remains.
#
# Usage: ./stop.sh [--force] [--keep-ollama]
#   --force        Kill processes immediately with SIGKILL
#   --keep-ollama  Leave Ollama running (default: stop it too)
#   env: STOP_OLLAMA=false  also keeps Ollama running
# ============================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PID_FILE="$SCRIPT_DIR/app.pid"
OLLAMA_PID_FILE="$SCRIPT_DIR/ollama.pid"
PORT_FILE="$SCRIPT_DIR/app.port"

# Parse arguments
FORCE=false
KEEP_OLLAMA=false
for arg in "$@"; do
    case "$arg" in
        force|--force|-f) FORCE=true ;;
        --keep-ollama|-k) KEEP_OLLAMA=true ;;
    esac
done
if [ "${STOP_OLLAMA:-true}" = "false" ] || [ "${STOP_OLLAMA:-true}" = "0" ]; then
    KEEP_OLLAMA=true
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[$(date '+%H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# ------------------------------------------------------------------
# stop_pid <pid> <name> <max-wait-s> — graceful TERM, escalate to KILL.
# Recursively signals child processes too.
# ------------------------------------------------------------------
stop_pid() {
    local pid="$1" name="$2" wait_s="${3:-8}" sig="TERM"
    if [ "$FORCE" = "true" ]; then sig="KILL"; wait_s=1; fi
    if ! kill -0 "$pid" 2>/dev/null; then
        warn "$name (PID $pid) not running"
        return 1
    fi
    log "Stopping $name (PID $pid)..."

    # Signal children first (top-down) so model runners shut down gracefully.
    local children
    children=$(pgrep -P "$pid" 2>/dev/null || true)
    for child in $children; do
        kill -"$sig" "$child" 2>/dev/null || true
    done
    kill -"$sig" "$pid" 2>/dev/null || true

    # Wait for graceful exit.
    local waited=0
    while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt "$wait_s" ]; do
        sleep 1
        waited=$((waited + 1))
    done

    # Escalate to SIGKILL only if it refused to exit.
    if kill -0 "$pid" 2>/dev/null; then
        warn "$name (PID $pid) did not exit cleanly, forcing..."
        kill -KILL "$pid" 2>/dev/null || true
        pkill -KILL -P "$pid" 2>/dev/null || true
        sleep 1
    fi

    if kill -0 "$pid" 2>/dev/null; then
        error "$name (PID $pid) could not be stopped"
        return 1
    fi
    success "$name stopped"
    return 0
}

log "Stopping GBLOXKOS MORPHEUS V.1..."
echo ""

# ============================================================
# 1) STOP FLASK APP
# ============================================================
if [ -f "$PID_FILE" ] && [ -n "$(cat "$PID_FILE" 2>/dev/null)" ]; then
    APP_PID=$(cat "$PID_FILE")
    if kill -0 "$APP_PID" 2>/dev/null; then
        stop_pid "$APP_PID" "Flask app" 5
    else
        warn "Flask app (PID $APP_PID) not running"
    fi
    rm -f "$PID_FILE"
else
    warn "No app PID file found"
fi

# Credible fallback: any app.py process from this directory.
for pid in $(pgrep -f "python3 .*app\.py" 2>/dev/null); do
    if ls -l "/proc/$pid/cwd" 2>/dev/null | grep -q "$SCRIPT_DIR"; then
        stop_pid "$pid" "Flask app (orphan)" 5
    fi
done

# Clear anything still bound to the app port.
if [ -f "$PORT_FILE" ]; then
    APP_PORT=$(cat "$PORT_FILE" 2>/dev/null)
else
    APP_PORT="5000"
fi
if curl -s --max-time 2 "http://localhost:$APP_PORT/api/status" &>/dev/null; then
    log "Application still responding on port $APP_PORT, clearing..."
    if command -v fuser &>/dev/null; then
        fuser -k "$APP_PORT"/tcp 2>/dev/null || true
    elif command -v lsof &>/dev/null; then
        lsof -ti :"$APP_PORT" | xargs -r kill -9 2>/dev/null || true
    fi
    sleep 1
    if curl -s --max-time 2 "http://localhost:$APP_PORT/api/status" &>/dev/null; then
        error "Port $APP_PORT still responding"
    else
        success "Port $APP_PORT cleared"
    fi
fi

# ============================================================
# 2) STOP OLLAMA + MODEL RUNNERS (advanced safe shutdown)
# ============================================================
# Ollama may be either (a) user-started by start.sh (we own it and can stop it)
# or (b) a system service owned by another user (e.g. 'ollama'). We always
# attempt a graceful stop of what we own; for foreign-owned processes we only
# escalate via sudo when passwordless sudo is available, otherwise we report
# them clearly instead of hanging or crash-killing a system service.
if [ "$KEEP_OLLAMA" = "true" ]; then
    log "Keeping Ollama running (--keep-ollama or STOP_OLLAMA=false)"
else
    log "Stopping Ollama and model runners..."

    # Discover ollama processes: recorded PID + live processes.
    OLLAMA_PIDS=()
    if [ -f "$OLLAMA_PID_FILE" ] && [ -n "$(cat "$OLLAMA_PID_FILE" 2>/dev/null)" ]; then
        OLLAMA_PIDS+=("$(cat "$OLLAMA_PID_FILE")")
    fi
    while IFS= read -r pid; do
        [ -n "$pid" ] && OLLAMA_PIDS+=("$pid")
    done < <(pgrep -x ollama 2>/dev/null)
    while IFS= read -r pid; do
        [ -n "$pid" ] && OLLAMA_PIDS+=("$pid")
    done < <(pgrep -f "ollama serve" 2>/dev/null || true)

    # Emit the "not owned / needs root" notice only once.
    sudo_ok=false
    command -v sudo >/dev/null 2>&1 && ! ps -o user= -p "$$" 2>/dev/null | grep -q root && sudo -n true >/dev/null 2>&1 && sudo_ok=true

    if [ "${#OLLAMA_PIDS[@]}" -eq 0 ]; then
        warn "No Ollama process found"
    else
        for pid in $(printf '%s\n' "${OLLAMA_PIDS[@]}" | sort -u); do
            if kill -0 "$pid" 2>/dev/null; then
                stop_pid "$pid" "Ollama" 15
            elif ps -p "$pid" >/dev/null 2>&1; then
                # Alive but not signalable by us -> owned by another user.
                OLLAMA_OWNER=$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')
                if [ "$sudo_ok" = "true" ]; then
                    log "Ollama (PID $pid) is owned by '$OLLAMA_OWNER' - stopping via sudo..."
                    if sudo -n kill -TERM "$pid" 2>/dev/null; then
                        waited=0
                        while ps -p "$pid" >/dev/null 2>&1 && [ "$waited" -lt 15 ]; do sleep 1; waited=$((waited + 1)); done
                        if ps -p "$pid" >/dev/null 2>&1; then
                            sudo -n kill -KILL "$pid" 2>/dev/null || true
                            sleep 1
                        fi
                        if ps -p "$pid" >/dev/null 2>&1; then
                            error "Could not stop Ollama (PID $pid) even with sudo"
                        else
                            success "Ollama stopped via sudo"
                        fi
                    else
                        error "Could not stop Ollama (PID $pid) even with sudo"
                    fi
                else
                    warn "Ollama (PID $pid) runs as '$OLLAMA_OWNER' (not this user) - skipping. Stop it with: sudo systemctl stop ollama"
                fi
            else
                warn "Ollama (PID $pid) not running"
            fi
        done
    fi

    # Stop any model runner (llama-server / ollama runner) children we own.
    for pid in $(pgrep -f "llama-server|ollama runner" 2>/dev/null); do
        if kill -0 "$pid" 2>/dev/null; then
            stop_pid "$pid" "Model runner" 5
        fi
    done

    rm -f "$OLLAMA_PID_FILE"
fi

# ============================================================
# 3) CLEANUP
# ============================================================
log "Cleaning up state files..."
rm -f "$SCRIPT_DIR"/*.pid "$SCRIPT_DIR"/app.port 2>/dev/null || true
success "State files cleaned"

# ============================================================
# 4) VERIFY EVERYTHING STOPPED
# ============================================================
sleep 1
ISSUES=0

# App port must be dead.
if curl -s --max-time 2 "http://localhost:$APP_PORT/api/status" &>/dev/null; then
    error "Flask app still responding on port $APP_PORT"
    ISSUES=$((ISSUES + 1))
else
    success "Port $APP_PORT released"
fi

# No leftover app/ollama processes (unless we kept ollama).
REMAINING=0
if pgrep -f "python3 .*app\.py" >/dev/null 2>&1; then
    echo "  Warning: app.py process still present"
    REMAINING=$((REMAINING + 1))
fi
# Report Ollama status truthfully: it may be intentionally kept, or a system
# service owned by another user that requires root to stop.
OLLAMA_STILL_UP=false
if curl -s --max-time 2 http://localhost:11434/api/tags >/dev/null 2>&1; then
    OLLAMA_STILL_UP=true
fi
if [ "$KEEP_OLLAMA" = "false" ] && [ "$OLLAMA_STILL_UP" = "true" ]; then
    echo "  Note: Ollama is still serving (system service owned by '$(ps -o user= -C ollama 2>/dev/null | head -1)')."
    echo "        To stop it:  sudo systemctl stop ollama"
    REMAINING=$((REMAINING + 1))
fi

if [ "$ISSUES" -eq 0 ] && [ "$REMAINING" -eq 0 ]; then
    success "All processes stopped cleanly"
else
    warn "$ISSUES issue(s) and/or $REMAINING leftover process(es) - see above"
fi

echo ""
echo "=========================================="
echo "  GBLOXKOS MORPHEUS V.1 - Stopped"
echo "=========================================="
if [ "$KEEP_OLLAMA" = "true" ]; then
    echo "  Ollama: still running (kept)"
elif [ "$OLLAMA_STILL_UP" = "true" ]; then
    echo "  Ollama: still running (system service - sudo systemctl stop ollama)"
else
    echo "  Ollama: stopped"
fi
echo ""
echo "  To start again:  ./start.sh"
echo "  Force stop:      ./stop.sh --force"
echo "  Keep Ollama:     ./stop.sh --keep-ollama"
echo "=========================================="