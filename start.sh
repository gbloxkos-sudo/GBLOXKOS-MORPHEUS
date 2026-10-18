#!/bin/bash
# ============================================================
# GBLOXKOS MORPHEUS V.1 - START SCRIPT
# ============================================================
# Usage: ./start.sh [port]
#   port: Optional Flask port (default: 5000)
# ============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

FLASK_PORT=${1:-5000}
export FLASK_PORT
PID_FILE="$SCRIPT_DIR/app.pid"
OLLAMA_PID_FILE="$SCRIPT_DIR/ollama.pid"
PORT_FILE="$SCRIPT_DIR/app.port"
LOG_FILE="$SCRIPT_DIR/app.log"
ERR_FILE="$SCRIPT_DIR/app.err"

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

# ============================================================
# CHECK PREREQUISITES
# ============================================================
log "Checking prerequisites..."

# Check Python
if ! command -v python3 &>/dev/null; then
    error "Python 3 not found. Please install Python 3.8+"
    exit 1
fi
success "Python 3 found: $(python3 --version)"

# Check pip packages
log "Checking Python packages..."
for pkg in "flask" "flask_cors" "feedparser"; do
    if python3 -c "import $pkg" 2>/dev/null; then
        success "${pkg/_/-} installed"
    else
        warn "${pkg/_/-} not found, installing..."
        pip3 install "${pkg/_/-}" --quiet || warn "Could not auto-install ${pkg/_/-}; run: pip3 install ${pkg/_/-}"
    fi
done

# ============================================================
# STOP ANY RUNNING INSTANCES
# ============================================================
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE" 2>/dev/null)
    if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
        warn "Stopping existing app (PID: $OLD_PID)..."
        kill "$OLD_PID" 2>/dev/null || true
        sleep 2
        kill -9 "$OLD_PID" 2>/dev/null || true
    fi
    rm -f "$PID_FILE"
fi

# Kill anything on our port
if command -v lsof &>/dev/null && lsof -ti :$FLASK_PORT &>/dev/null; then
    warn "Killing process on port $FLASK_PORT..."
    if command -v fuser &>/dev/null; then
        fuser -k $FLASK_PORT/tcp 2>/dev/null || true
        sleep 1
    elif command -v lsof &>/dev/null; then
        lsof -ti :$FLASK_PORT | xargs -r kill -9 2>/dev/null || true
        sleep 1
    fi
fi

# ============================================================
# CHECK/START OLLAMA
# ============================================================
log "Checking Ollama..."
OLLAMA_RUNNING=false

# Check if ollama is already serving
if curl -s --max-time 3 http://localhost:11434/api/tags &>/dev/null; then
    OLLAMA_RUNNING=true
    success "Ollama is already running"
elif command -v ollama &>/dev/null; then
    # Try to start ollama
    log "Starting Ollama..."
    nohup ollama serve > "$SCRIPT_DIR/ollama.log" 2>&1 &
    OLLAMA_PID=$!
    echo "$OLLAMA_PID" > "$OLLAMA_PID_FILE"
    
    # Wait for ollama to be ready
    for i in $(seq 1 15); do
        if curl -s --max-time 2 http://localhost:11434/api/tags &>/dev/null; then
            OLLAMA_RUNNING=true
            success "Ollama started (PID: $OLLAMA_PID)"
            break
        fi
        sleep 1
    done
else
    warn "Ollama not found. Install with: curl -fsSL https://ollama.ai/install.sh | sh"
fi

if [ "$OLLAMA_RUNNING" = false ]; then
    error "Ollama failed to start. Chat features will be unavailable."
    warn "You can still access research data and RSS feeds."
fi

# Check models
if [ "$OLLAMA_RUNNING" = true ]; then
    MODEL_COUNT=$(curl -s http://localhost:11434/api/tags 2>/dev/null | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('models',[])))" 2>/dev/null || echo 0)
    if [ "$MODEL_COUNT" -gt 0 ]; then
        success "Found $MODEL_COUNT Ollama models"
    else
        warn "No Ollama models found. Pull one: ollama pull qwen2.5:3b"
    fi
fi

# ============================================================
# START APPLICATION
# ============================================================
log "Starting GBLOXKOS MORPHEUS V.1 on port $FLASK_PORT..."

# Clean old logs
> "$LOG_FILE"
> "$ERR_FILE"

# Start Flask app
nohup env FLASK_PORT="$FLASK_PORT" python3 "$SCRIPT_DIR/app.py" > "$LOG_FILE" 2>> "$ERR_FILE" &
APP_PID=$!
echo "$APP_PID" > "$PID_FILE"
echo "$FLASK_PORT" > "$PORT_FILE"

# Wait for app to be ready
log "Waiting for application to start..."
APP_READY=false
for i in $(seq 1 10); do
    if curl -s --max-time 2 http://localhost:$FLASK_PORT/api/status &>/dev/null; then
        success "Application started (PID: $APP_PID)"
        APP_READY=true
        break
    fi
    if ! kill -0 "$APP_PID" 2>/dev/null; then
        error "Application failed to start. Check $ERR_FILE"
        exit 1
    fi
    sleep 1
done
if [ "$APP_READY" = false ]; then
    warn "Application is starting slowly (still booting in the background). It will be ready shortly."
    warn "If it never comes up, check $ERR_FILE"
fi

# ============================================================
# SHOW STATUS
# ============================================================
echo ""
echo "=========================================="
echo "  GBLOXKOS MORPHEUS V.1"
echo "=========================================="
echo ""
if [ "$OLLAMA_RUNNING" = true ]; then
    echo -e "  ${GREEN}Ollama${NC}:    Connected"
else
    echo -e "  ${YELLOW}Ollama${NC}:    Not available"
fi
echo "  Flask:     http://localhost:$FLASK_PORT"
echo "  PID:       $APP_PID"
echo "  Log:       $LOG_FILE"
echo "  Error:     $ERR_FILE"
echo ""
echo "  Commands:"
echo "    ./stop.sh          Stop the application"
echo "    ./start.sh         Restart (or use this)"
echo ""
echo "=========================================="