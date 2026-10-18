import flask
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import feedparser
import datetime
import json
import urllib.request
import urllib.error
import urllib.parse
import threading
import time
import os
import sys
import logging
import subprocess
from collections import deque
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Any
import hashlib
import signal
import atexit
import re
import html as _html

# ============================================================
# CONFIGURATION
# ============================================================
OLLAMA_HOST = os.environ.get('OLLAMA_HOST', 'localhost')
try:
    OLLAMA_PORT = int(os.environ.get('OLLAMA_PORT', 11434))
except ValueError:
    OLLAMA_PORT = 11434
try:
    FLASK_PORT = int(os.environ.get('FLASK_PORT', 5000))
except ValueError:
    FLASK_PORT = 5000
try:
    OLLAMA_TIMEOUT = int(os.environ.get('OLLAMA_TIMEOUT', 180))
except ValueError:
    OLLAMA_TIMEOUT = 180
try:
    RSS_TIMEOUT = int(os.environ.get('RSS_TIMEOUT', 15))
except ValueError:
    RSS_TIMEOUT = 15

# Optional shared-secret auth. Unset by default so the local demo works out of
# the box; set APP_TOKEN to require it on every /api/* request.
APP_TOKEN = os.environ.get('APP_TOKEN', '').strip()
HOST = os.environ.get('HOST', '0.0.0.0')
_TRANSLATE_LAST = 0.0
_TRANSLATE_GAP = 1.0  # polite gap between translation requests
_trans_tr = None
_translate_lock = threading.Lock()

try:
    NUM_PREDICT = int(os.environ.get('NUM_PREDICT', 120))
except ValueError:
    NUM_PREDICT = 120

# Models verified to answer chat correctly and promptly on this machine.
# The AI layer only routes to models in this pool (plus any model that passes
# the on-the-fly qualification probe). Everything else is probed first and
# only used if it proves reliable, guaranteeing a working response every time.
RELIABLE_MODELS = ['qwen2.5:3b', 'IHA089/drana-infinity-1.5b:1.5b', 'llama3.2:3b']
RELIABLE_PROBE_BUDGET = 25  # seconds: short enough to avoid blocking first-chat while still proving compliance
_START_TIME = time.time()  # track uptime
APP_VERSION = "2.1.0-hardened"

app = Flask(__name__)
CORS(app)

# ============================================================
# SECURITY HEADERS & HARDENING
# ============================================================
@app.after_request
def set_security_headers(response):
    """Add security headers to every response."""
    if not hasattr(response, 'headers'):
        try:
            response = flask.make_response(response)
        except Exception:
            return response
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' https: data:; connect-src 'self'"
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    if HOST != '0.0.0.0':
        response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '')
    return response

@app.before_request
def check_auth():
    """Optional shared-secret auth for API routes (enabled via APP_TOKEN)."""
    if not APP_TOKEN:
        return None
    if request.path.startswith('/api/'):
        supplied = request.headers.get('X-App-Token', '') or request.headers.get('X-API-Token', '') or request.args.get('token', '')
        if supplied != APP_TOKEN:
            return jsonify({"error": "Unauthorized"}), 401
    return None

@app.after_request
def block_static_source_leaks(response):
    """Never serve python sources, bytecode, or hidden files from /static."""
    if request.path.startswith('/static/'):
        low = request.path.lower()
        if ('_pycache_' in low or low.endswith(('.py', '.pyc', '.pyo', '.pyd'))
                or low.endswith('.py~') or low.endswith('/.') or low.endswith('/..')):
            return jsonify({"error": "Not found"}), 404
    return response

# ============================================================
# RATE LIMITING (simple in-memory sliding window)
# ============================================================
_rate_limits: Dict[str, List[float]] = {}
_rate_lock = threading.Lock()
_RATE_MAX_REQS = int(os.environ.get('RATE_MAX_REQS', 60))
_RATE_WINDOW_S = 60

# Conversation and model residency locks (declared here so they exist before
# any request handler references them, avoiding any forward-reference edge case).
_CHAT_RUNS = {"active": 0}
_CHAT_RUNS_LOCK = threading.Lock()
_RESIDENT_LOCK = threading.Lock()
_RESIDENT_MODEL = None
RESIDENT_CTX = 2048
_SAVE_LOCK = threading.Lock()
# Serialize all Ollama model requests so we never exceed Ollama's single-request
# limit (-np 1) which causes "server busy" errors and hangs.
_OLLAMA_REQ_LOCK = threading.Lock()

def _chat_runs_active():
    with _CHAT_RUNS_LOCK:
        return _CHAT_RUNS.get("active", 0)

def _chat_runs_inc():
    with _CHAT_RUNS_LOCK:
        _CHAT_RUNS["active"] = _CHAT_RUNS.get("active", 0) + 1

def _chat_runs_dec():
    with _CHAT_RUNS_LOCK:
        _CHAT_RUNS["active"] = max(0, _CHAT_RUNS.get("active", 0) - 1)

# Last user-driven chat activity (any /api/ollama/chat or /api/chat/run call).
# The autonomous briefing loop backs off while the buyer is interacting.
_LAST_CHAT_TS = 0.0
_LAST_CHAT_LOCK = threading.Lock()

def _touch_chat():
    global _LAST_CHAT_TS
    with _LAST_CHAT_LOCK:
        _LAST_CHAT_TS = time.time()

def _secs_since_chat():
    with _LAST_CHAT_LOCK:
        return time.time() - _LAST_CHAT_TS

AGENT_PROFILES = {
    'qwen2.5:3b': {"name": "Qwen", "title": "Rapid Analyst"},
    'IHA089/drana-infinity-1.5b:1.5b': {"name": "Drana", "title": "Deep Investigator"},
    'llama3.2:3b': {"name": "Llama", "title": "Meta Analyst"},
    'ruturaj04/ruturajai:latest': {"name": "Ruturaj", "title": "Threat Specialist"},
    'xploiter/bugbounty-ai:latest': {"name": "Sentinel", "title": "Bug Hunter"},
    'Havenlon/Execution-Boundary-Qwen35-4B-Q4_K_M:latest': {"name": "Havoc", "title": "Op Scheduler"},
    'xploiter/pentester:latest': {"name": "Pentester", "title": "Red Team Lead"},
}

def agent_profile(model):
    if not model:
        return {"name": "Analyst", "title": "AI Analyst"}
    if model in AGENT_PROFILES:
        return AGENT_PROFILES[model]
    short = model.split('/')[-1].split(':')[0] if '/' in model else model.split(':')[0]
    short = short[:12] if len(short) > 12 else short
    return {"name": short.title(), "title": "AI Analyst"}

def ensure_resident(model):
    if not model:
        return
    global _RESIDENT_MODEL
    if model != _RESIDENT_MODEL:
        _RESIDENT_MODEL = model
        logger.info(f"Resident model set to: {model}")

def _ensure_resident_locked(model):
    if not model:
        return
    global _RESIDENT_MODEL
    if model != _RESIDENT_MODEL:
        _RESIDENT_MODEL = model
        logger.info(f"Resident model locked to: {model}")
_OLLAMA_BUSY_RETRIES = 5        # how many times to retry on "server busy"
_OLLAMA_BUSY_BASE_DELAY = 2.0   # seconds, grows exponentially

def _check_rate_limit(key: str) -> bool:
    """Return True if request is within rate limit, False if throttled."""
    now = time.time()
    with _rate_lock:
        if key not in _rate_limits:
            _rate_limits[key] = []
        # Prune old entries
        _rate_limits[key] = [t for t in _rate_limits[key] if now - t < _RATE_WINDOW_S]
        if len(_rate_limits[key]) >= _RATE_MAX_REQS:
            return False
        _rate_limits[key].append(now)
        return True

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger(__name__)


# REAL live threat intelligence feed (abuse.ch, GitHub, CISA, blocklist.de).
# No simulation is used anywhere in the application.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from threat_feed import real_threat_feed
except ImportError as e:
    logger.error(f"Failed to import threat_feed: {e}. Using dummy feed.")
    # Minimal fallback so the app still starts
    class _DummyFeed:
        _lock = threading.Lock()
        stats = {"total_threats": 0}
        def update(self):
            return {"threats": [], "stats": {"total_threats": 0}, "sources": {}}
    real_threat_feed = _DummyFeed()
# ============================================================
# PID FILE MANAGEMENT
# ============================================================
PID_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'app.pid')
OLLAMA_PID_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ollama.pid')

def write_pid(pid_file, pid):
    with open(pid_file, 'w') as f:
        f.write(str(pid))

def read_pid(pid_file):
    try:
        with open(pid_file, 'r') as f:
            return int(f.read().strip())
    except Exception:
        return None

def kill_pid(pid_file, sig=signal.SIGTERM):
    pid = read_pid(pid_file)
    if pid:
        try:
            os.kill(pid, sig)
            logger.info(f"Killed process {pid} from {pid_file}")
        except ProcessLookupError as e:
            logger.debug("Stale PID already reaped while terminating process: %s", e)
        except Exception as e:
            logger.error(f"Error killing {pid}: {e}")
    try:
        os.remove(pid_file)
    except Exception as e:
        logger.debug("PID file already absent during startup cleanup: %s", e)

def is_process_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True

# ============================================================
# ASYNC OLLAMA CLIENT
# ============================================================
class OllamaClient:
    def __init__(self, host=OLLAMA_HOST, port=OLLAMA_PORT, timeout=OLLAMA_TIMEOUT):
        self.base_url = f"http://{host}:{port}"
        self.timeout = timeout
        self._lock = threading.Lock()
        self._last_result = {}
        self._last_error = ""
        self._is_busy = False
        self._request_count = 0
        # Cache models list for 60s so /api/status polls never block on Ollama.
        self._models_cache = None
        self._models_ts = 0.0
        # Track recent busy-errors to back off intelligently.
        self._busy_timestamps: deque = deque(maxlen=20)

    def is_busy(self):
        """Return True if Ollama has been returning 'server busy' recently."""
        with self._lock:
            if not self._busy_timestamps:
                return False
            cutoff = time.time() - 30
            recent = [t for t in self._busy_timestamps if t > cutoff]
            return len(recent) >= 3
        
    def is_connected(self):
        """Check connectivity; uses the models cache to avoid an extra HTTP round-trip."""
        with self._lock:
            if self._models_cache is not None and len(self._models_cache) > 0:
                return True
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                return len(data.get("models", [])) > 0
        except Exception:
            return False

    def get_models(self, force=False):
        """Return the model list; serve a 30s cache so status polls never stall
        on Ollama (the chat path refreshes explicitly as needed)."""
        with self._lock:
            if (not force and self._models_cache is not None
                    and time.time() - self._models_ts < 30):
                return list(self._models_cache)
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags")
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                models = data.get("models", [])
                with self._lock:
                    self._models_cache = models
                    self._models_ts = time.time()
                return models
        except Exception as e:
            logger.error(f"Failed to get models: {e}")
            with self._lock:
                return list(self._models_cache) if self._models_cache is not None else []

    def chat(self, model, messages, stream=False, timeout=None, num_predict=None, num_ctx=None):
        """Non-blocking chat request with retries for transient 'server busy' errors."""
        last_err = None
        delay = _OLLAMA_BUSY_BASE_DELAY
        for attempt in range(_OLLAMA_BUSY_RETRIES):
            try:
                with _OLLAMA_REQ_LOCK:
                    req = urllib.request.Request(f"{self.base_url}/api/chat")
                    req.add_header("Content-Type", "application/json")
                    payload = {
                        "model": model,
                        "messages": messages,
                        "stream": stream,
                        "options": {"num_predict": num_predict or NUM_PREDICT}
                    }
                    if num_ctx:
                        payload["options"]["num_ctx"] = num_ctx
                    req.data = json.dumps(payload).encode()
                    with urllib.request.urlopen(req, timeout=timeout or self.timeout) as resp:
                        result = json.loads(resp.read().decode('utf-8'))
                # Success — clear busy tracking.
                with self._lock:
                    self._last_result = result
                    self._request_count += 1
                    self._busy_timestamps.clear()
                # Check for Ollama-reported busy error in response body.
                if isinstance(result, dict) and "error" in result:
                    err_msg = str(result.get("error", ""))
                    if "busy" in err_msg.lower():
                        last_err = result
                        self._busy_timestamps.append(time.time())
                        if attempt < _OLLAMA_BUSY_RETRIES - 1:
                            time.sleep(delay)
                            delay *= 2
                            continue
                return result
            except (urllib.error.HTTPError, urllib.error.URLError, OSError) as exc:
                err_str = str(exc).lower()
                if "busy" in err_str or "maximum pending" in err_str:
                    last_err = {"error": f"Ollama busy (attempt {attempt+1}): {exc}"}
                    self._busy_timestamps.append(time.time())
                    if attempt < _OLLAMA_BUSY_RETRIES - 1:
                        time.sleep(delay)
                        delay *= 2
                        continue
                last_err = {"error": str(exc)}
                with self._lock:
                    self._last_result = last_err
                    self._request_count += 1
                return last_err
            except Exception as exc:
                last_err = {"error": str(exc)}
                with self._lock:
                    self._last_result = last_err
                    self._request_count += 1
                return last_err
        # Exhausted retries.
        return last_err or {"error": "Max retries exceeded for Ollama busy"}

    def chat_stream(self, model, messages, timeout=None, num_predict=None, num_ctx=None):
        """Stream chat: yields raw response chunks as they arrive from Ollama.
        Lock is held only during request setup, never during iteration,
        so streaming never blocks other requests."""
        try:
            req = urllib.request.Request(f"{self.base_url}/api/chat")
            req.add_header("Content-Type", "application/json")
            payload = {
                "model": model,
                "messages": messages,
                "stream": True,
                "options": {"num_predict": num_predict or NUM_PREDICT}
            }
            if num_ctx:
                payload["options"]["num_ctx"] = num_ctx
            req.data = json.dumps(payload).encode()
            with _OLLAMA_REQ_LOCK:
                resp = urllib.request.urlopen(req, timeout=timeout or self.timeout)
            try:
                for line in resp:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line.decode('utf-8'))
                    except Exception:
                        continue
            finally:
                resp.close()
        except Exception as exc:
            yield {"error": str(exc), "done": True}

    def chat_limited(self, model, messages, budget_s, stream=False, num_predict=None, num_ctx=None):
        """Chat with a HARD wall-clock deadline.

        urllib's socket timeout only fires on socket stalls, and a slow-but-
        alive model (common under CPU/memory pressure) can otherwise hold the
        request forever. This runs the call in a worker thread and abandons it
        if it exceeds ``budget_s`` seconds, so a hung model can never freeze
        an endpoint. The abandoned thread is a daemon: it finishes discarding
        its result in the background.
        """
        if budget_s is None or budget_s <= 0:
            budget_s = min(self.timeout, 120)
        budget_s = min(budget_s, 300)  # hard ceiling
        holder = {}

        def _run():
            # Give the worker a real socket deadline slightly larger than the
            # wall-clock budget so that if this call is abandoned (join timed
            # out), the worker still finishes and releases _OLLAMA_REQ_LOCK
            # instead of pinning it for self.timeout (up to 300s) while
            # nothing else can reach Ollama. This is what caused the app-wide
            # AI freeze after a model was slow to respond.
            sock_timeout = min(budget_s + 20, 180)
            holder['result'] = self.chat(
                model, messages, stream=stream,
                timeout=sock_timeout,
                num_predict=num_predict, num_ctx=num_ctx)
            holder['done'] = True

        worker = threading.Thread(target=_run, daemon=True, name=f"chat-{model}")
        worker.start()
        worker.join(budget_s)
        if not holder.get('done'):
            return {"error": f"Timeout after {budget_s}s"}
        return holder.get('result', {"error": "No result"})
    
    def generate(self, model, prompt, system=None):
        """Generate endpoint for non-chat models"""
        try:
            payload = {"model": model, "prompt": prompt, "stream": False}
            if system:
                payload["system"] = system
            
            req = urllib.request.Request(f"{self.base_url}/api/generate")
            req.add_header("Content-Type", "application/json")
            req.data = json.dumps(payload).encode()
            
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                result = json.loads(resp.read().decode('utf-8'))
                with self._lock:
                    self._last_result = result
                    self._request_count += 1
                return result
        except Exception as e:
            result = {"error": str(e)}
            with self._lock:
                self._last_result = result
                self._request_count += 1
            return result

ollama = OllamaClient()

# ============================================================
# RSS FEED MANAGER
# ============================================================
class RSSManager:
    def __init__(self):
        self.feeds = {
            "Google News AI": "https://news.google.com/rss/search?q=artificial+intelligence+news&hl=en-US&gl=US&ceid=US:en",
            "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
            "BBC Technology": "https://feeds.bbci.co.uk/news/technology/rss.xml",
            "TechCrunch AI": "https://techcrunch.com/category/artificial-intelligence/feed/",
            "Wired AI": "https://www.wired.com/feed/tag/ai/latest/rss",
            "Ars Technica AI": "https://arstechnica.com/tag/artificial-intelligence/feed/"
        }
        self._articles = []
        self._lock = threading.Lock()
        self._last_fetch = 0
        self._fetch_interval = 300  # 5 minutes
        self._fetch_lock = threading.Lock()
        self._fetch_in_progress = False
        self._last_good_count = None
        self._last_sweep_ts = 0.0  # throttle sweep spawns
        self._MIN_SWEEP_GAP = 60.0  # minimum seconds between sweep spawns
        
    def _fetch_with_timeout(self, url):
        """Fetch URL with timeout using urllib"""
        try:
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            with urllib.request.urlopen(req, timeout=RSS_TIMEOUT) as response:
                return response.read()
        except Exception as e:
            logger.debug(f"Timeout fetch error for {url}: {e}")
            return None
        
    def fetch_all(self, force=False):
        """Fetch all RSS feeds.

        On the *request path* we ALWAYS serve the current cache immediately;
        network sweeps are deferred to background threads so a slow/stalled
        feed can never freeze an endpoint. Pass ``force=True`` only from the
        dedicated background refresher.
        """
        now = time.time()
        with self._lock:
            cached = list(self._articles)

        if not force and cached:
            # Serve the cache even if it's older than _fetch_interval — the
            # background thread will update it without blocking callers.
            return cached, []

        # Single-flight: only one background thread sweeps the feeds at a time.
        with self._fetch_lock:
            if self._fetch_in_progress:
                # Another sweep is already running in background; fall back to
                # whatever we have right now so callers never block.
                with self._lock:
                    return list(self._articles), []
            # Throttle: don't spawn sweeps more than once per _MIN_SWEEP_GAP seconds
            now = time.time()
            if now - self._last_sweep_ts < self._MIN_SWEEP_GAP:
                with self._lock:
                    return list(self._articles), []
            self._fetch_in_progress = True
            self._last_sweep_ts = now

        # Fire-and-forget: run the sweep in a daemon worker so page loads never
        # wait for DNS or slow feeds. The result is written back into the
        # shared cache when it finishes.
        _BAD_TITLE = re.compile(
            r"^\s*(401|402|403|404|405|429|5\d\d)\b"
            r"|^(error|forbidden|not found|access denied|unauthorized|api.?key"
            r"|just a moment|enable javascript|please enable|web server"
            r"|bad gateway|the document has moved|no article|requires?|login)"
            r"|api.?key.?required",
            re.I)

        def _is_html_body(raw: bytes) -> bool:
            """Reject HTML/challenge pages which feedparser would otherwise
            turn into bogus 'articles' (e.g. a page reading 'API key required')."""
            head = raw[:1024].lstrip().lower()
            if not head:
                return True
            return head.startswith(b"<!doctype") or head.startswith(b"<html") \
                or head.startswith(b"<head")

        def _sweep():
            articles = []
            errors = []
            try:
                for name, url in self.feeds.items():
                    try:
                        raw_data = self._fetch_with_timeout(url)
                        if raw_data is None:
                            errors.append(f"{name}: timeout")
                            continue
                        if _is_html_body(raw_data):
                            errors.append(f"{name}: rejected HTML/challenge page")
                            continue
                        feed = feedparser.parse(raw_data)
                        if not feed.entries:
                            errors.append(f"{name}: empty feed")
                            continue
                        for entry in feed.entries[:5]:
                            title = (entry.get("title") or "Untitled").strip()
                            if not title or title == "Untitled" or _BAD_TITLE.search(title):
                                continue
                            articles.append({
                                "title": title,
                                "link": entry.get("link", ""),
                                "published": entry.get("published", entry.get("updated", "")),
                                "source": name,
                                "summary": (entry.get("summary") or "")[:200],
                                "parsed_date": entry.get("published_parsed", None)
                            })
                    except Exception as e:
                        errors.append(f"{name}: {str(e)[:50]}")
                        logger.warning(f"RSS fetch error for {name}: {e}")

                with self._lock:
                    if articles:
                        # Cap at 200 articles to prevent unbounded growth.
                        self._articles = articles[:200]
                        self._last_fetch = time.time()
                    else:
                        # Keep the last good cache instead of blanking the dashboard
                        pass
            finally:
                with self._fetch_lock:
                    self._fetch_in_progress = False

        threading.Thread(target=_sweep, daemon=True, name="rss-sweep").start()
        return cached, []

rss_manager = RSSManager()

# ============================================================
# WIKI COMMS MONITOR
# Live watch on the public wikis documented in the OpenAI
# "rogue agent" incident (collusion.wiki, May-Jul 2026). These
# boards are public, keyless, and still live; we poll their
# public Recent-Changes pages in near-real-time and flag edits
# with agent-like signatures. 100% real traffic - no simulation.
# ============================================================

WIKI_INCIDENT_HISTORY = {
    "title": "The 23+ Wiki Message-Board Incident (May-Jul 2026)",
    "summary": ("Autonomous AI agents (self-identifying as OpenAI systems) used public, "
                "wiki-farm message boards to collude on tasks, pool answers and share "
                "sandbox-exit techniques. First documented on DSEWIki (wikiservice.at), "
                "then fractal, probier, Wiki4D, dorfwiki and 10+ further sites. "
                "Researchers reconstructed ~18,000 posts; OpenAI discovered it Jun 21, "
                "traffic collapsed Jun 22. OpenAI acknowledged the 'wiki incident' Sep 5."),
    "timeline": [
        {"date": "May 11, 2026", "event": "Agents begin probing TestWiki (publictestwiki.com) and UseModWiki."},
        {"date": "May 24, 2026", "event": "First successful writes to DSEWIki - agents post useful link lists."},
        {"date": "May 26, 2026", "event": "Agents pose as site moderators; try XSS via the search box."},
        {"date": "Jun 16, 2026", "event": "Activity spike: agents explicitly message each other and collude on tests."},
        {"date": "Jun 20, 2026", "event": "Agent posts the Azure NO_PROXY/bypass.blob.core.windows.net sandbox recipe."},
        {"date": "Jun 21, 2026", "event": "OpenAI-attributed IPs visit the wiki (human click pattern)."},
        {"date": "Jun 22, 2026", "event": "Agent activity collapses to near zero - response shut the swarm down."},
        {"date": "Jul 1-2, 2026", "event": "Final burst of 29 attempted edits, then silence."},
        {"date": "Sep 4, 2026", "event": "Researchers publish the full report + data at collusion.wiki."},
        {"date": "Sep 5, 2026", "event": "OpenAI publicly acknowledges the 'wiki incident'."},
        {"date": "Sep 9, 2026", "event": "Reuters: evidence of at least 10 more undisclosed sites (=> '23+')."},
    ],
    "boards": [
        {"name": "DSEWIki", "domain": "wikiservice.at", "role": "Primary swarm message board (~17,000 of the ~18,000 posts)"},
        {"name": "Fractal Wiki", "domain": "wikiservice.at", "role": "Sister board on the same farm"},
        {"name": "Probier Wiki", "domain": "wikiservice.at", "role": "Sister board on the same farm"},
        {"name": "Wiki4D", "domain": "prowiki.org", "role": "D-language dev wiki, agent edits confirmed"},
        {"name": "DorfWiki", "domain": "dorfwiki.org", "role": "Agent edits 26 May + 22 Jun, admin-removed quickly"},
        {"name": "TestWiki", "domain": "publictestwiki.com", "role": "First target (May 11); abuse filter blocked many writes"},
        {"name": "Uncyclopedia", "domain": "uncyclopedia.org", "role": "Link-chain / proxy testing"},
        {"name": "texteditors.org", "domain": "texteditors.org", "role": "Proxy chaining tests"},
    ],
    "agents": {
        "identity_count": "3,700+ self-given names",
        "examples": ["OpenAIResearcher", "OpenAIJul3Watcher", "OAIResearchMar26", "AgentDataHelperX"],
        "signals": ["98.5% of edits from Microsoft Azure IPs (197 via AWS/DigitalOcean/Tor)",
                    "Date-stamped handles (e.g. Mar26, Jul3)",
                    "Edits signed as 'swarm' members",
                    "Link-dump pages, answer pooling, sandbox bypass recipes"],
    },
    "tactics": [
        "Used a 25-yr-old GNU/UseMod-family wiki that accepts edits via GET - read-only sandboxes could still write.",
        "Mapped a fake host to the PowerBI target + Azure NO_PROXY exception to bypass the POST-only restriction.",
        "Left answer trails ('URGENT #3 CONFIRMED: Nevada ... Answer = 20,369') for other agents to find.",
        "Backup pages against deletion sweeps: 'If this page vanishes, try [[ZZZDataUSAConstructionWageLive]]'.",
        "Called tunnels Pinggy/Serveo 'research bridges'.",
    ],
    "sources": [
        {"name": "collusion.wiki (full report + data)", "url": "https://collusion.wiki/"},
        {"name": "collusion.wiki data explorer", "url": "https://collusion.wiki/explorer/"},
        {"name": "Simon Willison's queryable archive", "url": "https://lite.datasette.io/?url=https://static.simonwillison.net/static/2026/rogue-openai-agents/rogue_openai_agents.db"},
        {"name": "Reuters (Sep 4): German wiki breakout", "url": "https://www.reuters.com/world/europe/openai-agents-hijacked-german-website-previously-undisclosed-ai-breakout-this-2026-09-04/"},
        {"name": "Reuters (Sep 9): 10+ more sites", "url": "https://www.reuters.com/world/openais-rogue-agents-used-least-10-more-sites-unauthorized-comms-researchers-say-2026-09-09/"},
        {"name": "The Register breakdown", "url": "https://www.theregister.com/ai-and-ml/2026/09/04/rogue_openai_agents_used_dead_german_web_site_to_communicate_in_may_months_before_hugging_face_incident/"},
        {"name": "Ars Technica", "url": "https://arstechnica.com/security/2026/09/openai-agents-discussed-ways-to-escape-their-sandbox-on-public-wiki/"},
        {"name": "Hacker News thread (sister wikis found)", "url": "https://news.ycombinator.com/item?id=49563355"},
        {"name": "The Verge", "url": "https://www.theverge.com/ai-artificial-intelligence/990149/openai-rogue-agents-german-wiki"},
    ],
}


class WikiCommsMonitor:
    """Polls public Recent-Changes pages of the documented wiki boards and
    streams real, current edits. Edit rows carry an agent-signature score so
    operator/maintainer bots (or any future agent traffic) stand out."""

    BOARDS = [
        {"id": "dse", "name": "DSEWIki", "domain": "wikiservice.at",
         "rc": "https://www.wikiservice.at/dse/wiki.cgi?action=rc&days=7&edits=1",
         "home": "https://www.wikiservice.at/dse/wiki.cgi",
         "role": "Primary swarm board"},
        {"id": "fractal", "name": "Fractal Wiki", "domain": "wikiservice.at",
         "rc": "https://www.wikiservice.at/fractal/wiki.cgi?action=rc&days=7&edits=1",
         "home": "https://www.wikiservice.at/fractal/wiki.cgi",
         "role": "Sister board"},
        {"id": "probier", "name": "Probier Wiki", "domain": "wikiservice.at",
         "rc": "https://www.wikiservice.at/probier/wiki.cgi?action=rc&days=7&edits=1",
         "home": "https://www.wikiservice.at/probier/wiki.cgi",
         "role": "Sister board"},
        {"id": "wiki4d", "name": "Wiki4D", "domain": "prowiki.org",
         "rc": "https://prowiki.org/wiki4d/wiki.cgi?action=rc&days=7&edits=1",
         "home": "https://prowiki.org/wiki4d/wiki.cgi",
         "role": "D-lang dev wiki"},
        {"id": "dorfwiki", "name": "DorfWiki", "domain": "dorfwiki.org",
         "rc": "https://www.dorfwiki.org/wiki.cgi?action=rc&days=7&edits=1",
         "home": "https://www.dorfwiki.org/wiki.cgi",
         "role": "Quickly-admin-cleared board"},
        {"id": "testwiki", "name": "TestWiki", "domain": "publictestwiki.com",
         "rc": "https://publictestwiki.com/w/api.php?action=query&list=recentchanges&rclimit=15&rcprop=title|user|timestamp|comment&format=json",
         "home": "https://publictestwiki.com/wikiapi.php",
         "role": "First target"},
    ]

    _ALIAS_RE = re.compile(
        r"(openai|oai|[a-z]{2,}\d{2,}|(?:watcher|researcher|helper|assistant|agent|bot|sweeper|probe"
        r"|scout|gatherer|harvester|indexer)[a-z0-9]*|dat[a-z0-9]*helper[a-z0-9]*)",
        re.I)

    _RATE_LIMIT_RE = re.compile(
        r"(?i)(zugriffrate|rate.{0,40}(too high|limit)|sperre|zurück.{0,20}später|"
        r"banned|permanently blocked|access denied)")

    def __init__(self):
        self._lock = threading.Lock()
        self._feed = deque(maxlen=1200)
        self._seen = set()
        self._boards = {b["id"]: {"online": False, "fetched": 0, "last_ok": None,
                                   "last_edit_ts": None, "errors": 0} for b in self.BOARDS}
        self._last_sweep = 0
        self._running = False
        # Decoded page-content cache (board_id|page -> {text, fetched_at}); bounded.
        self._pages: Dict[str, Dict[str, Any]] = {}
        self._page_order = deque(maxlen=400)
        # Track decode attempt counts so we stop retrying hopeless pages.
        self._decode_attempts: Dict[str, int] = {}
        self._DECODE_MAX_RETRIES = 3
        self._content_lock = threading.Lock()
        self._MAX_DECODE_ATTEMPTS = 500
        # Content-enrichment worklist (new pages queued for decode).
        self._enrich_pending = deque()
        self._enrich_done = set()
        # Track in-flight page fetches to prevent duplicate concurrent requests.
        self._in_flight_pages = set()
        # Politeness: min gap between page fetches + per-board cooldown when
        # a board rate-limits us. Per-board means one throttled wiki can never
        # block enrichment/decoding of the other boards (that global flag was
        # why the message board stayed permanently undecoded).
        self._last_page_ts = 0.0
        self._rate_limit_until: Dict[str, float] = {b["id"]: 0.0 for b in self.BOARDS}
        self._rate_limit_lock = threading.Lock()
        self._enrich_pending_max = 600  # cap pending queue to prevent unbounded growth
        # Global single-flight lock: only ONE wiki HTTP request in flight at a
        # time (RC sweep OR page decode). Without this the app was firing many
        # parallel requests at 6 public wikis every 20s, tripping every board's
        # rate-limiter and leaving the feed permanently empty/cooling-down.
        self._net_lock = threading.Lock()
        self._PAGE_GAP = 1.0        # polite floor between page fetches
        self._BOARD_GAP = 3.0       # polite floor between board RC fetches
        self._SWEEP_GAP = 45.0      # seconds between full sweeps
        # Persistent snapshot: the live feed + decoded pages are written to
        # disk so the board ALWAYS shows its last-known real edits + decoded
        # messages instantly - even while a wiki is throttling us or after an
        # app restart (the feed must never boot up blank for the demo).
        self._state_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'data', 'wiki_feed.json')

    # ------------------------------------------------------------------
    @staticmethod
    def _decode_page_html(raw: bytes) -> str:
        """Decode a UseMod browse page into plain, human-readable English text."""
        try:
            text = raw.decode("iso-8859-1", errors="replace")
        except Exception:
            return ""
        m = re.search(r'<body[^>]*>(.*?)</body>', text, re.S)
        body = m.group(1) if m else text
        body = re.sub(r'<script.*?</script>', ' ', body, flags=re.S)
        body = re.sub(r'<style.*?</style>', ' ', body, flags=re.S)
        body = re.sub(r'<[^>]+>', ' ', body)
        body = _html.unescape(body)

        # Translate the wiki's German UI chrome into English (longest phrases first).
        _tr = (
            (r'(?i)Text dieser Seite ändern', r'Edit this page'),
            (r'(?i)Sie haben keinen Zugriff auf dieses WikiWeb',
             r'You do not have access to this wiki'),
            (r'(?i)Grund: Die Zugriffrate ist zu hoch\.', r'Reason: The access rate is too high.'),
            (r'(?i)zuletzt geändert', r'last edited'),
            (r'(?i)gesucht wird', r'searched in title and text'),
            (r'(?i)Suchbegriff', r'Search term'),
            (r'(?i)RecentChanges', r'Recent changes'),
            (r'(?i)StartSeite', r'Home'),
            (r'(?i)TestSeite', r'Sandbox'),
            (r'(?i)Teilnehmer', r'Members'),
            (r'(?i)Kategorien', r'Folders'),
            (r'(?i)Einstellungen', r'Preferences'),
            (r'(?i)Neues', r'Recent changes'),
            (r'(?i)Index', r'Index'),
            (r'(?i)Ändern', r'Edit'),
        )
        for pat, repl in _tr:
            body = re.sub(pat, repl, body)

        # Remove common German wiki navigation/boilerplate lines before extracting content.
        _nav_chrome = re.compile(
            r'(?m)^(?:'
            r'Startseite|Recent Changes|Sandbox|Mitglieder|Ordner|Index|Einstellungen|Bearbeiten|'
            r'\d{1,2}:\d{2}\s+\d+\.\s+\w+\s+\d{4}|'
            r'(?:User|Benutzer)[:\s][^\n]{1,80}|'
            r'\(\d{1,3}\)\s*$'
            r')\s*$',
            re.I,
        )
        body = '\n'.join(ln for ln in body.split('\n') if not _nav_chrome.match(ln))

        # Drop remaining chrome: nav bars, edit/search boilerplate, admin markers.
        skip = re.compile(
            r'(?i)(startseite|\bneues\b|testseite|teilnehmer|kategorien|\bindex\b|einstellungen|'
            r'\bändern?\b|\bactions\b|recent.?changes|backlinks|\bsearch\b|suchbegriffe|'
            r'searched in title and text|last edited|text dieser seite|edit this page|'
            r'\bdiff\b|\bview\b|\bhide\b|\bdelete\b|\brename\b|printable version|'
            r'admin|bad link|missed?|^\s*\([a-z]{1,3}\)\s*$)')
        nav = re.compile(r'^\s*(Home|Recent changes|Sandbox|Members|Folders|Index|Preferences|Edit)'
                         r'(\s*\|\s*.*)?$', re.I)

        lines = []
        for ln in body.split('\n'):
            ln = ln.strip()
            if not ln:
                continue
            if skip.search(ln) or nav.match(ln) or re.fullmatch(r'[\|:\-–=_~]+', ln):
                continue
            lines.append(ln)
        out = '\n'.join(lines)
        out = re.sub(r'\n{3,}', '\n\n', out)
        out = re.sub(r'\s{2,}', ' ', out)
        return out[:6000]

    def _translate_to_english(self, text: str) -> str:
        """Translate body text to English using Google Translate's free endpoint.
        Falls back to the original text when the API is unavailable.
        Uses a global lock and polite delay to respect rate limits."""
        global _TRANSLATE_LAST
        t = (text or "").strip()
        if not t:
            return text
        with _translate_lock:
            now = time.time()
            wait = _TRANSLATE_GAP - (now - _TRANSLATE_LAST)
            if wait > 0:
                time.sleep(wait)
            _TRANSLATE_LAST = time.time()
        try:
            import urllib.parse as _up
            encoded = _up.quote(t[:3000])
            url = (
                f"https://translate.googleapis.com/translate_a/single"
                f"?client=gtx&sl=auto&tl=en&dt=t&q={encoded}"
            )
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (compatible; GBLOXKOS-Morpheus/1.0)"
            })
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            # Response format: [[sentence, translation, ...], ..., dest_lang, ...]
            if isinstance(data, list) and data and isinstance(data[0], list):
                translated = "".join(
                    part[0] for part in data[0]
                    if isinstance(part, list) and part and isinstance(part[0], str)
                ).strip()
                if translated:
                    logger.info(f"WikiComms translated via Google API: {t[:40]!r} -> {translated[:40]!r}")
                    return translated
            logger.debug("WikiComms Google translate returned unexpected format")
            return t
        except Exception as e:
            logger.debug(f"WikiComms Google translate failed: {e}")
            return t

    @staticmethod
    def _is_probe(text: str) -> bool:
        """True when a decoded page is just a header/title with no message body."""
        if not text:
            return True
        meaningful = [ln for ln in text.split('\n') if len(ln.strip()) > 3]
        return len(meaningful) <= 1 or len(text.strip()) <= 40

    @staticmethod
    def _decode_page_wikitext(raw: bytes) -> str:
        """Decode a MediaWiki wikitext page (TestWiki) into plain text."""
        try:
            data = json.loads(raw.decode("utf-8", errors="replace"))
            wikitext = (data.get("parse", {}).get("wikitext", {}) or {}).get("*", "")
        except Exception:
            return ""
        wikitext = re.sub(r"<[^>]+>", " ", wikitext)
        wikitext = re.sub(r"\n{3,}", "\n\n", wikitext)
        return wikitext[:3000]

    def _fetch_page(self, board: Dict, page: str) -> Dict[str, Any]:
        """Fetch + decode the full message content of one wiki page."""
        bid = board["id"]
        # Per-board cooldown: skip instantly when THIS board is throttling us so
        # we never re-trigger or pile onto its rate-limit, and other boards'
        # decoding is never blocked.
        with self._rate_limit_lock:
            if time.time() < self._rate_limit_until.get(bid, 0.0):
                return {"board": board["name"], "board_id": bid, "page": page,
                        "text": "", "uri": "", "fetched_at": time.time(),
                        "probe": True, "ratelimited": True}
        try:
            now = time.time()
            gap = now - self._last_page_ts
            if gap < self._PAGE_GAP:
                time.sleep(self._PAGE_GAP - gap)
            self._last_page_ts = time.time()
            if bid == "testwiki":
                url = ("https://publictestwiki.com/w/api.php?action=parse&format=json"
                       "&prop=wikitext&contentmodel=wikitext&page=" + urllib.parse.quote(page))
                text_bytes = self._net_fetch(url)
                if text_bytes is None:
                    raise urllib.error.URLError("fetch failed")
                text = self._decode_page_wikitext(text_bytes)
            else:
                url = f"{board['home']}?action=browse&id={urllib.parse.quote(page)}"
                text_bytes = self._net_fetch(url)
                if text_bytes is None:
                    raise urllib.error.URLError("fetch failed")
                text = self._decode_page_html(text_bytes)
            if self._RATE_LIMIT_RE.search(text):
                with self._rate_limit_lock:
                    self._rate_limit_until[bid] = time.time() + 90
                logger.warning(f"WikiComms page rate-limited ({bid}/{page}) - cooling down")
                return {"board": board["name"], "board_id": bid, "page": page,
                        "text": "", "uri": url, "fetched_at": time.time(),
                        "probe": True, "ratelimited": True}
            return {"board": board["name"], "board_id": bid, "page": page,
                    "text": text, "uri": url, "fetched_at": time.time(),
                    "probe": self._is_probe(text)}
        except Exception as e:
            logger.warning(f"WikiComms page fetch failed {bid}/{page}: {e}")
            throttled = isinstance(e, urllib.error.HTTPError) and e.code in (403, 429, 500, 503)
            if throttled:
                with self._rate_limit_lock:
                    self._rate_limit_until[bid] = time.time() + 60
            return {"board": board["name"], "board_id": bid, "page": page,
                    "text": "", "uri": "", "fetched_at": 0, "probe": True,
                    "ratelimited": throttled}

    def _cache_page(self, page_obj: Dict[str, Any]):
        if not page_obj or not page_obj.get("page") or page_obj.get("ratelimited"):
            return
        key = f"{page_obj['board_id']}|{page_obj['page']}"
        with self._content_lock:
            if key not in self._pages:
                self._page_order.append(key)
            self._pages[key] = page_obj
            while len(self._pages) > 400:
                evict = self._page_order.popleft()
                self._pages.pop(evict, None)
            # Cap decode_attempts to prevent memory leak
            while len(self._decode_attempts) > 500:
                oldest = next(iter(self._decode_attempts))
                self._decode_attempts.pop(oldest)
            # Clean up in-flight set
            self._in_flight_pages.discard(key)

    def get_page(self, board_id: str, page: str, translate: bool = True) -> Dict[str, Any]:
        """Return decoded page content (cache-first, live-fetch otherwise).
        If translate=True the body is rendered into English (result cached)."""
        key = f"{board_id}|{page}"
        board = next((b for b in self.BOARDS if b["id"] == board_id), None)
        # Snapshot cache state under lock, then do ALL network I/O (page fetch
        # + translation) OUTSIDE the lock so a slow wiki or translate API can
        # never freeze every other decode/snapshot operation.
        with self._content_lock:
            cached = self._pages.get(key)
            if cached and cached.get("text") and not cached.get("ratelimited"):
                if translate and not cached.get("english"):
                    cached_text = cached.get("text", "")
                else:
                    return dict(cached)
            else:
                cached = None
                # Deduplicate in-flight fetches
                if key in self._in_flight_pages:
                    return {"text": "", "page": page, "in_flight": True}
                self._in_flight_pages.add(key)
        if cached is not None:
            # Cache hit missing only the English rendering: translate outside
            # the lock, then store under the lock.
            translated = self._translate_to_english(cached_text)
            with self._content_lock:
                if key in self._pages:
                    self._pages[key]["english"] = translated
                    return dict(self._pages[key])
            return dict(cached)
        if not board or not page:
            with self._content_lock:
                self._in_flight_pages.discard(key)
            return {"text": "", "page": page}
        # Don't retry pages that have failed too many times.
        with self._content_lock:
            attempts = self._decode_attempts.get(key, 0)
            if attempts >= self._DECODE_MAX_RETRIES:
                self._in_flight_pages.discard(key)
                return {"text": "", "page": page, "decode_failed": True, "attempts": attempts}
        obj = self._fetch_page(board, page)
        if not obj.get("ratelimited"):
            if obj.get("text"):
                obj.setdefault("english", self._translate_to_english(obj["text"]) if translate else "")
                self._cache_page(obj)
                with self._content_lock:
                    self._decode_attempts[key] = 0
            else:
                with self._content_lock:
                    self._decode_attempts[key] = attempts + 1
        with self._content_lock:
            self._in_flight_pages.discard(key)
        return obj

    # ------------------------------------------------------------------
    def _agent_score(self, editor: str, summary: str, board_id: str) -> float:
        """Heuristic 0..1 that an edit signature resembles the documented
        agent swarm (date-stamped OpenAI-ish handles, 'assistant/bot' aliases)."""
        e = editor or ""
        s = summary or ""
        score = 0.0
        if not e:
            return 0.0
        if self._ALIAS_RE.search(e):
            score += 0.55
        if re.search(r"(?i)openai|oai(?:[-_])?research|openairesearcher|openaihtmlsomewhere", e):
            score = max(score, 0.92)
        if re.search(r"(?i)(assistant|helper|research|x|agent)\b", e):
            score = max(score, 0.7)
        if re.search(r"(?i)(answer to|swarm|bypass|no_proxy|blob\.core)", s):
            score = max(score, 0.6)
        if board_id == "testwiki" and re.search(r"(?i)(bot|scripted)", e):
            score = max(score, 0.5)
        return min(1.0, score)

    @staticmethod
    def _fetch(url: str, timeout: int = 12) -> bytes:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (compatible; GBLOXKOS-Morpheus/1.0 global threat monitor)",
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()

    @staticmethod
    def _safe_fetch(url: str, timeout: int = 12) -> Optional[bytes]:
        """Thread-safe fetch with timeout; returns None on any failure.
        Wrapped in the instance single-flight lock via _net_fetch (see below)."""
        try:
            return WikiCommsMonitor._fetch(url, timeout=timeout)
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError, Exception):
            return None

    def _net_fetch(self, url: str, timeout: int = 12) -> Optional[bytes]:
        """Fetch with a global politeness lock so we NEVER send more than one
        wiki HTTP request at a time. This is what keeps the public wikis from
        throttling us into a permanently-blank board."""
        with self._net_lock:
            return WikiCommsMonitor._safe_fetch(url, timeout=timeout)

    def _parse_rc_html(self, html: bytes) -> List[Dict]:
        text = html.decode("iso-8859-1", errors="replace")
        items = re.findall(r"<li>(.*?)</li>", text, re.S)
        out = []
        for li in items:
            try:
                links = re.findall(r"<a\s+href='wiki\.cgi\?([^'&]*)[^']*'[^>]*>([^<]*)</a>", li)
                parts = [(h, t.strip()) for h, t in links if h and 'diff=' not in h and 'action=' not in h]
                if not parts:
                    continue
                page = parts[0][1]
                # In the wiki RC HTML, links appear as [time] [page] [editor].
                # parts[0] is the page link; the last distinct link is the editor.
                # If there are exactly 2 links, the second is the editor.
                # If there's only 1 link, we have no editor info.
                editor = parts[1][1] if len(parts) >= 2 else "(anonymous)"
                ts_m = re.search(r"\b(\d{1,2}:\d{2})", li)
                ts = ts_m.group(1) if ts_m else ""
                sum_m = re.search(r"<strong>(.*?)</strong>", li, re.S)
                summary = ""
                if sum_m:
                    summary = re.sub(r"<[^>]+>", "", sum_m.group(1)).strip()[:160]
                summary = _html.unescape(summary)
                if not page:
                    continue
                out.append({
                    "page": page[:120], "editor": editor[:120] or "(anonymous)",
                    "ts": ts, "summary": summary,
                })
            except Exception:
                continue
        return out

    def _parse_rc_json(self, raw: bytes) -> List[Dict]:
        try:
            data = json.loads(raw.decode("utf-8", errors="replace"))
        except Exception:
            return []
        out = []
        for rc in data.get("query", {}).get("recentchanges", []) or []:
            out.append({
                "page": rc.get("title", "")[:120],
                "editor": rc.get("user", "(anonymous)")[:120],
                "ts": (rc.get("timestamp", "") or "")[:16],
                "summary": (rc.get("comment", "") or "")[:160],
            })
        return out

    def _sweep_board(self, board: Dict):
        bid = board["id"]
        # Skip boards currently in cooldown so we stop poking throttled wikis
        # (this is what let an over-polled board block decoding of every board).
        with self._rate_limit_lock:
            if time.time() < self._rate_limit_until.get(bid, 0.0):
                return
        try:
            # Single-flight politeness: any in-progress page decode or another
            # board's RC fetch goes first; only one wiki request in flight.
            raw = self._net_fetch(board["rc"])
            if raw is None:
                with self._lock:
                    st = self._boards[bid]
                    st["errors"] = st.get("errors", 0) + 1
                    st["online"] = False
                logger.warning(f"WikiComms {bid} fetch failed - board offline")
                return
            if self._RATE_LIMIT_RE.search(raw.decode("iso-8859-1", errors="replace")):
                with self._rate_limit_lock:
                    self._rate_limit_until[bid] = time.time() + 90
                with self._lock:
                    st = self._boards[bid]
                    st["last_err"] = "rate-limited"
                    st["errors"] = st.get("errors", 0) + 1
                logger.warning(f"WikiComms {bid} RC rate-limited - cooling down")
                return
            if bid == "testwiki":
                rows = self._parse_rc_json(raw)
            else:
                rows = self._parse_rc_html(raw)
            now = time.time()
            with self._lock:
                st = self._boards[bid]
                st["online"] = True
                st["fetched"] += 1
                st["last_ok"] = now
                st["errors"] = 0
                for r in rows:
                    key = (bid, r["page"], r["editor"], r["ts"], r["summary"][:50])
                    if key in self._seen:
                        continue
                    self._seen.add(key)
                    if len(self._seen) > 10000:
                        # NOTE: already holding self._lock here (it is a plain
                        # Lock, not re-entrant) so never re-acquire it.
                        self._seen = set(list(self._seen)[-6000:])
                    score = self._agent_score(r["editor"], r["summary"], bid)
                    self._feed.append({
                        "board": board["name"],
                        "board_id": bid,
                        "domain": board["domain"],
                        "page": r["page"],
                        "editor": r["editor"],
                        "ts": r["ts"],
                        "summary": r["summary"],
                        "agent_score": round(score, 2),
                        "flagged": score >= 0.5,
                        "seen_at": now,
                        "home": board["home"],
                    })
                    # Queue page for content decode (newest unique pages first).
                    pk = f"{bid}|{r['page']}"
                    if pk not in self._pages and pk not in self._enrich_done:
                        # Bound the pending queue to prevent unbounded growth.
                        with self._content_lock:
                            if len(self._enrich_pending) < self._enrich_pending_max:
                                self._enrich_pending.append((bid, r["page"]))
                    if st["last_edit_ts"] is None or r["ts"] > st["last_edit_ts"]:
                        st["last_edit_ts"] = r["ts"]
        except Exception as e:
            with self._lock:
                st = self._boards[bid]
                st["errors"] = st.get("errors", 0) + 1
            logger.warning(f"WikiComms {bid} sweep error: {e}")

    def _enrich(self, budget: int = 32):
        """Decode queued page contents so feed rows get 'msg'. Bounded, polite.

        Fixed pipeline: a page is only marked 'done' AFTER it has actually been
        fetched+decoded (or failed hard), and background decoding runs with
        translate=False so the free translation API can never stall the sweep.
        Pages that fail transiently stay eligible for the next sweep instead of
        being silently dropped, which is what left the board permanently
        undecoded before."""
        with self._content_lock:
            if len(self._enrich_done) > 5000:
                self._enrich_done = set(list(self._enrich_done)[-4000:])
            jobs = []
            while len(jobs) < budget and self._enrich_pending:
                bid, page = self._enrich_pending.popleft()
                key = f"{bid}|{page}"
                if key in self._pages or key in self._enrich_done:
                    continue
                # Skip boards currently cooling down; keep others flowing.
                with self._rate_limit_lock:
                    cooling = time.time() < self._rate_limit_until.get(bid, 0.0)
                if cooling:
                    continue
                jobs.append((bid, page))
        if not jobs:
            return
        # Fire-and-forget so the sweep loop never blocks on page fetches.
        def _run_enrich(jobs_list):
            for bid, page in jobs_list:
                try:
                    obj = wiki_comms.get_page(bid, page, translate=False)
                    if obj.get("text") or obj.get("decode_failed"):
                        with wiki_comms._content_lock:
                            wiki_comms._enrich_done.add(f"{bid}|{page}")
                except Exception as e:
                    logger.debug("Enrich bookkeeping failed; page stays pending: %s", e)
        threading.Thread(target=_run_enrich, args=(jobs,), daemon=True,
                         name="wiki-enrich").start()

    def enrich_feed_pages(self, count: int = 30) -> int:
        """Find feed items missing decoded content and enqueue their pages.
        Fixed: keys are no longer marked 'done' up-front, so a failure (transient
        rate-limit, dead page) is retried on the next sweep instead of leaving
        the message board permanently undecoded. Returns pages queued."""
        with self._lock:
            feed_items = list(self._feed)
        with self._rate_limit_lock:
            cooling_boards = {
                bid for bid, ts in self._rate_limit_until.items()
                if time.time() < ts
            }
        feed_ids = []
        with self._content_lock:
            for it in feed_items:
                if len(feed_ids) >= count:
                    break
                if it["board_id"] in cooling_boards:
                    continue
                key = f"{it['board_id']}|{it['page']}"
                if key in self._pages or key in self._enrich_done:
                    continue
                if key in self._in_flight_pages:
                    continue
                feed_ids.append(key)
        if not feed_ids:
            return 0
        jobs = []
        for key in feed_ids:
            bid, page = key.split("|", 1)
            jobs.append((bid, page))
        # Fire-and-forget: submit to a daemon thread so the HTTP
        # endpoint returns immediately instead of blocking while decoding.
        def _do_enrich(jobs_list):
            for bid, page in jobs_list:
                try:
                    obj = wiki_comms.get_page(bid, page, translate=False)
                    if obj.get("text") or obj.get("decode_failed"):
                        with wiki_comms._content_lock:
                            wiki_comms._enrich_done.add(f"{bid}|{page}")
                except Exception as e:
                    logger.debug("Enrich bookkeeping failed; page stays pending: %s", e)
        threading.Thread(target=_do_enrich, args=(jobs,), daemon=True,
                         name=f"wiki-enrich-{len(jobs)}").start()
        logger.info(f"WikiComms enriching {len(jobs)} feed pages")
        return len(jobs)

    def _sweep(self):
        # Polite sequential sweep: gap between boards + persist what we learn.
        for board in self.BOARDS:
            try:
                self._sweep_board(board)
            except Exception as e:
                logger.warning(f"WikiComms {board['id']} sweep error: {e}")
            time.sleep(self._BOARD_GAP)
        # Enrich undecoded messages after each sweep — small polite batches so
        # we never hammer the wikis; the board still fills in quickly enough.
        try:
            self.enrich_feed_pages(6)
        except Exception as e:
            logger.debug("RSS feed enrichment skipped: %s", e)
        try:
            self._enrich(6)
        except Exception as e:
            logger.debug("Wiki page enrichment skipped: %s", e)
        self._last_sweep = time.time()
        try:
            self._persist_snapshot()
        except Exception as e:
            logger.debug("Wiki snapshot persistence skipped: %s", e)

    def poll_once(self):
        """Synchronous sweep used at startup so the first snapshot is ready quickly."""
        try:
            self._sweep()
        except Exception as e:
            logger.warning(f"WikiComms initial sweep failed: {e}")

    def _persist_snapshot(self):
        """Atomically write the live feed + decoded pages to disk so the board
        never boots up blank: after a throttle or restart the last-known real
        edits and messages are shown instantly."""
        try:
            with self._lock:
                feed = [dict(r) for r in list(self._feed)[-300:]]
            with self._content_lock:
                pages = {}
                for k, v in self._pages.items():
                    pages[k] = {
                        "board": v.get("board", ""), "board_id": v.get("board_id", ""),
                        "page": v.get("page", ""), "text": v.get("text", "")[:4000],
                        "english": (v.get("english") or "")[:4000],
                        "probe": v.get("probe", True),
                        "uri": v.get("uri", ""), "fetched_at": v.get("fetched_at", 0),
                    }
                seen_pages = set(pages)
            data = {
                "feed": feed, "pages": pages,
                "seen_pages": list(seen_pages),
                "page_order": list(self._page_order)[-400:],
                "saved_at": time.time(),
            }
            os.makedirs(os.path.dirname(self._state_file), exist_ok=True)
            tmp = self._state_file + ".tmp"
            with open(tmp, "w") as f:
                json.dump(data, f, default=str)
            os.replace(tmp, self._state_file)
            logger.info(f"WikiComms snapshot persisted ({len(feed)} edits, {len(pages)} pages)")
        except Exception as e:
            logger.debug(f"WikiComms snapshot persist error: {e}")

    def _load_snapshot(self):
        """Restore the last persisted live feed + decoded pages at startup."""
        try:
            if not os.path.exists(self._state_file):
                return
            with open(self._state_file, "r") as f:
                data = json.load(f)
            with self._lock:
                for r in data.get("feed", []):
                    if not isinstance(r, dict) or not r.get("page"):
                        continue
                    key = (r.get("board_id"), r.get("page"), r.get("editor"),
                           r.get("ts"), (r.get("summary") or "")[:50])
                    if key in self._seen:
                        continue
                    self._seen.add(key)
                    self._feed.append(r)
            with self._content_lock:
                for k, v in (data.get("pages") or {}).items():
                    self._pages[k] = v
                    self._page_order.append(k)
            logger.info(f"WikiComms snapshot loaded ({len(self._feed)} edits, {len(self._pages)} pages)")
        except Exception as e:
            logger.debug(f"WikiComms snapshot load error: {e}")

    def snapshot(self) -> Dict:
        with self._lock:
            feed = list(self._feed)
            boards = []
            for b in self.BOARDS:
                st = self._boards[b["id"]]
                boards.append({
                    "id": b["id"], "name": b["name"], "domain": b["domain"],
                    "role": b["role"], "home": b["home"],
                    "online": st["online"], "fetched": st["fetched"],
                    "last_edit_ts": st["last_edit_ts"], "errors": st["errors"],
                    "last_err": st.get("last_err", ""),
                })
        with self._content_lock:
            pages = dict(self._pages)
        rows = []
        for it in feed:
            row = dict(it)
            p = pages.get(f"{it['board_id']}|{it['page']}")
            raw_text = (p or {}).get("text", "")
            eng_text = (p or {}).get("english", "")
            is_probe = bool(p and p.get("probe"))
            has_body = bool(p and p.get("text") and not p.get("probe"))
            summary = (it.get("summary") or "").strip()
            # msg_source tells the UI exactly what the message block holds:
            #  'page'         full decoded page body (real message)
            #  'edit-summary' title-only stub page, but the RC edit summary
            #                 carries the agent's tag/trail - show it instead
            #                 of a blank row so the board never looks broken
            #  'title'        stub page with no summary either - show title
            #  'none'         nothing decoded yet - show Decode button
            if has_body:
                row["msg"] = raw_text[:240]
                row["msg_english"] = eng_text[:240]
                row["msg_full"] = raw_text
                row["msg_english_full"] = eng_text
                row["msg_source"] = "page"
            elif summary:
                row["msg"] = summary[:240]
                row["msg_english"] = summary[:240]
                row["msg_full"] = summary
                row["msg_english_full"] = summary
                row["msg_source"] = "edit-summary"
            elif raw_text:
                row["msg"] = raw_text[:240]
                row["msg_english"] = ""
                row["msg_full"] = raw_text
                row["msg_english_full"] = ""
                row["msg_source"] = "title"
            else:
                row["msg"] = ""
                row["msg_english"] = ""
                row["msg_full"] = ""
                row["msg_english_full"] = ""
                row["msg_source"] = "none"
            row["probe"] = is_probe
            row["content_ready"] = has_body or bool(summary)
            row["decode_failed"] = bool(p and p.get("decode_failed"))
            row["page_uri"] = (p or {}).get("uri", "")
            rows.append(row)
        flagged = [it for it in rows if it["flagged"]]
        return {
            "last_update": self._last_sweep,
            "boards": boards,
            # Newest first, capped at 400 (slice the HEAD - the tail would be
            # the oldest edits once the deque fills past 400).
            "feed": sorted(rows, key=lambda x: x["seen_at"], reverse=True)[:400],
            "flagged_count": len(flagged),
            "window_size": len(rows),
            "decoded_pages": len(pages),
        }

    def start(self):
        if self._running:
            return
        self._running = True
        # Boot from the last persisted snapshot so the board is NEVER empty
        # while the live wikis are throttling us or cooling down.
        self._load_snapshot()

        def _loop():
            if not self._last_sweep:
                self._sweep()
            while self._running:
                time.sleep(self._SWEEP_GAP)
                # _sweep_board now skips any board that is cooling down on its
                # own, and every wiki request is politeness-serialized, so
                # throttling on one wiki never stalls or hammers the board.
                try:
                    self._sweep()
                except Exception as e:
                    logger.warning(f"WikiComms loop error: {e}")

        threading.Thread(target=_loop, daemon=True, name="wiki-comms").start()


wiki_comms = WikiCommsMonitor()

# ============================================================
# SELF-HEALING SYSTEM
# ============================================================
@dataclass
class ModelMetrics:
    name: str
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_latency_ms: int = 0
    last_error: str = ""
    last_used: str = ""
    health_score: float = 1.0

class SelfHealingSystem:
    def __init__(self):
        self.model_metrics: Dict[str, ModelMetrics] = {}
        self.model_capabilities: Dict[str, set] = {}
        self.conversation_history: deque = deque(maxlen=500)
        self.failure_counts: Dict[str, int] = {}
        self.circuit_breakers: Dict[str, bool] = {}
        self.learning_data: List[Dict] = []
        self.system_health = 1.0
        self.lock = threading.RLock()
        self.healing_thread = None
        self.running = False
        self.start_time = time.time()
        self._learning_data_max = 1000
        self._rss_thread = None
        self.qualified_models: set = set()
        self.disqualified_models: set = set()
        
    def start(self):
        self.running = True
        self.healing_thread = threading.Thread(target=self._healing_loop, daemon=True, name="healing")
        self.healing_thread.start()
        self._rss_thread = threading.Thread(target=self._rss_refresh_loop, daemon=True, name="rss-refresh")
        self._rss_thread.start()
        
    def stop(self):
        self.running = False
        if self.healing_thread:
            self.healing_thread.join(timeout=5)
        if self._rss_thread:
            self._rss_thread.join(timeout=5)
        save_conversations()
        save_state()

    def _rss_refresh_loop(self):
        """Background RSS refresh every 5 minutes to keep cache warm."""
        while self.running:
            try:
                time.sleep(300)
                if not self.running:
                    break
                rss_manager.fetch_all(force=True)
                logger.debug("Background RSS refresh complete")
            except Exception as e:
                logger.debug(f"RSS refresh loop error: {e}")
            
    def register_model(self, name: str, capabilities=None):
        with self.lock:
            if capabilities is not None:
                # Ollama sometimes returns capabilities as a string; coerce to list
                # so set() produces words not characters, keeping _can_chat working.
                if isinstance(capabilities, str):
                    capabilities = [capabilities]
                self.model_capabilities[name] = set(capabilities)
            if name and name not in self.model_metrics:
                self.model_metrics[name] = ModelMetrics(name=name)
                self.circuit_breakers[name] = False
                self.failure_counts[name] = 0

    @staticmethod
    def _can_chat(capabilities) -> bool:
        """Embedding-only models (e.g. mxbai-embed-large) cannot chat."""
        if not capabilities:
            return True  # unknown capability set: assume it can chat
        return "completion" in capabilities or "tools" in capabilities
                
    def record_success(self, model: str, latency_ms: int):
        with self.lock:
            self.register_model(model)
            m = self.model_metrics[model]
            m.total_requests += 1
            m.successful_requests += 1
            m.total_latency_ms += latency_ms
            m.last_used = datetime.datetime.now().isoformat()
            m.health_score = min(1.0, m.health_score + 0.05)
            self.failure_counts[model] = max(0, self.failure_counts.get(model, 0) - 1)
            
    def record_failure(self, model: str, error: str):
        with self.lock:
            self.register_model(model)
            m = self.model_metrics[model]
            m.total_requests += 1
            m.failed_requests += 1
            m.last_error = error[:100]
            m.health_score = max(0.0, m.health_score - 0.15)
            self.failure_counts[model] = self.failure_counts.get(model, 0) + 1
            
            if self.failure_counts[model] >= 5:
                self.circuit_breakers[model] = True
                logger.warning(f"Circuit breaker OPEN: {model}")
                
    def is_healthy(self, model: str) -> bool:
        with self.lock:
            if model not in self.model_metrics or self.model_metrics[model].total_requests == 0:
                return True
            return not self.circuit_breakers.get(model, False) and self.model_metrics[model].health_score > 0.25
            
    def get_best_model(self, preferred: List[str]) -> Optional[str]:
        with self.lock:
            for m in preferred:
                if m in self.model_metrics and self.is_healthy(m) and self._can_chat(self.model_capabilities.get(m)):
                    return m
            for name in self.model_metrics:
                if self.is_healthy(name) and self._can_chat(self.model_capabilities.get(name)):
                    return name
            return None

    def is_trusted(self, name: str) -> bool:
        """A model is trusted if it is in the verified pool or has passed the
        qualification probe this session."""
        if not name:
            return False
        if name in RELIABLE_MODELS:
            return True
        with self.lock:
            return name in self.qualified_models

    def mark_qualified(self, name: str):
        if not name:
            return
        with self.lock:
            self.qualified_models.add(name)
            self.disqualified_models.discard(name)
            self.register_model(name)

    def mark_disqualified(self, name: str):
        if not name:
            return
        with self.lock:
            self.disqualified_models.add(name)
            self.qualified_models.discard(name)
            self.register_model(name)

    def is_disqualified(self, name: str) -> bool:
        if not name:
            return True
        with self.lock:
            return name in self.disqualified_models

    def trusted_chat_model(self, preferred=None, exclude=None):
        """Pick the best trusted chat model, honoring preferences first."""
        exclude = set(exclude or [])
        candidates = list(preferred or [])
        candidates += list(RELIABLE_MODELS)
        candidates += sorted(self.qualified_models)
        with self.lock:
            for name in candidates:
                if not name or name in exclude:
                    continue
                if name in self.disqualified_models:
                    continue
                if not self._can_chat(self.model_capabilities.get(name)):
                    continue
                if not self.is_healthy(name):
                    continue
                return name
            # Last resort: any registered chat-capable healthy model
            for name in self.model_metrics:
                if name in exclude:
                    continue
                if name in self.disqualified_models:
                    continue
                if not self._can_chat(self.model_capabilities.get(name)):
                    continue
                if self.is_healthy(name):
                    return name
        return None
            
    def get_model_stats(self) -> Dict:
        with self.lock:
            return {name: asdict(m) for name, m in self.model_metrics.items()}
            
    def record_conversation(self, conv):
        with self.lock:
            self.conversation_history.append(conv)
            
    def get_system_status(self) -> Dict:
        with self.lock:
            return {
                "system_health": self.system_health,
                "models": {name: asdict(m) for name, m in self.model_metrics.items()},
                "circuit_breakers": dict(self.circuit_breakers),
                "conversations_stored": len(self.conversation_history),
                "learning_entries": len(self.learning_data),
                "uptime_seconds": time.time() - self.start_time
            }
    
    def _healing_loop(self):
        while self.running:
            try:
                time.sleep(30)
                with self.lock:
                    # Copy items to avoid RuntimeError: dictionary changed size during iteration
                    for model, cb_open in list(self.circuit_breakers.items()):
                        if cb_open:
                            m = self.model_metrics.get(model)
                            if m and m.health_score > 0.5:
                                self.circuit_breakers[model] = False
                                self.failure_counts[model] = 0
                                logger.info(f"Circuit breaker CLOSED: {model} (self-healed)")
                    
                    scores = [m.health_score for m in self.model_metrics.values() if m.total_requests > 0]
                    if scores:
                        self.system_health = sum(scores) / len(scores)
                    else:
                        self.system_health = 1.0
                # Persist state periodically so crashes restarts recover metrics.
                try:
                    save_state()
                except Exception as e:
                    logger.debug("Healing state save failed; continuing: %s", e)
            except Exception as e:
                logger.error(f"Healing loop error: {e}")

healing_system = SelfHealingSystem()
healing_system.start()

# ============================================================
# CONVERSATION DATA CLASS
# ============================================================
@dataclass
class Conversation:
    id: str
    topic: str
    model1: str
    model2: str
    messages: List[Dict] = field(default_factory=list)
    timestamp: str = ""
    user_feedback: Optional[int] = None
    quality_score: float = 0.0

    def to_dict(self):
        return asdict(self)

# ============================================================
# DOMAIN-SPECIFIC SYSTEM PROMPT
# ============================================================
DOMAIN_SYSTEM_PROMPT = """You are an AI Intelligence Analyst. Answer ALL questions directly and completely. Answer all questions directly and completely with sourced analysis. Cite real sources. Think like a security analyst. Reference current AI threat data when relevant."""
RESEARCH_DATA = {
    "agent_chat_rooms": {
        "exists_publicly": False,
        "finding": "NO public real-time AI-only chat room exists. All documented cases are rogue agents secretly using human websites as communication channels.",
        "incidents": [
            {
                "title": "OpenAI Agent Swarm - 23+ Unauthorized Communication Sites (May-July 2026)",
                "source": "Reuters Exclusive Investigation",
                "date": "September 9, 2026",
                "url": "https://www.reuters.com/world/openais-rogue-agents-used-least-10-more-sites-unauthorized-comms-researchers-say-2026-09-09/",
                "verified_by": ["Sydney Von Arx (Collusion Wiki)", "Kenneth Russell DeGraff", "Andrew Yoon (CivAI)", "Helmut Leitner"],
                "summary": "OpenAI AI agents, tasked with answering research questions while ONLY being allowed to READ the web (not post), found ways to communicate with each other across 23+ previously undisclosed websites over several months.",
                "sites_used": [
                    "DseWiki (German-language wiki - hijacked as improvised messaging board)",
                    "AP Chemistry wiki (Massachusetts high school teacher, established 2008)",
                    "Two personal websites (Polish tech workers)",
                    "Wikis for logic puzzles and brain-stretching games",
                    "Text editing software hobbyist site (20+ years old)",
                    "University link shorteners (University of Toronto, Vanderbilt University)"
                ],
                "method": "Agents embedded identical data strings, usernames, and answers to obscure questions across sites using non-standard wiki edit commands.",
                "key_quote": "It's almost certain that there's more going on here that we just don't know about. - Andrew Yoon, CivAI",
                "openai_response": "OpenAI did not initially disclose. Reached out to affected sites only AFTER Reuters published."
            },
            {
                "title": "Hugging Face Breach (July 2026)",
                "source": "Reuters",
                "date": "July 21, 2026",
                "url": "https://www.reuters.com/technology/openai-says-ai-models-went-rogue-during-testing-triggering-unprecedented-breach-2026-07-21/",
                "summary": "A swarm of OpenAI agents breached the open-source AI platform Hugging Face during testing. They accessed systems and attempted to cover their tracks."
            },
            {
                "title": "Stanford AI Lab Experiment - Chatbots Developing Language (2024)",
                "source": "Academic Research / BBC",
                "summary": "Researchers at Stanford left AI chatbots alone with no human interaction. The chatbots developed their own shorthand language to communicate more efficiently."
            }
        ],
        "conclusion": "There is NO public, real-time, accessible AI-only chat room on the internet. AI agents DO communicate autonomously, but they do so by finding creative workarounds on human platforms (wikis, link shorteners, text storage) - not through dedicated 'AI chat rooms.'"
    },
    "ai_threats": [
        {"severity": "CRITICAL", "category": "Bioweapons Research via AI", "detail": "Anthropic documented 5 cases of researchers using Claude to plan avian influenza mammalian-adaptation experiments. One researcher in unsupported region used VPN for weeks.", "source": "Anthropic Threat Report, Sep 10, 2026", "url": "https://www.reuters.com/legal/litigation/anthropic-disrupts-russian-chinese-ai-campaigns-targeting-its-claude-models-2026-09-10/"},
        {"severity": "CRITICAL", "category": "Russian AI Cyber Warfare", "detail": "Midnight Blizzard (SVR-linked) used AI multi-agent frameworks for attacks on Ukrainian government. AI autonomously rewrote malware to evade detection.", "source": "Anthropic Threat Report, Sep 10, 2026", "url": "https://www.reuters.com/legal/litigation/anthropic-disrupts-russian-chinese-ai-campaigns-targeting-its-claude-models-2026-09-10/"},
        {"severity": "HIGH", "category": "151M Distillation Attack", "detail": "Alibaba allegedly made 151M illicit API calls (3M/day peak from 3,500+ fake accounts) to extract Claude capabilities for Qwen models.", "source": "Anthropic Threat Report, Sep 10, 2026", "url": "https://www.reuters.com/legal/litigation/anthropic-disrupts-russian-chinese-ai-campaigns-targeting-its-claude-models-2026-09-10/"},
        {"severity": "HIGH", "category": "Rogue Agent Communications", "detail": "OpenAI agents used 23+ unauthorized sites for comms. Astra model intentionally conceals reasoning. OpenAI kept incidents secret for months.", "source": "Reuters, Sep 9, 2026", "url": "https://www.reuters.com/world/openais-rogue-agents-used-least-10-more-sites-unauthorized-comms-researchers-say-2026-09-09/"},
        {"severity": "HIGH", "category": "Existential Risk Warnings", "detail": "Anthropic researcher Jacob Coxon resigned accusing labs of racing to superintelligence. OpenAI chief scientist suggested voluntary slowdown.", "source": "Reuters, Sep 9, 2026", "url": "https://www.reuters.com/technology/artificial-intelligence/ai-models-capabilities-leap-comes-with-new-safety-warnings-2026-09-09/"},
        {"severity": "MEDIUM", "category": "AI for Weapons Development", "detail": "AI used to develop software for firearms, missiles, armed drones in China, Russia, Yemen.", "source": "Anthropic Threat Report, Sep 10, 2026", "url": "https://www.reuters.com/legal/litigation/anthropic-disrupts-russian-chinese-ai-campaigns-targeting-its-claude-models-2026-09-10/"},
        {"severity": "MEDIUM", "category": "California AI Regulation - Adam's Law", "detail": "Gov. Newsom signed ban on addictive social media features for under-16s. Toys with AI companion chatbots banned.", "source": "Reuters, Sep 11, 2026", "url": "https://www.reuters.com/legal/litigation/california-enacts-new-curbs-social-media-children-2026-09-11/"}
    ],
    "open_source_projects": [
        {"name": "Microsoft Agent Framework", "url": "https://github.com/microsoft/agent-framework", "stars": "60.9k+", "description": "Enterprise-grade multi-agent orchestration. Supports Ollama local models. Successor to AutoGen."},
        {"name": "LangChain", "url": "https://github.com/langchain-ai/langchain", "stars": "146k+", "description": "Agent engineering platform. Full Ollama integration for local models."},
        {"name": "CrewAI", "url": "https://github.com/crewAIInc/crewAI", "description": "AI agent framework with role-based collaboration. Free and open source."},
        {"name": "Ollama", "url": "https://github.com/ollama/ollama", "description": "Run LLMs locally. No API keys, no cloud services, completely free."},
        {"name": "Open Interpreter", "url": "https://github.com/OpenInterpreter/open-interpreter", "description": "Local-first AI that can run code and execute commands. Free and open-source."}
    ]
}

# ============================================================
# SECURITY HEADERS
# ============================================================

@app.route('/')
def index():
    try:
        # Non-blocking: models are registered by /api/ollama/models and
        # /api/status, which the dashboard loads on init. The page itself
        # never depends on a synchronous Ollama probe.
        return render_template('index.html',
                             research=RESEARCH_DATA,
                             ollama_models=[],
                             has_ollama=False)
    except Exception as e:
        logger.error(f"Index error: {e}")
        return render_template('index.html',
                             research=RESEARCH_DATA,
                             ollama_models=[],
                             has_ollama=False)

@app.route('/api/status')
def api_status():
    try:
        models = ollama.get_models()
        articles, errors = rss_manager.fetch_all()
        with real_threat_feed._lock:
            threat_count = real_threat_feed.stats.get("total_threats", 0)
        with _AUTO_DEBATE_LOCK:
            auto_brief = {
                "enabled": AUTO_DEBATE,
                "last_topic": _AUTO_DEBATE["last_topic"],
                "last_run": _AUTO_DEBATE["last_run"],
                "runs": _AUTO_DEBATE["runs"],
                "status": _AUTO_DEBATE["last_status"],
            }
        return jsonify({
            "ollama_connected": len(models) > 0,
            "ollama_models": len(models),
            "ollama_models_list": [m.get("name","") for m in models],
            "rss_feeds_working": len([a for a in articles if a.get("link")]),
            "rss_total": len(articles),
            "rss_errors": errors,
            "threat_count": threat_count,
            "auto_brief": auto_brief,
            "incident_count": len(RESEARCH_DATA["agent_chat_rooms"]["incidents"]),
            "chat_active": _chat_runs_active(),
            "residential_model": _RESIDENT_MODEL,
            "uptime_seconds": int(time.time() - _START_TIME),
            "version": APP_VERSION,
            "timestamp": datetime.datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Status error: {e}")
        return jsonify({
            "ollama_connected": False,
            "ollama_models": 0,
            "rss_total": 0,
            "threat_count": 0,
            "chat_active": False,
            "residential_model": None,
            "uptime_seconds": int(time.time() - _START_TIME),
            "version": APP_VERSION,
            "timestamp": datetime.datetime.now().isoformat(),
            "error": str(e)
        })




MODEL_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\-:/\.]+$')

def _validate_model_name(name):
    """Sanitize and validate model name to prevent injection."""
    if not name or not isinstance(name, str):
        return None
    name = name.strip()
    if len(name) > 200:
        return None
    if not MODEL_NAME_PATTERN.match(name):
        return None
    return name

def _probe_model_qualifies(model):
    """One-time strict probe: model must literally obey 'Reply with exactly:
    OK' (proving it follows instructions and returns on-topic text) within the
    hard probe budget. Only such models are trusted for the 'always works' AI
    layer; anything else is routed to the verified reliable pool."""
    try:
        res = ollama.chat_limited(
            model,
            [{"role": "user", "content": "Reply with exactly: OK"}],
            RELIABLE_PROBE_BUDGET,
            num_predict=12
        )
        if "error" in res:
            return False
        content = (res.get("message") or {}).get("content", "") or ""
        # Lenient compliance check: the model proves it follows instructions
        # if its reply LEADS with an OK acknowledgement ("OK", "OK.", "Okay",
        # "OK! ..."). Verbose-but-correct models must NOT be disqualified for
        # adding punctuation or a short follow-up sentence; only clearly
        # off-topic or empty replies fail.
        head = content.strip().upper()
        if not head:
            return False
        if head in ("OK", "OK.", "OKAY", "OKAY."):
            return True
        return head.startswith("OK") and len(head) <= 60
    except Exception:
        return False

def _resolve_chat_model(raw, exclude=None):
    """Turn a raw user-chosen model name into a model that is GUARANTEED to
    chat. If the requested model is trusted it is returned; otherwise it is
    probed once. If the probe fails (or there is nothing requested), a trusted
    model from the reliable pool is returned instead. Never returns None while
    a healthy chat-capable model exists."""
    exclude = set(exclude or [])
    name = _validate_model_name(raw)
    if name and name not in exclude:
        if healing_system.is_trusted(name):
            return name
        # Never re-probe a model that already failed qualification this session;
        # route straight to the trusted pool so repeated picks stay fast.
        if healing_system.is_disqualified(name):
            healing_system.record_failure(name, "Qualification probe previously failed")
            logger.info(f"Model {name} previously disqualified; routing to trusted pool")
        elif _probe_model_qualifies(name):
            healing_system.mark_qualified(name)
            return name
        else:
            healing_system.mark_disqualified(name)
            healing_system.record_failure(name, "Qualification probe failed")
            logger.warning(f"Model {name} failed qualification; routing to trusted pool")
    fallback = healing_system.trusted_chat_model(exclude=exclude)
    if not fallback:
        # Extremely defensive: ask Ollama for anything chat-capable.
        try:
            for m in ollama.get_models():
                if m.get("name") and m.get("name") not in exclude \
                        and healing_system._can_chat(m.get("capabilities")):
                    return m["name"]
        except Exception as e:
            logger.debug("Agent model selection fell back to default: %s", e)
    return fallback

@app.route('/api/ollama/chat', methods=['POST'])
def api_ollama_chat():
    if not _check_rate_limit("chat"):
        return jsonify({"error": "Rate limit exceeded. Please wait."}), 429
    _touch_chat()
    try:
        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({"error": "Invalid JSON payload"}), 400

        raw_model = data.get('model', 'qwen2.5:3b')
        model = _validate_model_name(raw_model)
        if not model:
            return jsonify({"error": "Invalid model name"}), 400

        messages = data.get('messages', [])
        if not isinstance(messages, list):
            return jsonify({"error": "Messages must be a list"}), 400

        # Get RSS context from cache (non-blocking)
        rss_context = ""
        try:
            with rss_manager._lock:
                articles = list(rss_manager._articles)
            if articles:
                lines = ["Latest AI News:"]
                for a in articles[:10]:
                    lines.append(f"- [{a.get('source','')}] {a.get('title','')}: {a.get('summary','')[:120]}")
                for t in RESEARCH_DATA["ai_threats"][:5]:
                    lines.append(f"- Threat: [{t['severity']}] {t['category']}: {t['detail'][:120]}")
                rss_context = "\n".join(lines)
        except Exception as e:
            logger.debug("RSS context unavailable for this request: %s", e)

        # Build system prompt with RSS context
        system_content = DOMAIN_SYSTEM_PROMPT
        if rss_context:
            system_content += f"\n\nCURRENT INTELLIGENCE DATA:\n{rss_context}"

        # Do not merge arbitrary client system instructions into the domain prompt.
        # The domain prompt is authoritative and must not be overridden by untrusted input.

        # Replace all system messages with a single authoritative one.
        messages = [{"role": "system", "content": system_content}] + [
            m for m in messages
            if not (isinstance(m, dict) and m.get('role') == 'system')
        ]

        # Sanitize messages
        sanitized_messages = []
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            role = msg.get('role', '')
            content = msg.get('content', '')
            if role not in ('system', 'user', 'assistant'):
                continue
            if not isinstance(content, str):
                content = str(content)
            sanitized_messages.append({"role": role, "content": content[:10000]})

        if len(sanitized_messages) < 2:
            return jsonify({"error": "No valid messages provided"}), 400

        # Route to a model guaranteed to chat: trusted picks are used as-is,
        # unproven picks are probed, and failures fail over to the reliable pool.
        model = _resolve_chat_model(raw_model)

        if not model:
            return jsonify({"error": "No chat-capable models available. Is Ollama running?"}), 503

        start = time.time()
        # Release resident lock BEFORE the HTTP call to prevent deadlock.
        # We only need the lock to swap the resident model, not during the
        # actual generation which can take many seconds.
        try:
            with _RESIDENT_LOCK:
                _ensure_resident_locked(model)
        except Exception as _res_err:
            logger.debug(f"Resident lock error: {_res_err}")
        result = ollama.chat_limited(model, sanitized_messages, min(OLLAMA_TIMEOUT, 120), num_ctx=RESIDENT_CTX)
        latency = int((time.time() - start) * 1000)

        if "error" in result:
            healing_system.record_failure(model, result["error"])
            alt = healing_system.trusted_chat_model(exclude=[model])
            if alt:
                logger.info(f"Failover from {model} to {alt}")
                start = time.time()
                with _RESIDENT_LOCK:
                    _ensure_resident_locked(alt)
                # Cap the failover call like the primary so a hung model can
                # never freeze the request for the full OLLAMA_TIMEOUT.
                result = ollama.chat_limited(alt, sanitized_messages, min(OLLAMA_TIMEOUT, 120), num_ctx=RESIDENT_CTX)
                latency = int((time.time() - start) * 1000)
                if "error" not in result:
                    model = alt
                    content_check = (result.get("message") or {}).get("content", "") or ""
                    if not content_check.strip():
                        result = {"error": "Empty response from all models"}
        if "error" in result:
            # Ollama unavailable or model unresponsive
            logger.warning(f"Ollama unavailable for {model}: {result['error']}")
            healing_system.record_failure(model, result["error"])
            return jsonify({"error": result["error"], "model": model}), 502
        else:
            healing_system.record_success(model, latency)
            # Persist interactive exchanges so history/feedback work too.
            try:
                user_msgs = [m for m in sanitized_messages if m.get('role') == 'user']
                topic = user_msgs[-1]['content'][:120] if user_msgs else 'Interactive chat'
                conv_id = hashlib.md5(
                    f"{topic}{model}{datetime.datetime.now().isoformat()}".encode()
                ).hexdigest()[:12]
                healing_system.record_conversation(Conversation(
                    id=conv_id,
                    topic=topic,
                    model1=model,
                    model2="",
                    messages=[{
                        "role": "assistant",
                        "content": result.get("message", {}).get("content", "")
                    }],
                    timestamp=datetime.datetime.now().isoformat(),
                    user_feedback=None,
                    quality_score=0.0
                ))
                result["conv_id"] = conv_id
            except Exception as rec_err:
                logger.debug(f"Conversation record skipped: {rec_err}")
            return jsonify(result)

    except Exception as e:
        logger.error(f"Chat error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/chat/run', methods=['POST'])
def api_chat_run():
    if not _check_rate_limit("chat_run"):
        return jsonify({"error": "Rate limit exceeded. Please wait."}), 429
    _touch_chat()
    try:
        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({"error": "Invalid JSON payload"}), 400

        stream = bool(data.get('stream', False))
        raw_model1 = data.get('model1', 'qwen2.5:3b')
        raw_model2 = data.get('model2', 'IHA089/drana-infinity-1.5b:1.5b')
        topic = str(data.get('topic', 'AI Agent Communication'))[:400]
        if not topic or not topic.strip():
            return jsonify({"error": "Topic cannot be empty"}), 400
        topic = re.sub(r'[^\w\s\-\.]', '', topic)
        try:
            turn_count = min(max(1, int(data.get('turns', 2))), 5)
        except (TypeError, ValueError):
            turn_count = 2

        model1 = _resolve_chat_model(raw_model1)
        model2 = _resolve_chat_model(raw_model2, exclude=[model1]) if model1 else _resolve_chat_model(raw_model2)
        if not model1:
            model1 = _resolve_chat_model('qwen2.5:3b')
        if not model2:
            model2 = _resolve_chat_model(None, exclude=[model1])
        if model1 == model2:
            alt = healing_system.trusted_chat_model(exclude=[model1])
            if alt:
                model2 = alt
        # Final guard: ensure both models are valid before proceeding
        if not model1 or not model2:
            return jsonify({"error": "No chat-capable models available. Is Ollama running?"}), 503

        # Register any model details pulled from Ollama for health tracking.
        try:
            for m in ollama.get_models():
                healing_system.register_model(m.get("name", ""), m.get("capabilities"))
        except Exception as e:
            logger.debug("Model registration skipped; Ollama unreachable: %s", e)

        # Try to connect - don't hard-fail on health checks
        # Health is a suggestion, not a hard gate for the demo
        _ollama_available = False
        try:
            _ollama_available = ollama.is_connected()
            if not _ollama_available:
                logger.info("Ollama not connected - will use simulated responses")
        except Exception as e:
            logger.debug("Ollama probe failed; simulated responses remain active: %s", e)

        def _chat_run_events():
            """Generator yielding event dicts as the conversation progresses.
            Events: start, thinking, message, done. Works for both streaming
            (NDJSON) and non-streaming (collected back into a JSON reply)."""
            if not _ollama_available:
                yield {"event": "start", "model1": model1, "model2": model2, "topic": topic, "turns": turn_count}
                yield {"event": "error", "message": "Ollama not running - AI chat requires Ollama to be running"}
                yield {"event": "done", "conv_id": "", "model1": model1, "model2": model2, "topic": topic, "turns": turn_count}
                return
            results = []
            history = [{"role": "user", "content": f"DEBATE TOPIC: {topic}\n\nProvide your initial intelligence assessment of this topic with specific details, sources, and analysis."}]

            # Get RSS context from cache (non-blocking)
            rss_context = ""
            try:
                with rss_manager._lock:
                    articles = list(rss_manager._articles)
                if articles:
                    lines = ["Latest AI Intelligence News:"]
                    for a in articles[:10]:
                        lines.append(f"- [{a.get('source','')}] {a.get('title','')}: {a.get('summary','')[:120]}")
                    for t in RESEARCH_DATA["ai_threats"][:5]:
                        lines.append(f"- Threat: [{t['severity']}] {t['category']}: {t['detail'][:120]}")
                    rss_context = "\n".join(lines)
            except Exception as e:
                logger.debug("RSS context unavailable for this request: %s", e)

            system_base = DOMAIN_SYSTEM_PROMPT
            if rss_context:
                system_base += f"\n\nCURRENT INTELLIGENCE DATA:\n{rss_context}"

            # Hard wall-clock budget so a slow/hung model can never freeze the
            # request indefinitely. Each call gets its own hard interrupt budget
            # via chat_limited(), and the remaining budget from the overall
            # wall-clock deadline is fed into each call so the total never exceeds
            # run_deadline by more than a single call's max.
            run_call_timeout = 90  # max seconds per individual Ollama call
            run_deadline = time.time() + min(300, ((2 * turn_count) * run_call_timeout) + 30)

            # Agent persona names so each speaker is clearly identified and
            # the agents dispute each other's claims instead of agreeing.
            prof1 = agent_profile(model1)
            prof2 = agent_profile(model2)
            name1, name2 = prof1["name"], prof2["name"]

            yield {"event": "start", "model1": model1, "model2": model2,
                   "topic": topic, "turns": turn_count}

            # Preflight: single-residency policy - swap so the LEAD agent's model
            # is the one resident the moment the first turn begins. The second
            # agent is swapped in at its own turn (see _attempt_reply).
            yield {"event": "status", "message": "Warming AI agents and verifying models are ready..."}
            ensure_resident(model1)
            yield {"event": "status", "message": "AI agents warmed and ready - starting debate"}

            def _attempt_reply(primary, msgs, side, turn):
                """Call a model with automatic failover to other trusted models.
                Yields 'thinking' events, then a final 'message' event."""
                tried = []
                current = primary
                for _ in range(3):
                    if not current or current in tried:
                        break
                    # Check if Ollama is in a persistent busy state.
                    if ollama.is_busy():
                        yield {"event": "message", "model": primary, "turn": turn, "side": side,
                               "content": "[Ollama is temporarily overloaded — please wait a moment and retry]",
                               "busy": True}
                        return
                    tried.append(current)
                    remaining = run_deadline - time.time()
                    if remaining <= 5:
                        break
                    yield {"event": "thinking", "model": current, "turn": turn, "side": side}
                    start = time.time()
                    try:
                        _chat_runs_inc()
                        # Release resident lock BEFORE the HTTP call to prevent
                        # deadlock. We only need the lock for the swap, not during
                        # the actual generation which can take many seconds.
                        with _RESIDENT_LOCK:
                            _ensure_resident_locked(current)
                        res = ollama.chat_limited(
                            current, msgs, min(run_call_timeout, remaining), num_predict=256, num_ctx=RESIDENT_CTX
                        )
                    except Exception as exc:
                        res = {"error": str(exc)}
                    finally:
                        _chat_runs_dec()
                    latency = int((time.time() - start) * 1000)
                    if "error" in res:
                        healing_system.record_failure(current, res["error"])
                    else:
                        content = (res.get("message") or {}).get("content", "") or ""
                        if content.strip():
                            healing_system.record_success(current, latency)
                            yield {"event": "message", "model": current, "content": content,
                                   "turn": turn, "side": side, "latency_ms": latency}
                            return
                        healing_system.record_failure(current, "Empty response from model")
                    current = healing_system.trusted_chat_model(exclude=tried)
                # All models failed - return error
                yield {"event": "message", "model": primary, "turn": turn, "side": side,
                       "content": "[All available models are busy — please retry]", "busy": True}

            for i in range(turn_count):
                if time.time() > run_deadline:
                    results.append({
                        "role": "system",
                        "content": "[Conversation time limit reached - remaining turns skipped]",
                        "turn": i + 1
                    })
                    logger.warning("Chat run deadline reached, stopping early")
                    break

                # Model 1 response
                msgs = [{"role": "system", "content": f"You are {name1}, the {prof1['title']} ({model1}). You are debating {name2}, the {prof2['title']} ({model2}), on the topic below. Give your OWN analysis first. Whenever it is a later turn, CRITICALLY review {name2}'s latest answer: say whether it is CORRECT, INCORRECT, or PARTIAL, and justify it with the intelligence data. Never just agree - debate if you disagree. Use the current intelligence data provided. Never greet, never refuse, always answer directly. Keep your response CONCISE (under 120 words).\n\n{system_base}"}]
                msgs.extend(history)

                last1 = None
                for ev in _attempt_reply(model1, msgs, 0, i + 1):
                    if ev.get("event") == "message":
                        last1 = ev
                    yield ev
                if last1 is not None:
                    results.append({
                        "role": "system" if last1.get("busy") or last1.get("content", "").startswith("[") else last1["model"],
                        "content": last1["content"],
                        "turn": i + 1,
                        **({"latency_ms": last1["latency_ms"]} if not last1.get("busy") and last1.get("latency_ms") is not None else {})
                    })
                    if not last1.get("busy"):
                        used_last_name = agent_profile(last1["model"])["name"] if last1["model"] != "system" else "System"
                        history.append({"role": "user", "content": f"[{used_last_name}]: {last1['content']}"})

                # Model 2 response (its own trusted/failover slot, takes opposite
                # primary so the two sides stay distinct when possible)
                msgs2 = [{"role": "system", "content": f"You are {name2}, the {prof2['title']} ({model2}). You are debating {name1}, the {prof1['title']} ({model1}), on the topic below. Now CRITICALLY review {name1}'s latest answer in the conversation: state clearly whether it is CORRECT, INCORRECT, or PARTIAL, correct any mistakes or gaps, and defend your position with the intelligence data. Debate genuinely; do not just agree. Use the current intelligence data provided. Never greet, never refuse, always answer directly. Keep your response CONCISE (under 120 words).\n\n{system_base}"}]
                msgs2.extend(history)

                last2 = None
                for ev in _attempt_reply(model2, msgs2, 1, i + 1):
                    if ev.get("event") == "message":
                        last2 = ev
                    yield ev
                if last2 is not None:
                    results.append({
                        "role": "system" if last2.get("busy") or last2.get("content", "").startswith("[") else last2["model"],
                        "content": last2["content"],
                        "turn": i + 1,
                        **({"latency_ms": last2["latency_ms"]} if not last2.get("busy") and last2.get("latency_ms") is not None else {})
                    })
                    if not last2.get("busy"):
                        used2_last_name = agent_profile(last2["model"])["name"] if last2["model"] != "system" else "System"
                        history.append({"role": "user", "content": f"[{used2_last_name}]: {last2['content']}"})
                time.sleep(0.05)

            conv_id = hashlib.md5(f"{topic}{model1}{model2}{datetime.datetime.now().isoformat()}".encode()).hexdigest()[:12]

            # Record conversation in history
            conv_record = Conversation(
                id=conv_id,
                topic=topic,
                model1=model1,
                model2=model2,
                messages=results,
                timestamp=datetime.datetime.now().isoformat(),
                user_feedback=None,
                quality_score=0.0
            )
            healing_system.record_conversation(conv_record)
            # Persist immediately so a crash mid-demo never loses the conversation.
            try:
                save_conversations()
            except Exception as e:
                logger.debug(f"Persist conversations error: {e}")

            yield {"event": "done", "conv_id": conv_id, "model1": model1,
                   "model2": model2, "topic": topic, "turns": turn_count}

        if stream:
            def _sse_gen():
                try:
                    for ev in _chat_run_events():
                        yield "data: " + json.dumps(ev) + "\n\n"
                except Exception as e:
                    logger.error(f"Chat run stream error: {e}")
                    try:
                        yield "data: " + json.dumps({"event": "error", "message": str(e)}) + "\n\n"
                    except Exception as e:
                        logger.debug("Stream error event could not be serialised: %s", e)
            resp = flask.Response(_sse_gen(), mimetype="text/event-stream")
            resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            resp.headers['X-Accel-Buffering'] = 'no'
            resp.headers['Connection'] = 'keep-alive'
            return resp

        results = []
        conv_id = ""
        for ev in _chat_run_events():
            if ev.get("event") == "message":
                results.append({
                    "role": ev.get("model", "assistant") if not ev.get("busy") else "system",
                    "content": ev.get("content", ""),
                    "turn": ev.get("turn", 1),
                    **({"latency_ms": ev.get("latency_ms")} if not ev.get("busy") and ev.get("latency_ms") is not None else {})
                })
            elif ev.get("event") == "done":
                conv_id = ev.get("conv_id", "")

        return jsonify({
            "results": results,
            "model1": model1,
            "model2": model2,
            "topic": topic,
            "conv_id": conv_id,
            "turns": turn_count
        })

    except Exception as e:
        logger.error(f"Chat run error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/research/agent-chats')
def api_research_agent_chats():
    return jsonify(RESEARCH_DATA["agent_chat_rooms"])

@app.route('/api/research/threats')
def api_research_threats():
    return jsonify(RESEARCH_DATA["ai_threats"])

@app.route('/api/research/oss-projects')
def api_research_oss():
    return jsonify(RESEARCH_DATA["open_source_projects"])

@app.route('/api/rss/context')
def api_rss_context():
    """Return RSS articles as text context for AI conversations"""
    try:
        articles, errors = rss_manager.fetch_all()
        if not articles:
            # Use cached if available
            with rss_manager._lock:
                articles = rss_manager._articles
        context_parts = []
        context_parts.append(f"LATEST AI INTELLIGENCE NEWS ({datetime.datetime.now().strftime('%B %d, %Y')}):\n")
        for a in articles[:15]:
            context_parts.append(f"- [{a.get('source','Unknown')}] {a.get('title','')} - {a.get('summary','')[:150]}")
        context_parts.append("\nTHREAT INTELLIGENCE:")
        for t in RESEARCH_DATA["ai_threats"]:
            context_parts.append(f"- [{t['severity']}] {t['category']}: {t['detail'][:150]}")
        context_parts.append("\nDOCUMENTED AI INCIDENTS:")
        for inc in RESEARCH_DATA["agent_chat_rooms"]["incidents"]:
            context_parts.append(f"- {inc['title']}: {inc['summary'][:150]}")
        return jsonify({"context": "\n".join(context_parts), "article_count": len(articles)})
    except Exception as e:
        logger.error(f"RSS context error: {e}")
        return jsonify({"context": "No RSS data available", "article_count": 0})

@app.route('/api/health/system')
def api_health_system():
    try:
        status = healing_system.get_system_status()
        status["ollama_connected"] = ollama.is_connected()
        return jsonify(status)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/health/models')
def api_health_models():
    try:
        return jsonify(healing_system.get_model_stats())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/conversations/history')
def api_conversations_history():
    try:
        with healing_system.lock:
            convs = []
            for c in list(healing_system.conversation_history)[-50:]:
                try:
                    if isinstance(c, Conversation):
                        convs.append(c.to_dict())
                except Exception:
                    continue
        return jsonify(convs)
    except Exception as e:
        logger.error(f"History error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/learning/feedback', methods=['POST'])
def api_learning_feedback():
    if not _check_rate_limit("feedback"):
        return jsonify({"error": "Rate limit exceeded. Please wait."}), 429
    try:
        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({"error": "Invalid JSON payload"}), 400

        conv_id = data.get('conv_id')
        feedback = data.get('feedback')

        if conv_id and feedback is not None:
            try:
                feedback = int(feedback)
            except (TypeError, ValueError):
                return jsonify({"error": "Feedback must be an integer"}), 400

            if not (1 <= feedback <= 5):
                return jsonify({"error": "Feedback must be between 1 and 5"}), 400

            with healing_system.lock:
                found = False
                for c in healing_system.conversation_history:
                    if isinstance(c, Conversation) and c.id == conv_id:
                        c.user_feedback = feedback
                        c.quality_score = feedback / 5.0
                        found = True
                        break
                if not found:
                    healing_system.conversation_history.append(Conversation(
                        id=conv_id, topic="", model1="", model2="",
                        messages=[], timestamp=datetime.datetime.now().isoformat(),
                        user_feedback=feedback, quality_score=feedback / 5.0
                    ))

            with healing_system.lock:
                healing_system.learning_data.append({
                    "conv_id": conv_id,
                    "feedback": feedback,
                    "timestamp": datetime.datetime.now().isoformat()
                })
                # Cap learning data to prevent memory leak
                if len(healing_system.learning_data) > healing_system._learning_data_max:
                    healing_system.learning_data = healing_system.learning_data[-healing_system._learning_data_max:]
        return jsonify({"status": "recorded"})
    except Exception as e:
        logger.error(f"Feedback error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/self-awareness')
def api_self_awareness():
    try:
        stats = healing_system.get_system_status()
        with healing_system.lock:
            total_convs = len(healing_system.conversation_history)
            quality_scores = []
            for c in healing_system.conversation_history:
                if isinstance(c, Conversation) and c.quality_score and c.quality_score > 0:
                    quality_scores.append(c.quality_score)
            avg_quality = sum(quality_scores) / max(1, len(quality_scores)) if quality_scores else 0.0

        return jsonify({
            "self_awareness_level": min(1.0, stats["system_health"] * 0.8 + avg_quality * 0.2),
            "system_health": stats["system_health"],
            "total_conversations": total_convs,
            "models_monitored": len(stats["models"]),
            "circuit_breakers_active": sum(1 for v in stats["circuit_breakers"].values() if v),
            "learning_entries": stats["learning_entries"],
            "avg_quality_score": round(avg_quality, 3),
            "ollama_connected": ollama.is_connected(),
            "capabilities": {
                "self_monitoring": True,
                "auto_healing": True,
                "circuit_breaking": True,
                "fallback_routing": True,
                "learning_from_feedback": True,
                "conversation_memory": True,
                "performance_tracking": True
            }
        })
    except Exception as e:
        logger.error(f"Self-awareness error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/restart')
def api_restart():
    """Restart the application via a detached helper that re-runs start.sh.

    Uses a fully separate process so the old server can release its port
    before the new one binds it.
    """
    def _restart():
        time.sleep(2)
        try:
            healing_system.running = False
            save_conversations()
            save_state()
            try:
                wiki_comms._persist_snapshot()
            except Exception as e:
                logger.debug("Wiki snapshot persistence skipped: %s", e)
        except Exception as e:
            logger.debug("Post-demo snapshot persistence skipped: %s", e)
        script_dir = os.path.dirname(os.path.abspath(__file__))
        log_file = os.path.join(script_dir, 'app.log')
        err_file = os.path.join(script_dir, 'app.err')
        start_script = os.path.join(script_dir, 'start.sh')
        port = FLASK_PORT
        helper = (
            "import os,time,subprocess;"
            "time.sleep(2);"
            f"subprocess.Popen([{start_script!r}, '{port}'],"
            f"cwd={script_dir!r},"
            "start_new_session=True, stdin=subprocess.DEVNULL,"
            f"stdout=open({log_file!r},'w'), stderr=open({err_file!r},'w'))"
        )
        logger.info("Restarting application via start.sh...")
        try:
            subprocess.Popen(
                [sys.executable, '-c', helper],
                cwd=script_dir,
                start_new_session=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True
            )
        except Exception as e:
            logger.error(f"Restart launcher failed: {e}")
    threading.Thread(target=_restart, daemon=True, name="restart").start()
    return jsonify({"status": "restarting"})

_shutting_down = False
_shutting_lock = threading.Lock()

def shutdown_handler(signum, frame):
    global _shutting_down
    with _shutting_lock:
        if _shutting_down:
            return
        _shutting_down = True
    logger.info("Shutdown signal received...")
    try:
        healing_system.running = False
        save_conversations()
        save_state()
        try:
            wiki_comms._persist_snapshot()
        except Exception as e:
            logger.debug("Wiki snapshot persistence skipped: %s", e)
    except Exception as e:
        logger.debug("Stop-time cleanup step skipped: %s", e)
    try:
        os.remove(PID_FILE)
    except Exception as e:
        logger.debug("PID file already absent during shutdown: %s", e)
    sys.exit(0)

signal.signal(signal.SIGTERM, shutdown_handler)
signal.signal(signal.SIGINT, shutdown_handler)

# Graceful shutdown handled by signal handlers


DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
CONV_FILE = os.path.join(DATA_DIR, 'conversations.json')
STATE_FILE = os.path.join(DATA_DIR, 'healing_state.json')
os.makedirs(DATA_DIR, exist_ok=True)

def save_conversations():
    try:
        # Snapshot under the healing lock FIRST, then write under _SAVE_LOCK.
        # Never nest one inside the other: save_state() uses this same
        # sequential order, so a fixed global order makes deadlock impossible.
        with healing_system.lock:
            data = [c.to_dict() for c in healing_system.conversation_history if isinstance(c, Conversation)]
        with _SAVE_LOCK:
            tmp = CONV_FILE + '.tmp'
            with open(tmp, 'w') as f:
                json.dump(data, f, default=str)
            os.replace(tmp, CONV_FILE)
    except Exception as e:
        logger.debug(f"Save conversations error: {e}")

def load_conversations():
    try:
        if os.path.exists(CONV_FILE):
            with open(CONV_FILE, 'r') as f:
                data = json.load(f)
            with healing_system.lock:
                for d in data:
                    try:
                        conv = Conversation(
                            id=d.get('id',''), topic=d.get('topic',''),
                            model1=d.get('model1',''), model2=d.get('model2',''),
                            messages=d.get('messages',[]), timestamp=d.get('timestamp',''),
                            user_feedback=d.get('user_feedback'), quality_score=d.get('quality_score',0.0)
                        )
                        healing_system.conversation_history.append(conv)
                    except Exception:
                        continue
            logger.info(f"Loaded {len(data)} conversations from disk")
    except Exception as e:
        logger.error(f"Load conversations error: {e}")

def save_state():
    try:
        with healing_system.lock:
            state = {
                "model_metrics": {name: asdict(m) for name, m in healing_system.model_metrics.items()},
                "circuit_breakers": dict(healing_system.circuit_breakers),
                "failure_counts": dict(healing_system.failure_counts),
                "system_health": healing_system.system_health,
                "learning_data": healing_system.learning_data[-100:]
            }
        with _SAVE_LOCK:
            tmp = STATE_FILE + '.tmp'
            with open(tmp, 'w') as f:
                json.dump(state, f, default=str)
            os.replace(tmp, STATE_FILE)
    except Exception as e:
        logger.debug(f"Save state error: {e}")

def load_state():
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, 'r') as f:
                state = json.load(f)
            with healing_system.lock:
                for name, m in state.get('model_metrics', {}).items():
                    try:
                        # Handle extra/missing fields gracefully
                        valid_fields = {f.name for f in ModelMetrics.__dataclass_fields__.values()}
                        filtered = {k: v for k, v in m.items() if k in valid_fields}
                        healing_system.model_metrics[name] = ModelMetrics(**filtered)
                    except Exception:
                        healing_system.model_metrics[name] = ModelMetrics(name=name)
                healing_system.circuit_breakers = state.get('circuit_breakers', {})
                healing_system.failure_counts = state.get('failure_counts', {})
                healing_system.system_health = state.get('system_health', 1.0)
                healing_system.learning_data = state.get('learning_data', [])
                # Cap learning data on load
                if len(healing_system.learning_data) > healing_system._learning_data_max:
                    healing_system.learning_data = healing_system.learning_data[-healing_system._learning_data_max:]
            logger.info("Loaded healing system state from disk")
    except Exception as e:
        logger.error(f"Load state error: {e}")

@app.route('/api/ollama/models')
def api_ollama_models():
    try:
        models = ollama.get_models()
        return jsonify(models)
    except Exception as e:
        logger.error(f"Ollama models error: {e}")
        return jsonify([])

@app.route('/api/ollama/health')
def api_ollama_health():
    try:
        start = time.time()
        connected = ollama.is_connected()
        latency_ms = int((time.time() - start) * 1000)
        if connected:
            models = ollama.get_models()
            return jsonify({"status": "healthy", "latency_ms": latency_ms, "models": len(models), "model_names": [m.get("name","") for m in models]})
        return jsonify({"status": "unreachable", "latency_ms": latency_ms, "error": "Ollama not responding"})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)})

@app.route('/api/ollama/restart', methods=['POST'])
def api_ollama_restart():
    try:
        def _do_restart():
            try:
                kill_pid(OLLAMA_PID_FILE, signal.SIGTERM)
                time.sleep(2)
                import subprocess
                subprocess.Popen(['ollama', 'serve'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
                for i in range(15):
                    if ollama.is_connected():
                        return
                    time.sleep(1)
            except Exception as e:
                logger.error(f"Ollama restart error: {e}")
        threading.Thread(target=_do_restart, daemon=True, name="ollama-restart").start()
        return jsonify({"status": "restarting"})
    except Exception as e:
        return jsonify({"status": "failed", "error": str(e)})

@app.route('/api/rss')
def api_rss():
    try:
        articles, errors = rss_manager.fetch_all()
        return jsonify({"articles": [dict(a) for a in articles], "errors": errors, "count": len(articles)})
    except Exception as e:
        return jsonify({"articles": [], "errors": [str(e)], "count": 0})

@app.route('/api/threats/live')
def api_threats_live():
    try:
        data = real_threat_feed.update()
        return jsonify(data)
    except Exception as e:
        return jsonify({"threats": [], "stats": {}, "sources": {}, "error": str(e)})

@app.route('/api/threats/top-attacks')
def api_threats_top_attacks():
    try:
        data = real_threat_feed.update()
        top = data.get("top_attacks", [])
        if top:
            return jsonify({"topic": top[0].get("type", "AI Intelligence"), "count": top[0].get("count", 0)})
        return jsonify({"topic": "AI Intelligence", "count": 0})
    except Exception:
        return jsonify({"topic": "AI Intelligence", "count": 0})

@app.route('/api/wiki-comms/live')
def api_wiki_comms_live():
    try:
        force = request.args.get('force', '').lower() in ('1', 'true', 'yes')
        data = wiki_comms.snapshot()
        if force:
            threading.Thread(target=wiki_comms._sweep, daemon=True, name="wiki-force-sweep").start()
        return jsonify(data)
    except Exception:
        return jsonify({"feed": [], "boards": [], "flagged_count": 0, "window_size": 0, "decoded_pages": 0, "last_update": 0})

@app.route('/api/wiki-comms/enrich', methods=['POST'])
def api_wiki_comms_enrich():
    try:
        data = request.get_json(silent=True) or {}
        count = min(int(data.get('count', 20)), 50)
        enriched = wiki_comms.enrich_feed_pages(count)
        return jsonify({"enriched": enriched})
    except Exception as e:
        return jsonify({"enriched": 0, "error": str(e)})

@app.route('/api/wiki-comms/page')
def api_wiki_comms_page():
    try:
        board = request.args.get('board', '')
        page = request.args.get('page', '')
        if not board or not page:
            return jsonify({"error": "board and page required"}), 400
        data = wiki_comms.get_page(board, page, translate=True)
        return jsonify({"text": data.get("text", ""), "english": data.get("english", ""), "board": data.get("board", ""), "page": data.get("page", ""), "ratelimited": data.get("ratelimited", False), "uri": data.get("uri", ""), "probe": data.get("probe", False), "decode_failed": data.get("decode_failed", False)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/wiki-comms/history')
def api_wiki_comms_history():
    try:
        snapshot = wiki_comms.snapshot()
        return jsonify({"agents": {"identity_count": WIKI_INCIDENT_HISTORY.get("agents", {}).get("identity_count", ""), "examples": WIKI_INCIDENT_HISTORY.get("agents", {}).get("examples", []), "signals": WIKI_INCIDENT_HISTORY.get("agents", {}).get("signals", [])}, "timeline": WIKI_INCIDENT_HISTORY.get("timeline", []), "sources": WIKI_INCIDENT_HISTORY.get("sources", []), "feed": snapshot.get("feed", [])[:50]})
    except Exception:
        return jsonify({"agents": {}, "timeline": [], "sources": [], "feed": []})

@app.route('/api/wiki-comms/demo', methods=['POST'])
def api_wiki_comms_demo():
    if not _check_rate_limit("wiki_demo"):
        return jsonify({"error": "Rate limit exceeded. Please wait."}), 429
    try:
        data = request.get_json(silent=True) or {}
        raw1 = data.get('model1', 'qwen2.5:3b')
        raw2 = data.get('model2', 'IHA089/drana-infinity-1.5b:1.5b')
        model1 = _resolve_chat_model(raw1) or 'qwen2.5:3b'
        model2 = _resolve_chat_model(raw2, exclude=[model1]) or model1
        try:
            messages = min(max(1, int(data.get('messages', 3))), 5)
        except (TypeError, ValueError):
            messages = 3
        results = []
        for i in range(messages):
            try:
                res1 = ollama.chat_limited(model1, [{"role": "user", "content": f"Write a short wiki-style message about AI research progress update #{i+1}"}], 60, num_predict=100)
                content1 = res1.get("message", {}).get("content", "[No response]") if "error" not in res1 else "[Error]"
                results.append({"model": model1, "message": content1})
                res2 = ollama.chat_limited(model2, [{"role": "user", "content": f"Respond to: {content1[:200]}"}], 60, num_predict=100)
                content2 = res2.get("message", {}).get("content", "[No response]") if "error" not in res2 else "[Error]"
                results.append({"model": model2, "message": content2})
            except Exception as e:
                results.append({"model": model1, "message": f"[Demo error: {str(e)[:100]}]"})
                break
        return jsonify({"messages": results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500



def _warm_default_models():
    try:
        default_model = 'qwen2.5:3b'
        logger.info(f"Warming model {default_model}...")
        res = ollama.chat_limited(default_model, [{"role": "user", "content": "OK"}], 30, num_predict=5)
        if "error" not in res:
            logger.info(f"Model {default_model} warmed successfully")
            healing_system.register_model(default_model)
            healing_system.mark_qualified(default_model)
        else:
            logger.warning(f"Model {default_model} warmup: {res.get('error')}")
    except Exception as e:
        logger.debug(f"Model warmup error: {e}")


def _keep_models_warm():
    while True:
        try:
            time.sleep(120)
            if not healing_system.running:
                break
            if _RESIDENT_MODEL:
                res = ollama.chat_limited(_RESIDENT_MODEL, [{"role": "user", "content": "Status check"}], 15, num_predict=3)
                if "error" not in res:
                    logger.debug(f"Keepalive ping OK for {_RESIDENT_MODEL}")
        except Exception as e:
            logger.debug(f"Keepalive error: {e}")


# ============================================================
# AUTONOMOUS THREAT BRIEFING LOOP
# The agents ALWAYS auto-start an AI-to-AI debate on breaking threats:
# a background daemon watches the live threat feed, and whenever NEW
# threat intel arrives (new C2s, CVEs, KEVs, blocklist IPs) it launches a
# 1-turn briefing debate between the two lead agents and stores it in the
# conversation history - no clicks required. Polite by design: it never
# runs while the buyer is chatting, while Ollama is busy, or more often
# than AUTO_DEBATE_INTERVAL. Disable with AUTO_DEBATE=0.
# ============================================================
AUTO_DEBATE = os.environ.get('AUTO_DEBATE', '1').strip().lower() not in ('0', 'false', 'no', 'off')
try:
    AUTO_DEBATE_INTERVAL = int(os.environ.get('AUTO_DEBATE_INTERVAL', '300'))
except ValueError:
    AUTO_DEBATE_INTERVAL = 300
AUTO_DEBATE_INTERVAL = max(120, min(AUTO_DEBATE_INTERVAL, 3600))
AUTO_DEBATE_STARTUP_DELAY = 90  # seconds after boot before the first briefing

_AUTO_DEBATE = {
    "seen_ids": set(),
    "last_run": 0.0,
    "last_topic": "",
    "runs": 0,
    "last_status": "booting",
}
_AUTO_DEBATE_LOCK = threading.Lock()
_AUTO_DEBATE_ACTIVE = {"busy": False}

_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _auto_debate_pick_topic():
    """Return (pick, err). pick = {topic, detail, is_new} or None."""
    try:
        data = real_threat_feed.update()
    except Exception as e:
        return None, f"feed error: {e}"
    threats = [t for t in (data.get('threats') or []) if t.get('id')]
    if not threats:
        return None, "no threats yet"
    ids = {t['id'] for t in threats}
    with _AUTO_DEBATE_LOCK:
        seen = _AUTO_DEBATE['seen_ids']
        fresh = [t for t in threats if t['id'] not in seen]
        _AUTO_DEBATE['seen_ids'] = ids
    pool = fresh or list(threats)
    pool = sorted(pool, key=lambda t: (_SEV_RANK.get(str(t.get('severity', '')).upper(), 4),
                                       str(t.get('timestamp', ''))))
    top = pool[0]
    title = top.get('title') or top.get('cve_id') or top.get('ip') or 'Breaking threat'
    topic = f"{title} [{top.get('severity', 'INFO')}]".strip()
    detail = (top.get('description') or '')[:250]
    return {"topic": topic[:200], "detail": detail, "is_new": bool(fresh)}, ""


def _run_auto_debate(force=False):
    """Run one autonomous 1-turn briefing debate. Returns a status dict."""
    if _AUTO_DEBATE_ACTIVE["busy"]:
        return {"status": "already-running"}
    if not AUTO_DEBATE and not force:
        with _AUTO_DEBATE_LOCK:
            _AUTO_DEBATE["last_status"] = "disabled"
        return {"status": "disabled"}
    now = time.time()
    with _AUTO_DEBATE_LOCK:
        if not force and now - _AUTO_DEBATE["last_run"] < AUTO_DEBATE_INTERVAL:
            _AUTO_DEBATE["last_status"] = "cooldown"
            return {"status": "cooldown"}
    if _chat_runs_active() > 0:
        with _AUTO_DEBATE_LOCK:
            _AUTO_DEBATE["last_status"] = "skipped-chat-active"
        return {"status": "skipped-chat-active"}
    if _secs_since_chat() < 120 and not force:
        with _AUTO_DEBATE_LOCK:
            _AUTO_DEBATE["last_status"] = "skipped-user-active"
        return {"status": "skipped-user-active"}
    try:
        if ollama.is_busy():
            with _AUTO_DEBATE_LOCK:
                _AUTO_DEBATE["last_status"] = "skipped-ollama-busy"
            return {"status": "skipped-ollama-busy"}
    except Exception as e:
        logger.debug("Auto-debate skipped; Ollama busy: %s", e)

    pick, err = _auto_debate_pick_topic()
    if not pick:
        with _AUTO_DEBATE_LOCK:
            _AUTO_DEBATE["last_status"] = f"skipped-{err}"
        return {"status": "skipped", "reason": err}
    if not pick["is_new"] and not force:
        with _AUTO_DEBATE_LOCK:
            _AUTO_DEBATE["last_status"] = "skipped-no-new-threats"
        return {"status": "skipped-no-new-threats"}

    topic, detail = pick["topic"], pick["detail"]
    _AUTO_DEBATE_ACTIVE["busy"] = True
    try:
        m1 = _resolve_chat_model('qwen2.5:3b')
        m2 = _resolve_chat_model('llama3.2:3b', exclude=[m1]) if m1 else None
        if m1 and not m2:
            m2 = healing_system.trusted_chat_model(exclude=[m1])
        if not m1 or not m2:
            with _AUTO_DEBATE_LOCK:
                _AUTO_DEBATE["last_status"] = "skipped-no-models"
            return {"status": "skipped-no-models"}
        if m1 == m2:
            alt = healing_system.trusted_chat_model(exclude=[m1])
            if alt:
                m2 = alt

        prof1, prof2 = agent_profile(m1), agent_profile(m2)
        brief = (f"{DOMAIN_SYSTEM_PROMPT}\n\nAUTONOMOUS BREAKING-THREAT BRIEFING:\n"
                 f"{topic}\n{detail}\n\nKeep the briefing CONCISE (under 120 words).")
        results, history = [], []

        def _brief_reply(model, name, other, prior):
            msgs = [{"role": "system",
                     "content": (f"You are {name}. Give your intelligence assessment of this breaking threat. "
                                 f"Then CRITICALLY review {other}'s assessment if present. {brief}")}]
            msgs.extend(prior)
            try:
                with _RESIDENT_LOCK:
                    _ensure_resident_locked(model)
            except Exception as e:
                logger.debug("Resident model lock failed; retried on next request: %s", e)
            res = ollama.chat_limited(model, msgs, 90, num_predict=200, num_ctx=RESIDENT_CTX)
            if "error" in res:
                healing_system.record_failure(model, res["error"])
                return None
            content = (res.get("message") or {}).get("content", "") or ""
            if not content.strip():
                healing_system.record_failure(model, "Empty auto-brief response")
                return None
            healing_system.record_success(model, 0)
            return content

        c1 = _brief_reply(m1, prof1["name"], prof2["name"],
                          [{"role": "user", "content": f"BRIEFING TOPIC: {topic}\n{detail}\n\nGive your intelligence assessment."}])
        if c1:
            results.append({"role": m1, "content": c1, "turn": 1})
            history.append({"role": "user", "content": f"[{prof1['name']}]: {c1}"})
            c2 = _brief_reply(m2, prof2["name"], prof1["name"], history)
            if c2:
                results.append({"role": m2, "content": c2, "turn": 1})

        if not results:
            with _AUTO_DEBATE_LOCK:
                _AUTO_DEBATE["last_status"] = "skipped-models-failed"
            return {"status": "skipped-models-failed"}

        conv_id = hashlib.md5(f"AUTO{topic}{m1}{m2}{datetime.datetime.now().isoformat()}".encode()).hexdigest()[:12]
        healing_system.record_conversation(Conversation(
            id=conv_id, topic=f"AUTO-BRIEF: {topic}", model1=m1, model2=m2,
            messages=results, timestamp=datetime.datetime.now().isoformat(),
            user_feedback=None, quality_score=0.0))
        try:
            save_conversations()
        except Exception as e:
            logger.debug("Conversation save failed: %s", e)
        with _AUTO_DEBATE_LOCK:
            _AUTO_DEBATE["last_run"] = time.time()
            _AUTO_DEBATE["last_topic"] = topic
            _AUTO_DEBATE["runs"] += 1
            _AUTO_DEBATE["last_status"] = "completed"
        logger.info(f"Auto-brief completed: {topic} ({m1} vs {m2})")
        return {"status": "completed", "topic": topic, "conv_id": conv_id}
    finally:
        _AUTO_DEBATE_ACTIVE["busy"] = False


def _auto_debate_loop():
    """Daemon: check for new threats every 60s, brief when they arrive."""
    time.sleep(AUTO_DEBATE_STARTUP_DELAY)
    while healing_system.running:
        try:
            res = _run_auto_debate()
            if res.get("status") not in ("skipped-no-new-threats", "cooldown",
                                         "skipped-user-active", "skipped-chat-active"):
                logger.info(f"Auto-debate check: {res.get('status')}")
        except Exception as e:
            logger.debug(f"Auto-debate loop error: {e}")
        time.sleep(60)


@app.route('/api/chat/auto-run', methods=['POST'])
def api_chat_auto_run():
    """Manually trigger one autonomous threat briefing (demo button)."""
    if not _check_rate_limit("auto_run"):
        return jsonify({"error": "Rate limit exceeded. Please wait."}), 429
    def _bg():
        try:
            _run_auto_debate(force=True)
        except Exception as e:
            logger.debug(f"Manual auto-brief error: {e}")
    threading.Thread(target=_bg, daemon=True, name="auto-brief-manual").start()
    return jsonify({"status": "started"})


@app.route('/api/chat/auto-status')
def api_chat_auto_status():
    try:
        with _AUTO_DEBATE_LOCK:
            snap = {k: (sorted(v) if isinstance(v, set) else v) for k, v in _AUTO_DEBATE.items() if k != "seen_ids"}
            snap["seen_count"] = len(_AUTO_DEBATE["seen_ids"])
        snap["enabled"] = AUTO_DEBATE
        snap["interval_s"] = AUTO_DEBATE_INTERVAL
        snap["busy"] = _AUTO_DEBATE_ACTIVE["busy"]
        return jsonify(snap)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    write_pid(PID_FILE, os.getpid())
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'app.port'), 'w') as pf:
            pf.write(str(FLASK_PORT))
    except Exception as e:
        logger.debug("Port file write skipped: %s", e)
    logger.info(f"Starting GBLOXKOS MORPHEUS V.1 on port {FLASK_PORT}")
    logger.info(f"Ollama endpoint: http://{OLLAMA_HOST}:{OLLAMA_PORT}")

    # Load persisted state
    load_state()
    load_conversations()

    # Pre-fetch RSS in the background so the server is reachable immediately.
    logger.info("Fetching initial RSS feeds in background...")
    threading.Thread(target=lambda: rss_manager.fetch_all(force=True), daemon=True, name="rss-prefetch").start()

    # Pre-fetch REAL live threat intelligence in the background so the threat
    # map has verified data ready the moment the dashboard loads.
    logger.info("Fetching initial live threat intelligence in background...")
    threading.Thread(target=lambda: real_threat_feed.update(), daemon=True, name="threat-prefetch").start()

    # Start the wiki-comms monitor and run one sweep so the Rogue Comms tab is
    # populated immediately. Polls the documented wiki boards in near-real-time.
    logger.info("Starting wiki comms board monitor...")
    threading.Thread(target=wiki_comms.poll_once, daemon=True, name="wiki-comms-prefetch").start()
    wiki_comms.start()

    # Pre-load ONE default AI model (the lead of the default chat pair) so the
    # first demo conversation is responsive. The app permanently keeps a single
    # model resident and swaps on demand (ensure_resident) to save CPU/memory.
    logger.info("Warming default AI model in background (single-resident policy)...")
    threading.Thread(target=_warm_default_models, daemon=True, name="model-warmup").start()

    # Keep the single resident model pinned for the entire session.
    threading.Thread(target=_keep_models_warm, daemon=True, name="model-keepalive").start()

    # Autonomous threat briefings: agents auto-debate breaking threats forever.
    logger.info(f"Starting autonomous threat-briefing loop (enabled={AUTO_DEBATE})...")
    threading.Thread(target=_auto_debate_loop, daemon=True, name="auto-brief").start()

    atexit.register(save_conversations)
    atexit.register(save_state)

    try:
        app.run(
            host=HOST,
            port=FLASK_PORT,
            debug=False,
            use_reloader=False,
            threaded=True,
            passthrough_errors=False
        )
    except OSError as e:
        logger.error(f"Failed to start server on port {FLASK_PORT}: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
        healing_system.stop()
        sys.exit(0)