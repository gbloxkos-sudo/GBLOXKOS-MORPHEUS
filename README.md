# GBLOXKOS MORPHEUS V.1

**Developer: GBLOXKOS LLC**
**License: MIT** — see [LICENSE](LICENSE)

A self-hosted Flask intelligence dashboard for AI-agent chatroom research, live
threat aggregation, and self-hosted LLM (Ollama) experimentation. Everything runs
locally; no third-party API keys are required for the core dashboard.

---

## Features

- **Multi-model chat room** — query a local Ollama model with domain-scoped system
  prompts, auto-debate between two models, and persisted conversation history.
- **Research dashboard** — curated AI-threat findings, documented agent-chat
  incidents, and open-source project tracking.
- **Live threat intelligence** — aggregated live attack telemetry with attack-type,
  tactic, sector, malware, and geography breakdowns.
- **RSS intelligence** — multi-feed aggregation parsed through `feedparser`,
  de-duplicated, summarised, and injected as prompt context.
- **WikiComms monitor** — background polling of wiki boards, agent-edit detection,
  page decoding, and on-demand English translation.
- **Self-healing system** — persisted model/health state, automatic recovery, and
  resident-model locking.
- **Hardened surface** — CORS, security headers (CSP, X-Frame-Options,
  X-Content-Type-Options, XSS-Protection), optional API-token auth, per-endpoint
  rate limiting, and input validation.

---

## Requirements

| Component | Version |
| --- | --- |
| Python | 3.8+ (tested on 3.13) |
| Flask | >= 2.3.0 |
| Flask-CORS | >= 4.0.0 |
| feedparser | >= 6.0.0 |
| Ollama *(optional)* | any recent build |

Ollama is optional. Without it the dashboard, research, threat, and RSS features
still work; only live chat is unavailable.

---

## Installation

```bash
git clone https://github.com/GBLOXKOS-LLC/gbloxkos-morpheus.git
cd gbloxkos-morpheus

python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Optionally install Ollama for local model inference:

```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull qwen2.5:3b
```

---

## Running

**Quick start (handles Ollama, ports, and logging for you):**

```bash
./start.sh          # defaults to port 5000
./start.sh 8080     # or pick your own port
./stop.sh           # shut down cleanly
```

**Manual:**

```bash
python3 app.py
```

Then open <http://localhost:5000>.

Configuration is driven by environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `FLASK_PORT` | `5000` | HTTP port |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama endpoint |
| `API_TOKEN` | *(unset)* | When set, required as `X-API-Token` on API routes |
| `ALLOW_CORS_ORIGINS` | *(all)* | Restrict CORS origins |

---

## Project layout

```
gbloxkos-morpheus/
├── app.py              # Flask app: routes, managers, background workers
├── threat_feed.py      # Live threat-intelligence aggregation
├── audit.py            # Self-audit harness (syntax, threads, leaks, security)
├── start.sh            # Boot script (Ollama + app lifecycle)
├── stop.sh             # Clean shutdown
├── templates/
│   └── index.html      # Single-page dashboard
├── static/
│   ├── bg.jpg
│   ├── leaflet.css
│   └── leaflet.js      # Vendored Leaflet (map for threat geolocation)
├── pics/
├── data/               # Runtime state, auto-created (git-ignored)
├── requirements.txt
└── LICENSE
```

---

## API reference

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | `/api/status` | Application status snapshot |
| GET | `/api/health/system` | Host system health |
| GET | `/api/health/models` | Per-model health/latency |
| GET | `/api/ollama/models` | Locally installed Ollama models |
| GET | `/api/ollama/health` | Ollama reachability |
| POST | `/api/ollama/chat` | Raw passthrough to Ollama |
| POST | `/api/ollama/restart` | Restart the Ollama client |
| POST | `/api/chat/run` | Run a domain-scoped chat turn |
| GET | `/api/chat/auto-status` | Auto-debate status |
| POST | `/api/chat/auto-run` | Trigger an auto-debate |
| GET | `/api/conversations/history` | Persisted conversation history |
| POST | `/api/learning/feedback` | Submit a learning rating |
| GET | `/api/rss` | Aggregated RSS articles |
| GET | `/api/rss/context` | RSS content as prompt context |
| GET | `/api/research/threats` | Curated AI-threat research |
| GET | `/api/research/agent-chats` | Documented agent-chat incidents |
| GET | `/api/research/oss-projects` | Tracked open-source projects |
| GET | `/api/threats/live` | Live threat telemetry |
| GET | `/api/threats/top-attacks` | Top attack aggregates |
| GET | `/api/wiki-comms/live` | Live WikiComms snapshot |
| GET | `/api/wiki-comms/history` | WikiComms incident history |
| GET | `/api/wiki-comms/page` | Decode a single wiki page |
| POST | `/api/wiki-comms/enrich` | Force a background enrichment sweep |
| POST | `/api/wiki-comms/demo` | Run a two-model wiki demo |
| GET | `/api/self-awareness` | Self-healing system introspection |
| GET | `/api/restart` | Restart the application process |

---

## Quality checks

Run the bundled self-audit before shipping or deploying:

```bash
python3 audit.py
```

It verifies syntax, imports, routes, thread safety, error handling, memory-leak
patterns, AI integration, and security headers, and reports a pass/fail summary.

Static analysis:

```bash
pip install pyflakes
pyflakes app.py threat_feed.py audit.py
```

Both are clean on the current release: **0 errors, 0 warnings**.

---

## Security notes

- This project is a **research and defensive-security dashboard**. It renders
  third-party RSS and wiki content; all fetched content is sanitised before being
  served or injected into prompts.
- Client-supplied system messages are deliberately **rejected** — the server-side
  domain prompt is authoritative and cannot be overridden by untrusted input.
- Do not expose the service directly to the internet without a reverse proxy
  (TLS) and `API_TOKEN` enabled.
- Python's development server is used for convenience. For production, deploy
  behind a WSGI server such as Gunicorn.

---

## Contributing

Issues and pull requests are welcome. Please run `python3 audit.py` and
`pyflakes` before submitting, and keep changes focused and documented.

---

## License

 Copyright (c) 2026 **GBLOXKOS LLC**. See [LICENSE](LICENSE).
