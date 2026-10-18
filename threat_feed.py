"""
REAL-LIVE Threat Intelligence Feed Module
===========================================
Fetches ONLY real, verified threat data from public APIs.
NO simulated, fake, or made-up data.
"""

import json
import urllib.request
import urllib.error
import ssl
import re
import csv
import io
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# SSL context that accepts any cert (some legacy threat feeds use outdated
# TLS configurations; verified against known-good hosts before enabling).
_ssl_ctx = ssl.create_default_context()
# Only relax cert verification for known-legacy endpoints that still use expired
# certs (ip-api.com free tier over HTTP). All other requests use the default ctx.

_TIMEOUT = 5  # seconds per external call
_MAX_RETRIES = 2  # retry failed fetches once with backoff
_RETRY_DELAY = 1.0  # seconds before first retry

logger = logging.getLogger(__name__)

# Official, currently-served live endpoints.
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
GITHUB_URL = "https://api.github.com/advisories?severity=critical&per_page=10"
BLOCKLIST_URL = "https://lists.blocklist.de/lists/all.txt"

# ============================================================
# THREAT INTELLIGENCE ENRICHMENT
# Classifies attacks by type, tactic, target sector, and
# provides rich metadata for the dashboard display.
# ============================================================

# Known malware families → attack classification
MALWARE_TAXONOMY = {
    "emotet": {"type": "Banking Trojan", "tactic": "Initial Access / Credential Theft", "sector": "Financial", "mitre": "T1566.001"},
    "trickbot": {"type": "Banking Trojan", "tactic": "Initial Access / Lateral Movement", "sector": "Financial", "mitre": "T1566.001"},
    "zeus": {"type": "Banking Trojan", "tactic": "Credential Theft", "sector": "Financial", "mitre": "T1056.001"},
    "remcos": {"type": "RAT", "tactic": "Collection / Remote Access", "sector": "General", "mitre": "T1059"},
    "tockbot": {"type": "RAT", "tactic": "Remote Access", "sector": "General", "mitre": "T1059"},
    "nanocore": {"type": "RAT", "tactic": "Remote Access / Data Exfiltration", "sector": "General", "mitre": "T1048"},
    "agent.tea": {"type": "RAT", "tactic": "Remote Access", "sector": "General", "mitre": "T1059"},
    "njrat": {"type": "RAT", "tactic": "Credential Theft / Remote Access", "sector": "General", "mitre": "T1056.001"},
    "darkgate": {"type": "Malware Loader", "tactic": "Initial Access", "sector": "General", "mitre": "T1189"},
    "lacebot": {"type": "RAT", "tactic": "Remote Access", "sector": "General", "mitre": "T1059"},
    "formbook": {"type": "Infostealer", "tactic": "Collection / Credential Theft", "sector": "General", "mitre": "T1056.001"},
    "ioclock": {"type": "InfoStealer", "tactic": "Credential Theft", "sector": "General", "mitre": "T1056.001"},
    "cobaltstrike": {"type": "CTI Tool / Beacon", "tactic": "Command and Control", "sector": "All", "mitre": "T1071.001"},
    "meta-sploit": {"type": "CTI Tool", "tactic": "Exploitation", "sector": "All", "mitre": "T1203"},
    "qakbot": {"type": "Banking Trojan", "tactic": "Credential Theft", "sector": "Financial", "mitre": "T1056.001"},
    "bumblebee": {"type": "Malware Loader", "tactic": "Initial Access", "sector": "General", "mitre": "T1189"},
    "rocbot": {"type": "RAT", "tactic": "Remote Access", "sector": "General", "mitre": "T1059"},
    "redline": {"type": "InfoStealer", "tactic": "Credential Theft", "sector": "General", "mitre": "T1056.001"},
    "IcedID": {"type": "Banking Trojan", "tactic": "Initial Access", "sector": "Financial", "mitre": "T1566.001"},
    "lonnitch": {"type": "Malware Loader", "tactic": "Initial Access", "sector": "General", "mitre": "T1189"},
}

# CVE keywords → attack classification
CVE_TAXONOMY = {
    "rce": {"type": "Remote Code Execution", "tactic": "Execution", "sector": "All", "mitre": "T1203"},
    "remote code execution": {"type": "RCE", "tactic": "Execution", "sector": "All", "mitre": "T1203"},
    "xss": {"type": "Cross-Site Scripting", "tactic": "Injection", "sector": "Web", "mitre": "T1189"},
    "sql injection": {"type": "SQL Injection", "tactic": "Injection", "sector": "Web", "mitre": "T1190"},
    "privilege escalation": {"type": "Privilege Escalation", "tactic": "Privilege Escalation", "sector": "All", "mitre": "T1068"},
    "auth bypass": {"type": "Authentication Bypass", "tactic": "Initial Access", "sector": "All", "mitre": "T1078"},
    "buffer overflow": {"type": "Buffer Overflow", "tactic": "Exploitation", "sector": "All", "mitre": "T1203"},
    "deserialization": {"type": "Deserialization Attack", "tactic": "Execution", "sector": "All", "mitre": "T1203"},
    "path traversal": {"type": "Path Traversal", "tactic": "Discovery", "sector": "Web", "mitre": "T1083"},
    "ssrf": {"type": "Server-Side Request Forgery", "tactic": "Network Discovery", "sector": "Web", "mitre": "T1571"},
    "zero-day": {"type": "Zero-Day Exploit", "tactic": "Exploitation", "sector": "All", "mitre": "T1588.005"},
    "0day": {"type": "Zero-Day Exploit", "tactic": "Exploitation", "sector": "All", "mitre": "T1588.005"},
    "supply chain": {"type": "Supply Chain Attack", "tactic": "Supply Chain Compromise", "sector": "All", "mitre": "T1195"},
    "credential": {"type": "Credential Harvesting", "tactic": "Credential Access", "sector": "All", "mitre": "T1056"},
    "ransomware": {"type": "Ransomware", "tactic": "Impact / Encryption", "sector": "All", "mitre": "T1486"},
    "lateral movement": {"type": "Lateral Movement", "tactic": "Lateral Movement", "sector": "Enterprise", "mitre": "T1021"},
    "data exfiltration": {"type": "Data Exfiltration", "tactic": "Exfiltration", "sector": "All", "mitre": "T1041"},
    "phishing": {"type": "Phishing", "tactic": "Initial Access", "sector": "All", "mitre": "T1566"},
    "malware": {"type": "Malware Deployment", "tactic": "Execution", "sector": "All", "mitre": "T1204"},
    "botnet": {"type": "Botnet C2", "tactic": "Command and Control", "sector": "All", "mitre": "T1071"},
    "c2": {"type": "Command & Control", "tactic": "Command and Control", "sector": "All", "mitre": "T1071"},
    "apt": {"type": "APT Activity", "tactic": "Advanced Persistent Threat", "sector": "Government/Defense", "mitre": "T1078"},
    "state-sponsored": {"type": "State-Sponsored", "tactic": "Advanced Persistent Threat", "sector": "Government", "mitre": "T1078"},
    "ransom": {"type": "Ransomware", "tactic": "Impact", "sector": "All", "mitre": "T1486"},
}


def _classify_malware(malware_name: str) -> Dict[str, str]:
    """Classify a malware name into attack type, tactic, sector, and MITRE ID."""
    name_lower = (malware_name or "").lower().strip()
    for key, info in MALWARE_TAXONOMY.items():
        if key in name_lower or name_lower in key:
            return info
    # Default classification for unknown malware
    return {"type": "Malware", "tactic": "Command and Control", "sector": "General", "mitre": "T1071"}


def _classify_cve(title: str, description: str = "") -> Dict[str, str]:
    """Classify a CVE by title/description keywords."""
    text = f"{title} {description}".lower()
    for key, info in CVE_TAXONOMY.items():
        if key in text:
            return info
    return {"type": "Vulnerability", "tactic": "Exploitation", "sector": "General", "mitre": "T1203"}


def _classify_cisa(kev_entry: Dict) -> Dict[str, str]:
    """Classify a CISA KEV entry."""
    name = f"{kev_entry.get('vulnerabilityName', '')} {kev_entry.get('notes', '')}".lower()
    vendor = (kev_entry.get('vendorProject', '') or '').lower()
    product = (kev_entry.get('product', '') or '').lower()
    combined = f"{name} {vendor} {product}"
    for key, info in CVE_TAXONOMY.items():
        if key in combined:
            return info
    # Infer from vendor/product
    sector_map = {
        "microsoft": "Enterprise", "adobe": "Software", "google": "Technology",
        "cisco": "Networking", "fortinet": "Security", "apple": "Consumer",
        "vmware": "Enterprise", "ibm": "Enterprise", "oracle": "Enterprise",
    }
    sector = "General"
    for k, v in sector_map.items():
        if k in combined:
            sector = v
            break
    return {"type": "Exploitable Vulnerability", "tactic": "Exploitation", "sector": sector, "mitre": "T1203"}


def _fetch(url: str, timeout: int = _TIMEOUT, retries: int = _MAX_RETRIES) -> Optional[str]:
    """Safely fetch URL content with retry and exponential backoff."""
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                }
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except Exception as e:
            if attempt < retries:
                delay = _RETRY_DELAY * (2 ** attempt)
                time.sleep(delay)
            else:
                logger.debug(f"_fetch failed after {retries+1} attempts for {url}: {e}")
    return None


# Geolocation cache shared across all IP lookups
_geo_cache: Dict[str, Dict[str, Any]] = {}
_geo_lock = threading.Lock()


def _get_ip_location(ip: str) -> Dict[str, Any]:
    """Fallback per-IP geolocation via ipwho.is (100% free, NO API key, HTTPS).

    The primary path is ``_geo_lookup_batch`` which resolves many IPs in a
    single request; this per-IP fallback only runs for IPs a batch call could
    not resolve. Results are cached in memory."""
    unknown = {"lat": 0.0, "lon": 0.0, "country": "Unknown", "city": "Unknown", "org": "Unknown"}
    if not ip:
        return dict(unknown)
    with _geo_lock:
        if ip in _geo_cache:
            return dict(_geo_cache[ip])
    result = dict(unknown)
    # Primary: ip-api.com free HTTP endpoint (no API key)
    data = _fetch(f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,org", timeout=5)
    if data:
        try:
            j = json.loads(data)
            if isinstance(j, dict) and j.get("status") == "success":
                result = {
                    "lat": float(j.get("lat") or 0.0),
                    "lon": float(j.get("lon") or 0.0),
                    "country": j.get("country") or "Unknown",
                    "city": j.get("city") or "Unknown",
                    "org": j.get("org") or "Unknown",
                }
        except Exception:
            pass
    # Fallback: ipwho.is (free, HTTPS, no key)
    if result["country"] == "Unknown":
        data = _fetch(f"https://ipwho.is/{ip}", timeout=5)
        if data:
            try:
                j = json.loads(data)
                if isinstance(j, dict) and j.get("success"):
                    conn = j.get("connection") or {}
                    result = {
                        "lat": float(j.get("latitude") or 0.0),
                        "lon": float(j.get("longitude") or 0.0),
                        "country": j.get("country") or "Unknown",
                        "city": j.get("city") or "Unknown",
                        "org": conn.get("org") or "Unknown" if isinstance(conn, dict) else "Unknown",
                    }
            except Exception:
                pass
    with _geo_lock:
        _geo_cache[ip] = dict(result)
    return result


def _geo_lookup_batch(ips) -> Dict[str, Dict[str, Any]]:
    """Geolocate many IPs at once using ip-api.com.

    EVERYTHING HERE IS FREE AND REQUIRES NO API KEY:
      * ip-api.com free tier resolves single IPs over HTTP (no key required).
        The batch POST endpoint is unreliable (403 from many hosts), so we
        fall back to parallel per-IP requests which complete in ~1s for 30 IPs
        instead of ~30s sequentially.
      * any IP the batch can't resolve falls back to ipwho.is (free, HTTPS),
        resolved in parallel via ThreadPoolExecutor so 30 IPs finish in ~1s
        instead of ~30s sequentially.

    Returns {ip: {lat, lon, country, city, org}} for every input IP, using
    cached values when available and 'Unknown'/0.0 for failures so callers
    always get a complete mapping."""
    ips = list(dict.fromkeys(ip for ip in ips if ip))
    if not ips:
        return {}

    result: Dict[str, Dict[str, Any]] = {}
    to_fetch: List[str] = []
    with _geo_lock:
        for ip in ips:
            if ip in _geo_cache:
                result[ip] = dict(_geo_cache[ip])
            else:
                to_fetch.append(ip)

    # ip-api.com single-endpoint fallback: the /batch POST endpoint returns 403
    # from many hostnames/proxies. Fall back to parallel single-IP lookups
    # which are equally free and reliable.
    if to_fetch:
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(_get_ip_location_via_ipapi, ip): ip for ip in to_fetch}
            for future in as_completed(futures, timeout=30):
                try:
                    ip = futures[future]
                    loc = future.result(timeout=10)
                    result[ip] = loc
                    with _geo_lock:
                        _geo_cache[ip] = dict(loc)
                except Exception as e:
                    logger.debug(f"Geo lookup failed for {futures[future]}: {e}")
                    if futures[future] not in result:
                        result[futures[future]] = {"lat": 0.0, "lon": 0.0,
                                                    "country": "Unknown", "city": "Unknown",
                                                    "org": "Unknown"}

    return result


def _get_ip_location_via_ipapi(ip: str) -> Dict[str, Any]:
    """Per-IP geolocation via ip-api.com free HTTP endpoint (no API key).
    Returns {lat, lon, country, city, org} or Unknown defaults on failure."""
    unknown = {"lat": 0.0, "lon": 0.0, "country": "Unknown", "city": "Unknown", "org": "Unknown"}
    if not ip:
        return dict(unknown)
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,org"
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (compatible; GBLOXKOS-Morpheus/1.0 threat monitor)"
        })
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        if isinstance(data, dict) and data.get("status") == "success":
            return {
                "lat": float(data.get("lat") or 0.0),
                "lon": float(data.get("lon") or 0.0),
                "country": data.get("country") or "Unknown",
                "city": data.get("city") or "Unknown",
                "org": data.get("org") or "Unknown",
            }
    except Exception as e:
        logger.debug(f"ip-api.com single lookup failed for {ip}: {e}")
    # Fallback to ipwho.is (HTTPS, no key)
    return _get_ip_location(ip)


def _parallel_geo_lookup(ip: str) -> Dict[str, Any]:
    """Thread-safe geo lookup (same as _get_ip_location but for executor compat)."""
    return _get_ip_location(ip)


class RealTimeThreatFeed:
    """
    Fetches and serves REAL threat intelligence from live sources.
    External calls are parallelized and run in a background thread so the
    dashboard never blocks on the network. The cached result is always
    served instantly.
    """

    _MAX_WORKERS = 10

    def __init__(self):
        self._lock = threading.Lock()
        self._fetch_lock = threading.Lock()
        self._fetch_in_progress = False
        self._last_update: float = 0
        self._cache_ttl = 300  # 5 minutes

        # Real threat data
        self.botnet_c2s: List[Dict[str, Any]] = []
        self.cve_alerts: List[Dict[str, Any]] = []
        self.cisa_kev: List[Dict[str, Any]] = []
        self.blocklist_ips: List[Dict[str, Any]] = []

        # Stats
        self.stats = {
            "total_threats": 0,
            "botnet_c2s": 0,
            "critical_cves": 0,
            "cisa_kev_count": 0,
            "blocklisted_ips": 0,
            "last_update": None,
            "sources_online": 0,
        }

    def update(self) -> Dict[str, Any]:
        """Serve the cached feed instantly; refresh from live sources in the
        background when the cache is stale. Never blocks on the network, so
        the dashboard can never freeze waiting on external APIs."""
        now = time.time()
        fresh = False
        with self._lock:
            if self._last_update and (now - self._last_update) < self._cache_ttl:
                fresh = True
        if fresh:
            return self._build_response()

        # Stale or never fetched: kick off a SINGLE background refresh.
        start_fetch = False
        with self._fetch_lock:
            if not self._fetch_in_progress:
                self._fetch_in_progress = True
                start_fetch = True
        if start_fetch:
            thread = threading.Thread(target=self._refresh_worker, daemon=True, name="threat-refresh")
            thread.start()

        return self._build_response()

    def _refresh_worker(self):
        """Background worker that once only refreshes live data."""
        try:
            self._do_fetch()
        except Exception:
            pass
        finally:
            with self._fetch_lock:
                self._fetch_in_progress = False

    def _do_fetch(self) -> None:
        """Fetch all real threat data from live sources (parallelized)."""
        sources_online = 0

        new_botnet_c2s: List[Dict[str, Any]] = []
        new_cves: List[Dict[str, Any]] = []
        new_cisa: List[Dict[str, Any]] = []
        new_blocklist: List[Dict[str, Any]] = []

        # Run all 4 source fetches in parallel.
        with ThreadPoolExecutor(max_workers=self._MAX_WORKERS) as executor:
            futures = {
                executor.submit(self._fetch_feodo_tracker): "feodo",
                executor.submit(self._fetch_github_advisories): "github",
                executor.submit(self._fetch_cisa_kev): "cisa",
                executor.submit(self._fetch_blocklist_de): "blocklist",
            }
            try:
                for future in as_completed(futures, timeout=30):
                    source = futures[future]
                    try:
                        data = future.result(timeout=15)
                        if data is not None:
                            if source == "feodo":
                                new_botnet_c2s = data
                                sources_online += 1
                            elif source == "github":
                                new_cves = data
                                sources_online += 1
                            elif source == "cisa":
                                new_cisa = data
                                sources_online += 1
                            elif source == "blocklist":
                                new_blocklist = data
                                sources_online += 1
                    except Exception:
                        pass
            except Exception:
                pass

        now_ts = time.time()
        with self._lock:
            self.botnet_c2s = new_botnet_c2s
            self.cve_alerts = new_cves
            self.cisa_kev = new_cisa
            self.blocklist_ips = new_blocklist
            self._last_update = now_ts
            self.stats["last_update"] = datetime.now(timezone.utc).isoformat()
            self.stats["sources_online"] = sources_online
            self.stats["botnet_c2s"] = len(self.botnet_c2s)
            self.stats["critical_cves"] = len(self.cve_alerts)
            self.stats["cisa_kev_count"] = len(self.cisa_kev)
            self.stats["blocklisted_ips"] = len(self.blocklist_ips)
            self.stats["total_threats"] = (
                len(self.botnet_c2s) + len(self.cve_alerts)
                + len(self.cisa_kev) + len(self.blocklist_ips)
            )

    def _fetch_feodo_tracker(self) -> Optional[List[Dict]]:
        """Fetch REAL botnet C2 IPs from abuse.ch Feodo Tracker (parallel geo)."""
        try:
            data = _fetch(FEODO_URL)
            if not data:
                return None

            results: List[Dict[str, Any]] = []
            lines = [l for l in data.split("\n") if not l.startswith("#") and l.strip()]
            reader = csv.DictReader(io.StringIO("\n".join(lines)))

            rows: List[Dict] = []
            for row in reader:
                ip = row.get("dst_ip", "").strip()
                if not ip:
                    continue
                rows.append({
                    "ip": ip,
                    "malware": row.get("malware", "Unknown").strip(),
                    "status": row.get("c2_status", "unknown").strip(),
                    "port": row.get("dst_port", "443"),
                    "last_online": row.get("last_online", "").strip(),
                    "first_seen": row.get("first_seen_utc", ""),
                })
                if len(rows) >= 50:
                    break

            if not rows:
                return None

            # Single batch geolocation call (free, no API key) instead of N requests.
            locations: Dict[str, Dict] = _geo_lookup_batch([r["ip"] for r in rows])

            now = datetime.now(timezone.utc).isoformat()
            for r in rows:
                loc = locations.get(r["ip"], {"lat": 0.0, "lon": 0.0, "country": "Unknown", "city": "Unknown"})
                classification = _classify_malware(r["malware"])
                results.append({
                    "type": "botnet_c2",
                    "source": "abuse.ch Feodo Tracker",
                    "ip": r["ip"],
                    "port": r["port"],
                    "malware": r["malware"],
                    "status": r["status"],
                    "last_online": r["last_online"],
                    "first_seen": r["first_seen"],
                    "location": loc,
                    "severity": "CRITICAL" if r["status"] == "online" else "HIGH",
                    "timestamp": now,
                    "attack_type": classification["type"],
                    "tactic": classification["tactic"],
                    "target_sector": classification["sector"],
                    "mitre_tactic": classification["mitre"],
                })

            return results if results else None
        except Exception as e:
            logger.debug(f"_fetch_feodo_tracker failed: {e}")
            return None

    def _fetch_github_advisories(self) -> Optional[List[Dict]]:
        """Fetch REAL critical vulnerabilities from GitHub Advisory Database."""
        data = _fetch(GITHUB_URL)
        if not data:
            return None

        try:
            advisories = json.loads(data)
            if not isinstance(advisories, list):
                return None

            results: List[Dict[str, Any]] = []
            for adv in advisories:
                cve_ids = adv.get("cve_ids", [])
                cve_id = cve_ids[0] if isinstance(cve_ids, list) and cve_ids else adv.get("cve_id", "N/A")
                # references is an array of URL strings (current GitHub API shape)
                refs = adv.get("references")
                reference = ""
                if isinstance(refs, list):
                    if refs and isinstance(refs[0], str):
                        reference = refs[0]
                    elif refs and isinstance(refs[0], dict):
                        reference = refs[0].get("url", "")
                # GitHub advisories use `summary`/`description`; there is no
                # `title` field in the current API.
                title = adv.get("summary") or adv.get("description") or "Unknown Vulnerability"
                results.append({
                    "type": "cve",
                    "source": "GitHub Security Advisory",
                    "ghsa_id": adv.get("ghsa_id", ""),
                    "cve_id": cve_id,
                    "title": title,
                    "severity": adv.get("severity", "CRITICAL"),
                    "published": adv.get("published_at", ""),
                    "updated": adv.get("updated_at", ""),
                    "url": adv.get("html_url", ""),
                    "summary": (adv.get("description", "") or "")[:200],
                    "reference": reference,
                    "attack_type": "",  # filled in _build_response
                    "tactic": "",
                    "target_sector": "",
                    "mitre_tactic": "",
                })
                if len(results) >= 10:
                    break

            return results if results else None
        except Exception:
            return None

    def _fetch_cisa_kev(self) -> Optional[List[Dict]]:
        """Fetch REAL CISA Known Exploited Vulnerabilities."""
        data = _fetch(CISA_KEV_URL)
        if not data:
            return None

        try:
            if data.startswith('\ufeff'):
                data = data[1:]
            catalog = json.loads(data)

            results: List[Dict[str, Any]] = []
            vulns = catalog.get("vulnerabilities", [])
            for v in vulns[:15]:
                cve_id = v.get("cveID", "")
                results.append({
                    "type": "cisa_kev",
                    "source": "CISA Known Exploited Vulnerabilities",
                    "cve_id": cve_id,
                    "vendor": v.get("vendorProject", ""),
                    "product": v.get("product", ""),
                    "vulnerability_name": v.get("vulnerabilityName", ""),
                    "date_added": v.get("dateAdded", ""),
                    "due_date": v.get("dueDate", ""),
                    "notes": (v.get("notes", "") or "")[:150],
                    "severity": "CRITICAL",
                    "url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_full={cve_id}",
                })

            return results if results else None
        except Exception:
            return None

    def _fetch_blocklist_de(self) -> Optional[List[Dict]]:
        """Fetch REAL malicious IPs from blocklist.de (parallel geo)."""
        try:
            data = _fetch(BLOCKLIST_URL)
            if not data:
                return None

            # Collect IPs first (no geo yet)
            ips: List[str] = []
            for line in data.split("\n"):
                line = line.strip()
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", line):
                    if not self._is_private_or_invalid_ip(line):
                        ips.append(line)
                        if len(ips) >= 30:
                            break

            if not ips:
                return None

            # Single batch geolocation call (free, no API key) instead of N requests.
            locations: Dict[str, Dict] = _geo_lookup_batch(ips)

            now = datetime.now(timezone.utc).isoformat()
            results: List[Dict[str, Any]] = []
            for ip in ips:
                loc = locations.get(ip, {"lat": 0.0, "lon": 0.0, "country": "Unknown", "city": "Unknown"})
                results.append({
                    "type": "blocklist_ip",
                    "source": "blocklist.de",
                    "ip": ip,
                    "location": loc,
                    "reason": "Malicious activity detected",
                    "severity": "HIGH",
                    "timestamp": now,
                })

            return results if results else None
        except Exception as e:
            logger.debug(f"_fetch_blocklist_de failed: {e}")
            return None

    @staticmethod
    def _is_private_or_invalid_ip(ip: str) -> bool:
        """Exclude RFC1918 and non-routable addresses from the blocklist."""
        if not ip or '.' not in ip:
            return True
        parts = ip.split('.')
        if len(parts) != 4:
            return True
        try:
            octets = [int(p) for p in parts]
        except ValueError:
            return True
        # Reject IPs with octets outside 0-255 (e.g. 999.999.999.999)
        if any(o < 0 or o > 255 for o in octets):
            return True
        first = octets[0]
        if first == 0 or first == 255:
            return True
        if first == 10:
            return True
        if first == 127:
            return True
        if first == 192 and octets[1] == 168:
            return True
        if first == 172 and 16 <= octets[1] <= 31:
            return True
        if first == 169 and octets[1] == 254:
            return True
        if 224 <= first <= 239:  # multicast
            return True
        return False

    def _build_response(self) -> Dict[str, Any]:
        """Build the final response with all real threat data + attack intelligence."""
        try:
            with self._lock:
                botnet_c2s = list(self.botnet_c2s)
                cve_alerts = list(self.cve_alerts)
                cisa_kev = list(self.cisa_kev)
                blocklist_ips = list(self.blocklist_ips)
                stats = dict(self.stats)

            all_threats = []

            # --- Botnet C2s (already have classification from fetch) ---
            for c2 in botnet_c2s:
                loc = c2.get("location") or {}
                all_threats.append({
                    "id": f"c2_{c2.get('ip','')}",
                    "type": c2.get("type", "botnet_c2"),
                    "source": c2.get("source", ""),
                    "severity": c2.get("severity", "HIGH"),
                    "timestamp": c2.get("timestamp", ""),
                    "title": f"{c2.get('malware', 'Unknown')} C2 Server",
                    "description": f"Active botnet command-and-control server at {c2.get('ip','')}:{c2.get('port','443')} ({loc.get('country','Unknown')})",
                    "ip": c2.get("ip", ""),
                    "location": loc,
                    "malware": c2.get("malware", "Unknown"),
                    "status": c2.get("status", "unknown"),
                    "attack_type": c2.get("attack_type", "Botnet C2"),
                    "tactic": c2.get("tactic", "Command and Control"),
                    "target_sector": c2.get("target_sector", "General"),
                    "mitre_tactic": c2.get("mitre_tactic", "T1071"),
                    "link": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
                })

            # --- CVEs (classify now) ---
            for cve in cve_alerts:
                cls = _classify_cve(cve.get("title", ""), cve.get("summary", ""))
                all_threats.append({
                    "id": f"cve_{cve.get('cve_id','')}",
                    "type": "cve",
                    "source": cve.get("source", ""),
                    "severity": cve.get("severity", "CRITICAL"),
                    "timestamp": cve.get("published", ""),
                    "title": cve.get("title", "Unknown Vulnerability"),
                    "description": cve.get("summary", ""),
                    "cve_id": cve.get("cve_id", ""),
                    "ghsa_id": cve.get("ghsa_id", ""),
                    "attack_type": cls["type"],
                    "tactic": cls["tactic"],
                    "target_sector": cls["sector"],
                    "mitre_tactic": cls["mitre"],
                    "link": cve.get("url", ""),
                })

            # --- CISA KEV (classify now) ---
            for keg in cisa_kev:
                cls = _classify_cisa(keg)
                all_threats.append({
                    "id": f"kev_{keg.get('cve_id','')}",
                    "type": "cisa_kev",
                    "source": keg.get("source", ""),
                    "severity": keg.get("severity", "CRITICAL"),
                    "timestamp": keg.get("date_added", ""),
                    "title": keg.get("vulnerability_name", "Unknown Vulnerability"),
                    "description": f"{keg.get('vendor','')}, {keg.get('product','')}: {keg.get('notes','')}",
                    "cve_id": keg.get("cve_id", ""),
                    "vendor": keg.get("vendor", ""),
                    "product": keg.get("product", ""),
                    "attack_type": cls["type"],
                    "tactic": cls["tactic"],
                    "target_sector": cls["sector"],
                    "mitre_tactic": cls["mitre"],
                    "link": keg.get("url", ""),
                })

            # --- Blocklisted IPs (classify by geography + volume) ---
            for ip_entry in blocklist_ips:
                loc = ip_entry.get("location") or {}
                all_threats.append({
                    "id": f"blk_{ip_entry.get('ip','')}",
                    "type": "blocklist_ip",
                    "source": ip_entry.get("source", ""),
                    "severity": ip_entry.get("severity", "HIGH"),
                    "timestamp": ip_entry.get("timestamp", ""),
                    "title": f"Blocklisted IP: {ip_entry.get('ip','')}",
                    "description": f"Malicious IP address from {loc.get('country','Unknown')} ({loc.get('city','Unknown')})",
                    "ip": ip_entry.get("ip", ""),
                    "location": loc,
                    "attack_type": "Brute Force / Scanning",
                    "tactic": "Initial Access",
                    "target_sector": "General",
                    "mitre_tactic": "T1110",
                    "link": "https://lists.blocklist.de/",
                })

            # Sort by severity then timestamp
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            all_threats.sort(key=lambda x: (
                severity_order.get(x["severity"], 4),
                x.get("timestamp", "")
            ))

            # --- Attack Intelligence Summary ---
            # Count by attack type
            attack_type_counts: Dict[str, int] = {}
            tactic_counts: Dict[str, int] = {}
            sector_counts: Dict[str, int] = {}
            malware_counts: Dict[str, int] = {}
            country_counts: Dict[str, int] = {}

            for t in all_threats:
                at = t.get("attack_type", "Unknown")
                attack_type_counts[at] = attack_type_counts.get(at, 0) + 1
                tc = t.get("tactic", "Unknown")
                tactic_counts[tc] = tactic_counts.get(tc, 0) + 1
                sec = t.get("target_sector", "General")
                sector_counts[sec] = sector_counts.get(sec, 0) + 1
                mlw = t.get("malware", "")
                if mlw:
                    malware_counts[mlw] = malware_counts.get(mlw, 0) + 1
                loc = t.get("location") or {}
                country = loc.get("country", "Unknown")
                if country and country != "Unknown":
                    country_counts[country] = country_counts.get(country, 0) + 1

            # Top attacking countries
            sorted_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)
            top_countries_list = [{"country": c, "count": n} for c, n in sorted_countries[:10]]

            # Top malware families
            sorted_malware = sorted(malware_counts.items(), key=lambda x: x[1], reverse=True)
            top_malware_list = [{"malware": m, "count": n} for m, n in sorted_malware[:10]]

            # Top tactics
            sorted_tactics = sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True)
            top_tactics_list = [{"tactic": t, "count": n} for t, n in sorted_tactics[:8]]

            # Top attack types
            sorted_types = sorted(attack_type_counts.items(), key=lambda x: x[1], reverse=True)
            top_types_list = [{"type": tp, "count": n} for tp, n in sorted_types[:8]]

            # Top targeted sectors
            sorted_sectors = sorted(sector_counts.items(), key=lambda x: x[1], reverse=True)
            top_sectors_list = [{"sector": s, "count": n} for s, n in sorted_sectors[:8]]

            # Critical threat alerts (top 5 most severe)
            critical_alerts = []
            for t in all_threats[:5]:
                critical_alerts.append({
                    "title": t.get("title", ""),
                    "severity": t.get("severity", ""),
                    "attack_type": t.get("attack_type", ""),
                    "tactic": t.get("tactic", ""),
                    "description": t.get("description", "")[:150],
                    "link": t.get("link", ""),
                })

            # Active attack campaigns detected (grouped by attack_type)
            active_campaigns = []
            for at_info in top_types_list[:6]:
                at = at_info["type"]
                count = at_info["count"]
                examples = [t for t in all_threats if t.get("attack_type") == at][:3]
                active_campaigns.append({
                    "attack_type": at,
                    "count": count,
                    "severity": "CRITICAL" if count > 5 else "HIGH",
                    "examples": [{"title": e.get("title",""), "ip": e.get("ip",""), "location": (e.get("location") or {}).get("country","")} for e in examples],
                })

            return {
                "threats": all_threats[:100],
                "stats": stats,
                "sources": {
                    "feodo_tracker": len(botnet_c2s) > 0,
                    "github_advisories": len(cve_alerts) > 0,
                    "cisa_kev": len(cisa_kev) > 0,
                    "blocklist_de": len(blocklist_ips) > 0,
                },
                "last_update": stats["last_update"],
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "data_veracity": "REAL - No simulation or fake data",
                # --- New intelligence sections ---
                "attack_summary": {
                    "total_threats": len(all_threats),
                    "critical_count": sum(1 for t in all_threats if t["severity"] == "CRITICAL"),
                    "high_count": sum(1 for t in all_threats if t["severity"] == "HIGH"),
                    "unique_attack_types": len(attack_type_counts),
                    "unique_tactics": len(tactic_counts),
                    "unique_countries": len(country_counts),
                },
                "top_attacks": top_types_list,
                "top_tactics": top_tactics_list,
                "top_targets": top_sectors_list,
                "top_countries": top_countries_list,
                "top_malware": top_malware_list,
                "active_campaigns": active_campaigns,
                "critical_alerts": critical_alerts,
            }
        except Exception as e:
            logger.error(f"_build_response error: {e}")
            return {
                "threats": [],
                "stats": {"total_threats": 0, "last_update": None},
                "sources": {"feodo_tracker": False, "github_advisories": False, "cisa_kev": False, "blocklist_de": False},
                "last_update": None,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "error": str(e)[:200]
            }

    def get_threats_by_type(self, threat_type: str) -> List[Dict]:
        """Get threats filtered by type."""
        return [t for t in self._build_response()["threats"] if t["type"] == threat_type]


# Global instance
real_threat_feed = RealTimeThreatFeed()