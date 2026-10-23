#!/usr/bin/env python3
"""
ioc_enrich.py - multi-source IOC enrichment with a normalized verdict.

Takes IPs, domains, URLs, file hashes (MD5/SHA1/SHA256) and CVE IDs, queries
free / free-key threat-intel APIs in parallel, and emits one JSON object per
indicator that a SOAR playbook or a local LLM can consume directly.

Design rules:
  * Lookup only. Nothing is ever uploaded or submitted for scanning.
  * Private, loopback, link-local and reserved IPs are never sent externally.
  * Providers without a configured key are skipped (or run keyless where the
    provider allows it), and every provider failure is isolated.
  * Python standard library only.

Usage:
  python3 ioc_enrich.py 8.8.8.8 hxxps://evil[.]example/path CVE-2024-3400
  python3 ioc_enrich.py -f iocs.txt --format jsonl
  cat iocs.txt | python3 ioc_enrich.py -
"""
from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from typing import Callable, Optional

__version__ = "1.0.0"
USER_AGENT = f"ioc-enrich/{__version__}"
DEFAULT_TIMEOUT = 12

# --------------------------------------------------------------------------- #
# Indicator parsing
# --------------------------------------------------------------------------- #

RE_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
RE_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
RE_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
RE_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$", re.IGNORECASE
)


def refang(value: str) -> str:
    """Undo common defanging: hxxp, [.], (.), [:], [at]."""
    v = value.strip().strip("'\"<>")
    v = re.sub(r"^hxxp", "http", v, flags=re.IGNORECASE)
    v = re.sub(r"^fxp", "ftp", v, flags=re.IGNORECASE)
    for a, b in (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."),
                 ("[:]", ":"), ("[://]", "://"), ("[at]", "@"), ("[@]", "@")):
        v = v.replace(a, b)
    return v


@dataclass
class Indicator:
    raw: str
    value: str
    type: str  # ipv4 | ipv6 | domain | url | md5 | sha1 | sha256 | cve | unknown
    internal: bool = False  # private/reserved IP -> never sent externally

    @property
    def host(self) -> Optional[str]:
        if self.type == "url":
            return urllib.parse.urlsplit(self.value).hostname
        if self.type in ("domain", "ipv4", "ipv6"):
            return self.value
        return None


def classify(raw: str) -> Indicator:
    v = refang(raw)
    try:
        ip = ipaddress.ip_address(v)
        internal = not ip.is_global
        return Indicator(raw, str(ip), "ipv4" if ip.version == 4 else "ipv6", internal)
    except ValueError:
        pass
    if RE_CVE.match(v):
        return Indicator(raw, v.upper(), "cve")
    if RE_SHA256.match(v):
        return Indicator(raw, v.lower(), "sha256")
    if RE_SHA1.match(v):
        return Indicator(raw, v.lower(), "sha1")
    if RE_MD5.match(v):
        return Indicator(raw, v.lower(), "md5")
    if re.match(r"^[a-z][a-z0-9+.-]*://", v, re.IGNORECASE):
        return Indicator(raw, v, "url")
    if RE_DOMAIN.match(v):
        return Indicator(raw, v.lower().rstrip("."), "domain")
    return Indicator(raw, v, "unknown")


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #

class HTTPError(Exception):
    def __init__(self, status: int, body: str = ""):
        super().__init__(f"HTTP {status}")
        self.status = status
        self.body = body


def http_json(url: str, *, method: str = "GET", headers: Optional[dict] = None,
              form: Optional[dict] = None, timeout: int = DEFAULT_TIMEOUT):
    """Minimal JSON HTTP client. Raises HTTPError on non-2xx."""
    data = None
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    hdrs.update(headers or {})
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        method = "POST"
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        raise HTTPError(e.code, e.read().decode("utf-8", "replace")[:500]) from None
    return json.loads(body) if body else {}


# Swappable for tests.
HTTP: Callable[..., dict] = http_json

# --------------------------------------------------------------------------- #
# Provider framework
# --------------------------------------------------------------------------- #

# Signals, strongest first. "exploited" is used for CVEs.
SIGNALS = ("malicious", "exploited", "suspicious", "benign", "unknown")


@dataclass
class Finding:
    provider: str
    status: str = "ok"           # ok | not_found | skipped | error
    signal: str = "unknown"      # one of SIGNALS
    score: Optional[int] = None  # provider-native 0-100 where meaningful
    tags: list = field(default_factory=list)
    details: dict = field(default_factory=dict)
    reference: Optional[str] = None
    error: Optional[str] = None
    latency_ms: Optional[int] = None


class Provider:
    name = "base"
    types: tuple = ()
    key_env: Optional[str] = None
    key_required = True

    @property
    def key(self) -> Optional[str]:
        return os.environ.get(self.key_env) if self.key_env else None

    def available(self) -> bool:
        return not (self.key_required and self.key_env and not self.key)

    def supports(self, ind: Indicator) -> bool:
        return ind.type in self.types

    def lookup(self, ind: Indicator) -> Finding:  # pragma: no cover - abstract
        raise NotImplementedError

    def run(self, ind: Indicator) -> Finding:
        if not self.available():
            return Finding(self.name, status="skipped", error=f"set {self.key_env}")
        t0 = time.monotonic()
        try:
            f = self.lookup(ind)
        except HTTPError as e:
            if e.status == 404:
                f = Finding(self.name, status="not_found")
            elif e.status == 429:
                f = Finding(self.name, status="error", error="rate limited (429)")
            elif e.status in (401, 403):
                f = Finding(self.name, status="error", error=f"auth failed ({e.status})")
            else:
                f = Finding(self.name, status="error", error=str(e))
        except Exception as e:  # network, JSON, unexpected schema
            f = Finding(self.name, status="error", error=f"{type(e).__name__}: {e}")
        f.latency_ms = int((time.monotonic() - t0) * 1000)
        return f


# ---------------------------- VirusTotal (v3) ------------------------------ #

class VirusTotal(Provider):
    name = "virustotal"
    types = ("ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256")
    key_env = "VT_API_KEY"

    def lookup(self, ind):
        if ind.type in ("ipv4", "ipv6"):
            path, gui = f"ip_addresses/{ind.value}", f"ip-address/{ind.value}"
        elif ind.type == "domain":
            path, gui = f"domains/{ind.value}", f"domain/{ind.value}"
        elif ind.type == "url":
            uid = base64.urlsafe_b64encode(ind.value.encode()).decode().rstrip("=")
            path, gui = f"urls/{uid}", f"url/{uid}"
        else:
            path, gui = f"files/{ind.value}", f"file/{ind.value}"
        data = HTTP(f"https://www.virustotal.com/api/v3/{path}",
                    headers={"x-apikey": self.key})
        attrs = data.get("data", {}).get("attributes", {})
        st = attrs.get("last_analysis_stats", {}) or {}
        mal, sus = st.get("malicious", 0), st.get("suspicious", 0)
        total = sum(v for v in st.values() if isinstance(v, int)) or 0
        if mal >= 3:
            signal = "malicious"
        elif mal >= 1 or sus >= 2:
            signal = "suspicious"
        elif total and st.get("harmless", 0) > 0:
            signal = "benign"
        else:
            signal = "unknown"
        tags = list(attrs.get("tags", []) or [])[:10]
        label = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
        if label:
            tags.append(label)
        return Finding(self.name, signal=signal,
                       score=round(100 * mal / total) if total else None,
                       tags=tags,
                       details={"malicious": mal, "suspicious": sus, "engines": total,
                                "reputation": attrs.get("reputation")},
                       reference=f"https://www.virustotal.com/gui/{gui}")


# ------------------------------- AbuseIPDB -------------------------------- #

class AbuseIPDB(Provider):
    name = "abuseipdb"
    types = ("ipv4", "ipv6")
    key_env = "ABUSEIPDB_API_KEY"

    def lookup(self, ind):
        q = urllib.parse.urlencode({"ipAddress": ind.value, "maxAgeInDays": 90})
        d = HTTP(f"https://api.abuseipdb.com/api/v2/check?{q}",
                 headers={"Key": self.key}).get("data", {})
        score = int(d.get("abuseConfidenceScore") or 0)
        signal = ("malicious" if score >= 75 else "suspicious" if score >= 25
                  else "benign" if d.get("isWhitelisted") else "unknown")
        tags = [t for t in ("tor" if d.get("isTor") else None, d.get("usageType")) if t]
        return Finding(self.name, signal=signal, score=score, tags=tags,
                       details={"reports": d.get("totalReports"),
                                "distinct_users": d.get("numDistinctUsers"),
                                "country": d.get("countryCode"), "isp": d.get("isp"),
                                "last_reported": d.get("lastReportedAt")},
                       reference=f"https://www.abuseipdb.com/check/{ind.value}")


# --------------------------- GreyNoise Community -------------------------- #

class GreyNoise(Provider):
    name = "greynoise"
    types = ("ipv4",)
    key_env = "GREYNOISE_API_KEY"
    key_required = False  # community endpoint works keyless at a low rate

    def lookup(self, ind):
        hdrs = {"key": self.key} if self.key else {}
        try:
            d = HTTP(f"https://api.greynoise.io/v3/community/{ind.value}", headers=hdrs)
        except HTTPError as e:
            if e.status == 404:  # "IP not observed scanning the internet"
                return Finding(self.name, status="not_found",
                               details={"noise": False, "riot": False})
            raise
        cls = d.get("classification")
        signal = {"malicious": "malicious", "benign": "benign"}.get(cls, "unknown")
        if d.get("riot"):  # known business service (CDN, SaaS, resolver)
            signal = "benign"
        return Finding(self.name, signal=signal,
                       tags=[t for t in (d.get("name"), "riot" if d.get("riot") else None,
                                         "scanner" if d.get("noise") else None) if t],
                       details={"classification": cls, "noise": d.get("noise"),
                                "riot": d.get("riot"), "last_seen": d.get("last_seen")},
                       reference=d.get("link"))


# ----------------------------- AlienVault OTX ----------------------------- #

class OTX(Provider):
    name = "otx"
    types = ("ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256")
    key_env = "OTX_API_KEY"
    key_required = False

    SECTION = {"ipv4": "IPv4", "ipv6": "IPv6", "domain": "domain", "url": "url",
               "md5": "file", "sha1": "file", "sha256": "file"}

    def lookup(self, ind):
        sec = self.SECTION[ind.type]
        val = urllib.parse.quote(ind.value, safe="")
        hdrs = {"X-OTX-API-KEY": self.key} if self.key else {}
        d = HTTP(f"https://otx.alienvault.com/api/v1/indicators/{sec}/{val}/general",
                 headers=hdrs)
        pulses = (d.get("pulse_info") or {}).get("pulses", []) or []
        count = (d.get("pulse_info") or {}).get("count", len(pulses))
        whitelisted = any(v.get("source") == "whitelist" for v in d.get("validation", []) or [])
        signal = ("benign" if whitelisted else "malicious" if count >= 5
                  else "suspicious" if count >= 1 else "unknown")
        tags = sorted({t for p in pulses[:20] for t in (p.get("tags") or [])})[:10]
        families = sorted({m.get("display_name") for p in pulses[:20]
                           for m in (p.get("malware_families") or []) if m.get("display_name")})
        attack = sorted({a.get("id") for p in pulses[:20]
                         for a in (p.get("attack_ids") or []) if a.get("id")})
        return Finding(self.name, signal=signal, tags=tags,
                       details={"pulse_count": count, "malware_families": families,
                                "attack_techniques": attack},
                       reference=f"https://otx.alienvault.com/indicator/{sec.lower()}/{val}")


# ------------------------------ abuse.ch ---------------------------------- #

class URLhaus(Provider):
    name = "urlhaus"
    types = ("domain", "ipv4", "url", "md5", "sha256")
    key_env = "ABUSECH_AUTH_KEY"  # abuse.ch now requires a free Auth-Key

    def lookup(self, ind):
        base = "https://urlhaus-api.abuse.ch/v1"
        h = {"Auth-Key": self.key}
        if ind.type == "url":
            d = HTTP(f"{base}/url/", form={"url": ind.value}, headers=h)
        elif ind.type in ("md5", "sha256"):
            d = HTTP(f"{base}/payload/", form={f"{ind.type}_hash": ind.value}, headers=h)
        else:
            d = HTTP(f"{base}/host/", form={"host": ind.value}, headers=h)
        if d.get("query_status") != "ok":
            return Finding(self.name, status="not_found")

        if ind.type == "url":
            online = d.get("url_status") == "online"
            return Finding(self.name, signal="malicious",
                           tags=(d.get("tags") or []) + [d.get("threat") or ""],
                           details={"url_status": d.get("url_status"),
                                    "date_added": d.get("date_added")},
                           reference=d.get("urlhaus_reference"),
                           score=100 if online else 80)
        if ind.type in ("md5", "sha256"):
            return Finding(self.name, signal="malicious",
                           tags=[t for t in (d.get("signature"), d.get("file_type")) if t],
                           details={"url_count": d.get("url_count"),
                                    "first_seen": d.get("firstseen")},
                           reference=f"https://urlhaus.abuse.ch/browse.php?search={ind.value}")
        urls = d.get("urls") or []
        online = sum(1 for u in urls if u.get("url_status") == "online")
        return Finding(self.name, signal="malicious" if online else "suspicious",
                       tags=sorted({t for u in urls[:50] for t in (u.get("tags") or [])})[:10],
                       details={"url_count": d.get("url_count"), "online_urls": online,
                                "blacklists": d.get("blacklists")},
                       reference=d.get("urlhaus_reference"))


class MalwareBazaar(Provider):
    name = "malwarebazaar"
    types = ("md5", "sha1", "sha256")
    key_env = "ABUSECH_AUTH_KEY"

    def lookup(self, ind):
        d = HTTP("https://mb-api.abuse.ch/api/v1/",
                 form={"query": "get_info", "hash": ind.value},
                 headers={"Auth-Key": self.key})
        if d.get("query_status") != "ok" or not d.get("data"):
            return Finding(self.name, status="not_found")
        s = d["data"][0]
        return Finding(self.name, signal="malicious",
                       tags=[t for t in [s.get("signature")] + (s.get("tags") or []) if t][:10],
                       details={"file_type": s.get("file_type"),
                                "file_name": s.get("file_name"),
                                "first_seen": s.get("first_seen"),
                                "sha256": s.get("sha256_hash")},
                       reference=f"https://bazaar.abuse.ch/sample/{s.get('sha256_hash')}/")


# ---------------------------- CVE context --------------------------------- #

class CisaKEV(Provider):
    name = "cisa_kev"
    types = ("cve",)
    key_required = False
    URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
    _cache: Optional[dict] = None

    def _catalog(self) -> dict:
        if CisaKEV._cache is None:  # one download per run, shared across CVEs
            feed = HTTP(self.URL, timeout=30)
            CisaKEV._cache = {v["cveID"].upper(): v for v in feed.get("vulnerabilities", [])}
        return CisaKEV._cache

    def lookup(self, ind):
        v = self._catalog().get(ind.value)
        if not v:
            return Finding(self.name, status="not_found", signal="unknown",
                           details={"in_kev": False})
        ransomware = v.get("knownRansomwareCampaignUse") == "Known"
        return Finding(self.name, signal="exploited",
                       tags=["kev"] + (["ransomware"] if ransomware else []),
                       details={"in_kev": True, "vendor": v.get("vendorProject"),
                                "product": v.get("product"), "name": v.get("vulnerabilityName"),
                                "date_added": v.get("dateAdded"), "due_date": v.get("dueDate"),
                                "ransomware_use": v.get("knownRansomwareCampaignUse"),
                                "cwes": v.get("cwes")},
                       reference=f"https://nvd.nist.gov/vuln/detail/{ind.value}")


class NVD(Provider):
    name = "nvd"
    types = ("cve",)
    key_env = "NVD_API_KEY"
    key_required = False

    def lookup(self, ind):
        hdrs = {"apiKey": self.key} if self.key else {}
        d = HTTP("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
                 + urllib.parse.quote(ind.value), headers=hdrs)
        vulns = d.get("vulnerabilities") or []
        if not vulns:
            return Finding(self.name, status="not_found")
        cve = vulns[0]["cve"]
        metrics = cve.get("metrics", {})
        score = severity = vector = None
        for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(k):
                m = metrics[k][0]["cvssData"]
                score, vector = m.get("baseScore"), m.get("vectorString")
                severity = m.get("baseSeverity") or metrics[k][0].get("baseSeverity")
                break
        desc = next((x["value"] for x in cve.get("descriptions", []) if x.get("lang") == "en"), "")
        cwes = sorted({dd["value"] for w in cve.get("weaknesses", [])
                       for dd in w.get("description", []) if dd.get("value", "").startswith("CWE")})
        return Finding(self.name, signal="unknown",
                       score=int(round(score * 10)) if score is not None else None,
                       tags=[severity.lower()] if severity else [],
                       details={"cvss": score, "severity": severity, "vector": vector,
                                "cwes": cwes, "published": cve.get("published"),
                                "description": desc[:400]},
                       reference=f"https://nvd.nist.gov/vuln/detail/{ind.value}")


class EPSS(Provider):
    name = "epss"
    types = ("cve",)
    key_required = False

    def lookup(self, ind):
        d = HTTP("https://api.first.org/data/v1/epss?cve=" + urllib.parse.quote(ind.value))
        rows = d.get("data") or []
        if not rows:
            return Finding(self.name, status="not_found")
        epss, pct = float(rows[0]["epss"]), float(rows[0]["percentile"])
        return Finding(self.name, signal="unknown", score=int(round(epss * 100)),
                       details={"epss": epss, "percentile": pct, "date": rows[0].get("date")},
                       reference=f"https://www.first.org/epss/")


PROVIDERS: list[Provider] = [VirusTotal(), AbuseIPDB(), GreyNoise(), OTX(),
                             URLhaus(), MalwareBazaar(), CisaKEV(), NVD(), EPSS()]

# --------------------------------------------------------------------------- #
# Verdict aggregation
# --------------------------------------------------------------------------- #

def aggregate(ind: Indicator, findings: list[Finding]) -> dict:
    ok = [f for f in findings if f.status in ("ok", "not_found")]
    by = lambda s: [f.provider for f in ok if f.signal == s]  # noqa: E731

    if ind.type == "cve":
        kev = next((f for f in ok if f.provider == "cisa_kev"), None)
        nvd = next((f for f in ok if f.provider == "nvd"), None)
        epss = next((f for f in ok if f.provider == "epss"), None)
        if kev is None:
            # KEV is authoritative for "exploited"; without it we must not
            # imply the CVE is safe to deprioritize.
            return {"verdict": "undetermined", "priority": None, "confidence": "none",
                    "summary": f"{ind.value}: CISA KEV lookup failed; exploitation "
                               f"status undetermined. Do not deprioritize."}
        in_kev = bool(kev.details.get("in_kev"))
        cvss = nvd.details.get("cvss") if nvd else None
        e = epss.details.get("epss") if epss else None
        if in_kev:
            priority = "P1"
        elif (e or 0) >= 0.10 or (cvss or 0) >= 9.0:
            priority = "P2"
        elif (cvss or 0) >= 7.0:
            priority = "P3"
        else:
            priority = "P4"
        verdict = "exploited" if in_kev else "not_known_exploited"
        parts = [f"{ind.value}: {'IN CISA KEV' if in_kev else 'not in CISA KEV'}"]
        if cvss is not None:
            parts.append(f"CVSS {cvss}")
        if e is not None:
            parts.append(f"EPSS {e:.2%} (p{round(epss.details['percentile'] * 100)})")
        if kev and kev.details.get("ransomware_use") == "Known":
            parts.append("known ransomware use")
        return {"verdict": verdict, "priority": priority,
                "confidence": "high" if kev else "low",
                "summary": "; ".join(parts) + f" -> {priority}."}

    mal, sus, ben = by("malicious"), by("suspicious"), by("benign")
    if not ok:
        return {"verdict": "undetermined", "confidence": "none", "tags": [],
                "malicious_sources": [], "suspicious_sources": [], "benign_sources": [],
                "summary": f"{ind.type} {ind.value}: no source answered "
                           f"(see sources.errors / sources.skipped). Undetermined."}
    if len(mal) >= 2 or (mal and not ben):
        verdict = "malicious"
    elif mal or sus:
        verdict = "suspicious"
    elif ben:
        verdict = "benign"
    else:
        verdict = "unknown"

    answered = len(ok)
    agreeing = len(mal) if verdict == "malicious" else len(mal) + len(sus) if verdict == "suspicious" \
        else len(ben)
    confidence = ("high" if agreeing >= 3 else "medium" if agreeing >= 2
                  else "low")
    tags = sorted({t for f in ok for t in f.tags if t})[:15]
    summary = (f"{ind.type} {ind.value}: {verdict.upper()} "
               f"({len(mal)} malicious, {len(sus)} suspicious, {len(ben)} benign "
               f"of {answered} sources answering)")
    if tags:
        summary += f"; tags: {', '.join(tags[:6])}"
    return {"verdict": verdict, "confidence": confidence,
            "malicious_sources": mal, "suspicious_sources": sus,
            "benign_sources": ben, "tags": tags, "summary": summary + "."}


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

def enrich(raw: str, providers: Optional[list[Provider]] = None,
           pool: Optional[ThreadPoolExecutor] = None) -> dict:
    ind = classify(raw)
    out = {"indicator": ind.value, "input": ind.raw, "type": ind.type}
    if ind.type == "unknown":
        out.update(verdict="unparsed", summary=f"Could not classify '{raw}'.", findings=[])
        return out
    if ind.internal:
        out.update(verdict="internal", confidence="n/a", findings=[],
                   summary=f"{ind.value} is a private/reserved address; not sent to "
                           f"external services. Enrich from internal sources (CMDB, EDR, DHCP).")
        return out

    provs = [p for p in (providers or PROVIDERS) if p.supports(ind)]
    if pool:
        findings = list(pool.map(lambda p: p.run(ind), provs))
    else:
        findings = [p.run(ind) for p in provs]

    out.update(aggregate(ind, findings))
    out["findings"] = [asdict(f) for f in findings]
    out["sources"] = {"answered": sum(f.status in ("ok", "not_found") for f in findings),
                      "skipped": [f.provider for f in findings if f.status == "skipped"],
                      "errors": {f.provider: f.error for f in findings if f.status == "error"}}
    out["enriched_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return out


def read_inputs(args) -> list[str]:
    items: list[str] = []
    for a in args.iocs:
        if a == "-":
            items += sys.stdin.read().split()
        else:
            items.append(a)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line:
                    items.append(line)
    seen, uniq = set(), []
    for i in items:
        if i not in seen:
            seen.add(i)
            uniq.append(i)
    return uniq


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Multi-source IOC enrichment (lookup only).")
    ap.add_argument("iocs", nargs="*", help="indicators; '-' reads stdin")
    ap.add_argument("-f", "--file", help="file with one IOC per line (# comments ok)")
    ap.add_argument("--format", choices=("json", "jsonl", "summary"), default="json")
    ap.add_argument("--providers", help="comma list to restrict, e.g. virustotal,otx")
    ap.add_argument("--no-findings", action="store_true",
                    help="drop per-provider detail (smaller payload for LLM context)")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--list-providers", action="store_true")
    args = ap.parse_args(argv)

    if args.list_providers:
        for p in PROVIDERS:
            state = "ready" if p.available() else f"needs {p.key_env}"
            if p.available() and p.key_env and not p.key:
                state = "ready (keyless, rate limited)"
            print(f"{p.name:15} {','.join(p.types):45} {state}")
        return 0

    iocs = read_inputs(args)
    if not iocs:
        ap.error("no indicators given")
    provs = PROVIDERS
    if args.providers:
        wanted = {x.strip() for x in args.providers.split(",")}
        provs = [p for p in PROVIDERS if p.name in wanted]

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = [enrich(i, provs, pool) for i in iocs]
    if args.no_findings:
        for r in results:
            r.pop("findings", None)

    if args.format == "jsonl":
        for r in results:
            print(json.dumps(r, separators=(",", ":")))
    elif args.format == "summary":
        for r in results:
            print(r["summary"])
    else:
        print(json.dumps(results if len(results) > 1 else results[0], indent=2))

    # Exit code is pipeline-friendly: 2 if anything is malicious/exploited.
    return 2 if any(r.get("verdict") in ("malicious", "exploited") for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
