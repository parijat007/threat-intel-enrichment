#!/usr/bin/env python3
"""
phishing_triage.py - triage a user-reported phishing email end to end.

Use case
--------
A user reports a suspicious email. The analyst needs to know, quickly:
  * Did the message fail sender authentication (SPF / DKIM / DMARC)?
  * Are there header red flags (Reply-To mismatch, display-name spoofing)?
  * Are the links, sending infrastructure or attachments known-bad?
  * What should happen next (block, purge, reset credentials, close)?

This script answers those from a single .eml file:

  1. Parse the message and its MIME parts (stdlib `email`).
  2. Extract indicators: originating public IPs from Received headers,
     sender / Reply-To / Return-Path domains, URLs from text and HTML
     bodies (including href targets), and attachment SHA256 hashes.
  3. Run header heuristics and read Authentication-Results.
  4. Enrich every indicator through ioc_enrich (lookup only, internal IPs
     never leave the host, attachments are hashed locally and never uploaded).
  5. Produce an overall disposition, ATT&CK mapping and recommended actions
     as a Markdown report (for the ticket) and JSON (for SOAR / an LLM).

Usage
-----
  python3 examples/phishing_triage.py reported.eml
  python3 examples/phishing_triage.py reported.eml --json report.json --md report.md
  python3 examples/phishing_triage.py reported.eml --no-enrich   # parsing only, no network

Exit code: 2 if the disposition is MALICIOUS, otherwise 0.
"""
from __future__ import annotations

import argparse
import email
import hashlib
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from email import policy
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import ioc_enrich  # noqa: E402

# Domains that appear in almost every message and add only noise to enrichment.
NOISE_DOMAINS = {
    "w3.org", "schemas.microsoft.com", "schemas.openxmlformats.org",
    "purl.org", "www.w3.org",
}
URL_RE = re.compile(r"""\b(?:https?|hxxps?)://[^\s<>"'()\]]+""", re.IGNORECASE)
IP_RE = re.compile(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?")
RISKY_EXT = {".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".lnk",
             ".iso", ".img", ".vhd", ".one", ".html", ".htm", ".svg", ".zip", ".7z",
             ".rar", ".docm", ".xlsm", ".pptm", ".msi", ".bat", ".cmd", ".ps1"}


# --------------------------------------------------------------------------- #
# Extraction
# --------------------------------------------------------------------------- #

class _HrefParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[tuple[str, str]] = []  # (href, visible text)
        self._href: Optional[str] = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def _domain_of(addr: str) -> Optional[str]:
    _, a = parseaddr(addr or "")
    return a.rsplit("@", 1)[1].lower().strip(">") if "@" in a else None


def _registrable(host: str) -> str:
    """Rough registrable domain (last two labels). Good enough for mismatch checks."""
    parts = host.lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def _clean_url(u: str) -> str:
    return ioc_enrich.refang(u).rstrip(".,;:!?'\")]>")


def _host(u: str) -> Optional[str]:
    """Hostname of a URL, or None if the URL is malformed."""
    try:
        return urlsplit(u).hostname
    except ValueError:
        return None


_DEFANG = (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("[:]", ":"), ("[://]", "://"))


def _refang_text(text: str) -> str:
    for a, b in _DEFANG:
        text = text.replace(a, b)
    return re.sub(r"\bhxxp", "http", text, flags=re.IGNORECASE)


def parse_auth_results(msg) -> dict:
    out = {}
    for h in msg.get_all("Authentication-Results", []) or []:
        for mech in ("spf", "dkim", "dmarc"):
            m = re.search(rf"\b{mech}=(\w+)", str(h), re.IGNORECASE)
            if m and mech not in out:
                out[mech] = m.group(1).lower()
    return out


def extract(raw: bytes) -> dict:
    msg = email.message_from_bytes(raw, policy=policy.default)

    from_hdr = str(msg.get("From", ""))
    display, from_addr = parseaddr(from_hdr)
    from_dom = _domain_of(from_hdr)
    reply_dom = _domain_of(str(msg.get("Reply-To", ""))) if msg.get("Reply-To") else None
    rpath_dom = _domain_of(str(msg.get("Return-Path", ""))) if msg.get("Return-Path") else None

    # Originating IPs: Received headers are prepended, so the last one is closest
    # to the sender. Keep public addresses only; ioc_enrich also guards this.
    received_ips: list[str] = []
    for h in reversed(msg.get_all("Received", []) or []):
        for ip in IP_RE.findall(str(h)):
            ind = ioc_enrich.classify(ip)
            if ind.type == "ipv4" and not ind.internal and ip not in received_ips:
                received_ips.append(ip)

    urls: list[str] = []
    mismatched_links: list[dict] = []
    attachments: list[dict] = []

    for part in msg.walk():
        if part.is_multipart():
            continue
        disp = part.get_content_disposition()
        fname = part.get_filename()
        ctype = part.get_content_type()

        if disp == "attachment" or (fname and disp != "inline"):
            payload = part.get_payload(decode=True) or b""
            ext = Path(fname or "").suffix.lower()
            attachments.append({
                "filename": fname, "content_type": ctype, "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "md5": hashlib.md5(payload).hexdigest(),  # noqa: S324 - lookup key only
                "risky_extension": ext in RISKY_EXT,
            })
            continue

        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            body = part.get_content()
        except Exception:
            body = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")

        for u in URL_RE.findall(_refang_text(body)):
            u = _clean_url(u)
            if u not in urls:
                urls.append(u)

        if ctype == "text/html":
            p = _HrefParser()
            p.feed(body)
            for href, text in p.links:
                if not href or not re.match(r"^(https?|hxxps?)://", href, re.IGNORECASE):
                    continue
                href = _clean_url(href)
                if href not in urls:
                    urls.append(href)
                # Visible text shows one domain, link goes to another.
                shown = URL_RE.search(text) or re.search(r"\b([a-z0-9-]+\.)+[a-z]{2,}\b", text, re.I)
                if shown:
                    shown_host = _host(_clean_url(shown.group(0))) or shown.group(0)
                    real_host = _host(href) or ""
                    if shown_host and real_host and _registrable(shown_host) != _registrable(real_host):
                        mismatched_links.append({"text": text[:120], "href": href})

    hosts = []
    for u in urls:
        h = _host(u)
        if h and h not in hosts and _registrable(h) not in NOISE_DOMAINS:
            hosts.append(h)

    return {
        "subject": str(msg.get("Subject", "")),
        "date": str(msg.get("Date", "")),
        "message_id": str(msg.get("Message-ID", "")),
        "from": {"display_name": display, "address": from_addr, "domain": from_dom},
        "reply_to_domain": reply_dom,
        "return_path_domain": rpath_dom,
        "auth": parse_auth_results(msg),
        "received_ips": received_ips,
        "urls": [u for u in urls if _registrable(_host(u) or "") not in NOISE_DOMAINS],
        "url_hosts": hosts,
        "mismatched_links": mismatched_links,
        "attachments": attachments,
    }


# --------------------------------------------------------------------------- #
# Heuristics
# --------------------------------------------------------------------------- #

def header_flags(x: dict) -> list[dict]:
    flags = []
    auth = x["auth"]
    for mech in ("spf", "dkim", "dmarc"):
        v = auth.get(mech)
        if v in ("fail", "softfail", "permerror"):
            flags.append({"flag": f"{mech.upper()} {v}", "weight": 2 if mech == "dmarc" else 1})
    if not auth:
        flags.append({"flag": "No Authentication-Results header", "weight": 0})

    fd = x["from"]["domain"]
    if fd and x["reply_to_domain"] and _registrable(x["reply_to_domain"]) != _registrable(fd):
        flags.append({"flag": f"Reply-To domain ({x['reply_to_domain']}) differs from From ({fd})",
                      "weight": 2})
    if fd and x["return_path_domain"] and _registrable(x["return_path_domain"]) != _registrable(fd):
        flags.append({"flag": f"Return-Path domain ({x['return_path_domain']}) differs from From ({fd})",
                      "weight": 1})

    dn = (x["from"]["display_name"] or "").lower()
    m = re.search(r"([a-z0-9-]+\.)+[a-z]{2,}", dn)
    if m and fd and _registrable(m.group(0)) != _registrable(fd):
        flags.append({"flag": f"Display name shows domain '{m.group(0)}' but sender is {fd}",
                      "weight": 2})

    for ml in x["mismatched_links"]:
        flags.append({"flag": f"Link text '{ml['text'][:60]}' points to {_host(ml['href'])}",
                      "weight": 2})
    for a in x["attachments"]:
        if a["risky_extension"]:
            flags.append({"flag": f"High-risk attachment type: {a['filename']}", "weight": 2})
    return flags


# --------------------------------------------------------------------------- #
# Enrichment and disposition
# --------------------------------------------------------------------------- #

def indicators_for(x: dict, max_urls: int = 15) -> list[tuple[str, str]]:
    """(role, indicator) pairs, deduplicated, URLs capped to protect API quotas."""
    items: list[tuple[str, str]] = []
    for ip in x["received_ips"]:
        items.append(("sending_ip", ip))
    for role, d in (("sender_domain", x["from"]["domain"]),
                    ("reply_to_domain", x["reply_to_domain"]),
                    ("return_path_domain", x["return_path_domain"])):
        if d:
            items.append((role, d))
    for u in x["urls"][:max_urls]:
        items.append(("url", u))
    for h in x["url_hosts"]:
        items.append(("url_host", h))
    for a in x["attachments"]:
        items.append(("attachment", a["sha256"]))
    seen, out = set(), []
    for role, v in items:
        if v not in seen:
            seen.add(v)
            out.append((role, v))
    return out


def disposition(flags: list[dict], enriched: list[dict]) -> dict:
    verdicts = [e["verdict"] for e in enriched]
    mal = [e for e in enriched if e["verdict"] == "malicious"]
    sus = [e for e in enriched if e["verdict"] == "suspicious"]
    flag_score = sum(f["weight"] for f in flags)
    undetermined = sum(v == "undetermined" for v in verdicts)

    if mal:
        verdict, conf = "MALICIOUS", "high" if any(e.get("confidence") in ("high", "medium") for e in mal) else "medium"
    elif sus or flag_score >= 4:
        verdict, conf = "SUSPICIOUS", "medium" if (sus and flag_score >= 2) else "low"
    elif enriched and undetermined == len(enriched):
        verdict, conf = "UNDETERMINED", "none"
    elif flag_score >= 2:
        verdict, conf = "SUSPICIOUS", "low"
    else:
        verdict, conf = "NO KNOWN THREAT", "low" if undetermined else "medium"
    return {"verdict": verdict, "confidence": conf, "header_flag_score": flag_score,
            "malicious_indicators": [e["indicator"] for e in mal],
            "suspicious_indicators": [e["indicator"] for e in sus],
            "undetermined_indicators": undetermined}


def attack_mapping(x: dict, enriched: list[dict], flags: list[dict]) -> list[dict]:
    techniques = []
    bad = {e["indicator"] for e in enriched if e["verdict"] in ("malicious", "suspicious")}
    if x["urls"]:
        techniques.append({"id": "T1566.002", "name": "Phishing: Spearphishing Link",
                           "evidence": f"{len(x['urls'])} URL(s); "
                                       f"{sum(u in bad for u in x['urls'])} flagged"})
    if x["attachments"]:
        techniques.append({"id": "T1566.001", "name": "Phishing: Spearphishing Attachment",
                           "evidence": ", ".join(a["filename"] or "unnamed" for a in x["attachments"])})
    spoofed_name = any(f["flag"].startswith("Display name") for f in flags)
    if x["mismatched_links"] or spoofed_name:
        ev = [e for e, on in (("link text does not match destination", x["mismatched_links"]),
                              ("display name impersonates another domain", spoofed_name)) if on]
        techniques.append({"id": "T1036", "name": "Masquerading", "evidence": "; ".join(ev)})
    # Credential-harvesting page signal from enrichment tags.
    tags = {t.lower() for e in enriched for t in e.get("tags", [])}
    if tags & {"phishing", "credential_phishing", "credential-harvesting"}:
        techniques.append({"id": "T1598.003", "name": "Phishing for Information: Spearphishing Link",
                           "evidence": "provider tags indicate credential phishing"})
    return techniques


def recommended_actions(disp: dict, x: dict) -> list[str]:
    v = disp["verdict"]
    if v == "MALICIOUS":
        acts = [
            "Purge the message from all mailboxes (search by Message-ID and sender).",
            "Block the malicious indicators: " + ", ".join(disp["malicious_indicators"][:5]) + ".",
            "Query proxy, DNS and EDR telemetry for any user who clicked or opened the attachment.",
        ]
        if x["urls"]:
            acts.append("If anyone submitted credentials: reset the password, revoke sessions and tokens, and review MFA registrations.")
        if x["attachments"]:
            acts.append("Hunt for the attachment hash across endpoints and quarantine any matches.")
        acts.append("Notify the reporter, and open an incident if any interaction is confirmed.")
        return acts
    if v == "SUSPICIOUS":
        return ["Quarantine the message pending analyst review.",
                "Detonate the URLs or attachment in an isolated sandbox (an internal or approved service).",
                "Check whether other users received the same message (sender + subject).",
                "Re-run enrichment in 24 hours; new infrastructure is often unlisted at first."]
    if v == "UNDETERMINED":
        return ["Enrichment sources were unreachable or unconfigured: do not close.",
                "Fix connectivity or API keys (see sources.errors) and re-run.",
                "Hold the message in quarantine until there is a verdict."]
    return ["No known-bad indicators were found and the headers show no strong red flags.",
            "Absence from threat feeds is not proof of safety: new phishing infrastructure is often unlisted.",
            "Close with a note to the reporter, or release from quarantine if your process allows it."]


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #

_URLISH = re.compile(r"\bhttps?://\S+", re.IGNORECASE)
_HOSTISH = re.compile(r"\b(?:\d{1,3}(?:\.\d{1,3}){3}|(?:[a-z0-9-]+\.)+[a-z]{2,63})\b", re.IGNORECASE)


def _defang(v: str) -> str:
    """Defang every URL, domain and IPv4 address in a string."""
    if not v:
        return v
    v = _URLISH.sub(lambda m: re.sub(r"^http", "hxxp", m.group(0), flags=re.I), v)
    return _HOSTISH.sub(lambda m: m.group(0).replace(".", "[.]"), v)


def render_markdown(r: dict) -> str:
    x, d = r["extracted"], r["disposition"]
    icon = {"MALICIOUS": "🔴", "SUSPICIOUS": "🟠", "UNDETERMINED": "⚪", "NO KNOWN THREAT": "🟢"}[d["verdict"]]
    L = [f"# Phishing triage report",
         "",
         f"**Disposition:** {icon} **{d['verdict']}** (confidence: {d['confidence']})"
         + (" (headers only, no indicator lookups run)" if d.get("mode") == "headers_only" else "") + "  ",
         f"**Subject:** {x['subject']}  ",
         f"**From:** {x['from']['display_name']} <{x['from']['address']}>  ",
         f"**Date:** {x['date']}  ",
         f"**Message-ID:** `{x['message_id']}`  ",
         f"**Generated:** {r['generated_at']}",
         "",
         "## Sender authentication",
         "",
         "| SPF | DKIM | DMARC |", "|---|---|---|",
         "| {} | {} | {} |".format(*(x["auth"].get(m, "n/a") for m in ("spf", "dkim", "dmarc"))),
         "",
         "## Header and content red flags",
         ""]
    L += [f"- {_defang(f['flag'])}" for f in r["header_flags"]] or ["- None found"]
    L += ["", "## Indicator enrichment", "",
          "| Role | Indicator | Verdict | Confidence | Summary |", "|---|---|---|---|---|"]
    for e in r["enrichment"]:
        s = _defang(e.get("summary", "")).replace("|", "/")
        L.append(f"| {e['role']} | `{_defang(e['indicator'])}` | {e['verdict']} | "
                 f"{e.get('confidence', '')} | {s[:140]} |")
    if r["extracted"]["attachments"]:
        L += ["", "## Attachments", "", "| File | Type | Size | SHA256 |", "|---|---|---|---|"]
        for a in x["attachments"]:
            L.append(f"| {a['filename']} | {a['content_type']} | {a['size']} B | `{a['sha256']}` |")
    L += ["", "## MITRE ATT&CK", ""]
    L += [f"- **{t['id']}** {t['name']}: {t['evidence']}" for t in r["attack"]] or ["- None mapped"]
    L += ["", "## Recommended actions", ""]
    L += [f"{i}. {_defang(a)}" for i, a in enumerate(r["actions"], 1)]
    L += ["", "---",
          "_Indicators are defanged. Enrichment is lookup-only; the attachment was hashed locally and was not uploaded._"]
    return "\n".join(L) + "\n"


def triage(raw: bytes, enrich: bool = True, workers: int = 8) -> dict:
    x = extract(raw)
    flags = header_flags(x)
    enriched: list[dict] = []
    if enrich:
        pairs = indicators_for(x)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for role, ind in pairs:
                res = ioc_enrich.enrich(ind, pool=pool)
                res.pop("findings", None)
                res["role"] = role
                enriched.append(res)
    disp = disposition(flags, enriched)
    disp["mode"] = "full" if enrich else "headers_only"
    if not enrich and disp["verdict"] == "NO KNOWN THREAT":
        # Without lookups, a clean header check proves nothing about the payload.
        disp.update(verdict="UNDETERMINED", confidence="none")
    return {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "disposition": disp, "extracted": x, "header_flags": flags,
            "enrichment": enriched, "attack": attack_mapping(x, enriched, flags),
            "actions": recommended_actions(disp, x)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Triage a reported phishing email (.eml).")
    ap.add_argument("eml", help="path to the .eml file")
    ap.add_argument("--json", help="write the JSON report to this path")
    ap.add_argument("--md", help="write the Markdown report to this path")
    ap.add_argument("--no-enrich", action="store_true", help="parse and score headers only; no lookups")
    args = ap.parse_args(argv)

    report = triage(Path(args.eml).read_bytes(), enrich=not args.no_enrich)
    md = render_markdown(report)
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2))
    if args.md:
        Path(args.md).write_text(md)
    if not args.md:
        print(md)
    return 2 if report["disposition"]["verdict"] == "MALICIOUS" else 0


if __name__ == "__main__":
    sys.exit(main())
