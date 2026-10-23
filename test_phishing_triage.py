"""Offline tests for examples/phishing_triage.py. All provider HTTP is mocked.
Run: python3 -m unittest test_phishing_triage.py -v
"""
import os
import sys
import unittest
from email.message import EmailMessage
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "examples"))
import ioc_enrich  # noqa: E402
import phishing_triage as pt  # noqa: E402

SAMPLE = (ROOT / "examples" / "samples" / "payroll_phish.eml").read_bytes()
ENV = {"VT_API_KEY": "k", "ABUSEIPDB_API_KEY": "k", "ABUSECH_AUTH_KEY": "k"}


def fake_http(routes):
    calls = []

    def _http(url, **kw):
        calls.append((url, kw))
        target = url + " " + str(kw.get("form", ""))
        for needle, resp in routes:
            if needle in target:
                if isinstance(resp, Exception):
                    raise resp
                return resp
        raise ioc_enrich.HTTPError(404)
    _http.calls = calls
    return _http


def clean_email(**over):
    m = EmailMessage()
    m["From"] = over.get("frm", "Alice <alice@corp.example>")
    m["To"] = "bob@corp.example"
    m["Subject"] = "Lunch"
    m["Authentication-Results"] = "mx.corp.example; spf=pass; dkim=pass; dmarc=pass"
    m["Received"] = "from mail.corp.example (mail.corp.example [10.0.0.9]) by mx.corp.example"
    m.set_content(over.get("body", "See you at noon."))
    return bytes(m)


class TestExtraction(unittest.TestCase):
    def setUp(self):
        self.x = pt.extract(SAMPLE)

    def test_auth_results(self):
        self.assertEqual(self.x["auth"], {"spf": "softfail", "dkim": "none", "dmarc": "fail"})

    def test_received_ips_public_only(self):
        self.assertEqual(self.x["received_ips"], ["185.220.101.1"])  # 10.20.0.5 dropped

    def test_urls_refanged_and_noise_filtered(self):
        self.assertIn("https://payroll-verify.example/login?id=4471", self.x["urls"])
        self.assertFalse(any("w3.org" in u for u in self.x["urls"]))

    def test_mismatched_link(self):
        self.assertEqual(len(self.x["mismatched_links"]), 1)
        self.assertIn("payroll-verify.example", self.x["mismatched_links"][0]["href"])

    def test_attachment_hashed(self):
        a = self.x["attachments"][0]
        self.assertEqual(a["filename"], "Invoice_Summary_4471.html")
        self.assertEqual(len(a["sha256"]), 64)
        self.assertTrue(a["risky_extension"])

    def test_header_flags(self):
        flags = " | ".join(f["flag"] for f in pt.header_flags(self.x))
        for needle in ("DMARC fail", "SPF softfail", "Reply-To domain",
                       "Display name shows domain", "Link text", "High-risk attachment"):
            self.assertIn(needle, flags)

    def test_defanged_url_with_brackets_does_not_crash(self):
        x = pt.extract(clean_email(body="go to hxxps://bad[.]example[.]net/a and http://[broken"))
        self.assertIn("https://bad.example.net/a", x["urls"])

    def test_clean_email_has_no_flags(self):
        self.assertEqual(pt.header_flags(pt.extract(clean_email())), [])


class TestTriage(unittest.TestCase):
    def setUp(self):
        ioc_enrich.CisaKEV._cache = None

    def run_triage(self, routes, raw=SAMPLE):
        with mock.patch.object(ioc_enrich, "HTTP", fake_http(routes)), \
             mock.patch.dict(os.environ, ENV, clear=True):
            return pt.triage(raw)

    def test_malicious_when_url_listed(self):
        r = self.run_triage([
            ("payroll-verify.example/login", {"query_status": "ok", "url_status": "online",
                                              "threat": "credential_phishing", "tags": ["phishing"]}),
            ("urlhaus-api.abuse.ch/v1/host", {"query_status": "no_results"}),
            ("urlhaus-api.abuse.ch/v1/payload", {"query_status": "no_results"}),
            ("virustotal.com/api/v3/urls", {"data": {"attributes": {"last_analysis_stats":
                {"malicious": 9, "suspicious": 1, "harmless": 50}}}}),
        ])
        d = r["disposition"]
        self.assertEqual(d["verdict"], "MALICIOUS")
        self.assertIn("https://payroll-verify.example/login?id=4471", d["malicious_indicators"])
        ids = {t["id"] for t in r["attack"]}
        self.assertTrue({"T1566.002", "T1566.001", "T1036", "T1598.003"} <= ids)
        self.assertTrue(any("Purge" in a for a in r["actions"]))
        md = pt.render_markdown(r)
        self.assertIn("payroll-verify[.]example", md)        # defanged in the report
        self.assertNotIn("https://payroll-verify.example", md)

    def test_attachment_never_uploaded(self):
        http = fake_http([])
        with mock.patch.object(ioc_enrich, "HTTP", http), mock.patch.dict(os.environ, ENV, clear=True):
            pt.triage(SAMPLE)
        for url, kw in http.calls:
            form = kw.get("form") or {}
            self.assertNotIn("file", form)                   # only hash lookups, no uploads
            self.assertNotIn("Sample attachment", str(form))

    def test_all_sources_down_is_undetermined_not_clean(self):
        r = self.run_triage([("", ioc_enrich.HTTPError(503))], raw=clean_email(
            body="Report: https://reports.corp.example/q4"))
        self.assertEqual(r["disposition"]["verdict"], "UNDETERMINED")
        self.assertTrue(any("do not close" in a for a in r["actions"]))

    def test_headers_only_mode(self):
        with mock.patch.object(ioc_enrich, "HTTP", fake_http([])):
            r = pt.triage(SAMPLE, enrich=False)
        self.assertEqual(r["disposition"]["mode"], "headers_only")
        self.assertEqual(r["disposition"]["verdict"], "SUSPICIOUS")
        self.assertEqual(r["enrichment"], [])

    def test_internal_relay_never_queried(self):
        http = fake_http([])
        with mock.patch.object(ioc_enrich, "HTTP", http), mock.patch.dict(os.environ, ENV, clear=True):
            pt.triage(SAMPLE)
        self.assertFalse(any("10.20.0.5" in u for u, _ in http.calls))


if __name__ == "__main__":
    unittest.main()
