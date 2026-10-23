"""Offline tests: classification, refanging, provider parsing and verdict logic.
Run: python3 -m unittest test_ioc_enrich.py -v
"""
import base64
import os
import unittest
from unittest import mock

import ioc_enrich as ie


def fake_http(routes):
    """routes: list of (substring, response-or-exception). First match wins."""
    calls = []

    def _http(url, **kw):
        calls.append((url, kw))
        for needle, resp in routes:
            if needle in url:
                if isinstance(resp, Exception):
                    raise resp
                return resp
        raise ie.HTTPError(404)
    _http.calls = calls
    return _http


ENV = {"VT_API_KEY": "k", "ABUSEIPDB_API_KEY": "k", "ABUSECH_AUTH_KEY": "k"}


class TestClassify(unittest.TestCase):
    def test_types(self):
        cases = {
            "8.8.8.8": "ipv4", "2606:4700:4700::1111": "ipv6",
            "example.com": "domain", "https://a.b.example.org/x?y=1": "url",
            "d41d8cd98f00b204e9800998ecf8427e": "md5",
            "da39a3ee5e6b4b0d3255bfef95601890afd80709": "sha1",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "sha256",
            "cve-2024-3400": "cve", "not an ioc": "unknown",
        }
        for raw, t in cases.items():
            self.assertEqual(ie.classify(raw).type, t, raw)

    def test_refang(self):
        self.assertEqual(ie.classify("hxxps://evil[.]example[.]com/p").value,
                         "https://evil.example.com/p")
        self.assertEqual(ie.classify("1[.]2[.]3[.]4").value, "1.2.3.4")

    def test_internal_ips_flagged(self):
        for ip in ("10.1.2.3", "192.168.0.1", "127.0.0.1", "169.254.1.1", "fd00::1"):
            self.assertTrue(ie.classify(ip).internal, ip)
        self.assertFalse(ie.classify("8.8.8.8").internal)


class TestInternalNeverSent(unittest.TestCase):
    def test_no_http_for_private(self):
        http = fake_http([])
        with mock.patch.object(ie, "HTTP", http), mock.patch.dict(os.environ, ENV):
            r = ie.enrich("10.0.0.5")
        self.assertEqual(r["verdict"], "internal")
        self.assertEqual(http.calls, [])


class TestIPVerdicts(unittest.TestCase):
    def run_ip(self, routes):
        with mock.patch.object(ie, "HTTP", fake_http(routes)), \
             mock.patch.dict(os.environ, ENV, clear=False):
            return ie.enrich("185.220.101.1")

    def test_malicious_consensus(self):
        r = self.run_ip([
            ("virustotal", {"data": {"attributes": {"last_analysis_stats":
                {"malicious": 12, "suspicious": 1, "harmless": 50, "undetected": 30}}}}),
            ("abuseipdb", {"data": {"abuseConfidenceScore": 100, "totalReports": 900,
                                    "isTor": True, "usageType": "Data Center"}}),
            ("greynoise", {"classification": "malicious", "noise": True, "riot": False,
                           "name": "unknown", "link": "https://viz.greynoise.io/ip/x"}),
            ("otx", {"pulse_info": {"count": 40, "pulses": [
                {"tags": ["tor"], "malware_families": [{"display_name": "X"}],
                 "attack_ids": [{"id": "T1090"}]}]}}),
        ])
        self.assertEqual(r["verdict"], "malicious")
        self.assertEqual(r["confidence"], "high")
        otx = next(f for f in r["findings"] if f["provider"] == "otx")
        self.assertEqual(otx["details"]["attack_techniques"], ["T1090"])
        self.assertIn("tor", r["tags"])

    def test_benign_riot(self):
        r = self.run_ip([
            ("virustotal", {"data": {"attributes": {"last_analysis_stats":
                {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 20}}}}),
            ("abuseipdb", {"data": {"abuseConfidenceScore": 0, "isWhitelisted": True}}),
            ("greynoise", {"classification": "benign", "riot": True, "noise": False,
                           "name": "Google Public DNS"}),
            ("otx", {"pulse_info": {"count": 0, "pulses": []},
                     "validation": [{"source": "whitelist"}]}),
        ])
        self.assertEqual(r["verdict"], "benign")

    def test_errors_isolated(self):
        r = self.run_ip([
            ("virustotal", ie.HTTPError(429)),
            ("abuseipdb", ie.HTTPError(401)),
            ("greynoise", ie.HTTPError(404)),
            ("otx", ValueError("bad json")),
        ])
        self.assertEqual(r["verdict"], "unknown")  # greynoise not_found still answered
        self.assertIn("virustotal", r["sources"]["errors"])
        self.assertIn("rate limited", r["sources"]["errors"]["virustotal"])
        gn = next(f for f in r["findings"] if f["provider"] == "greynoise")
        self.assertEqual(gn["status"], "not_found")

    def test_missing_key_skipped(self):
        with mock.patch.object(ie, "HTTP", fake_http([])), \
             mock.patch.dict(os.environ, {}, clear=True):
            r = ie.enrich("1.1.1.1")
        self.assertIn("virustotal", r["sources"]["skipped"])
        self.assertIn("abuseipdb", r["sources"]["skipped"])
        self.assertNotIn("greynoise", r["sources"]["skipped"])  # keyless allowed


class TestURLAndHash(unittest.TestCase):
    def test_vt_url_id_and_urlhaus(self):
        url = "http://bad.example.net/payload.exe"
        http = fake_http([
            ("urlhaus-api", {"query_status": "ok", "url_status": "online",
                             "threat": "malware_download", "tags": ["exe"],
                             "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/"}),
            ("virustotal", {"data": {"attributes": {"last_analysis_stats":
                {"malicious": 5, "harmless": 1}}}}),
        ])
        with mock.patch.object(ie, "HTTP", http), mock.patch.dict(os.environ, ENV):
            r = ie.enrich(url)
        uid = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        self.assertTrue(any(uid in c[0] for c in http.calls))
        self.assertEqual(r["verdict"], "malicious")
        uh = next(f for f in r["findings"] if f["provider"] == "urlhaus")
        self.assertEqual(uh["score"], 100)

    def test_hash_malwarebazaar(self):
        h = "a" * 64
        http = fake_http([
            ("mb-api", {"query_status": "ok", "data": [{
                "sha256_hash": h, "signature": "AgentTesla", "tags": ["stealer"],
                "file_type": "exe"}]}),
            ("urlhaus-api", {"query_status": "no_results"}),
        ])
        with mock.patch.object(ie, "HTTP", http), mock.patch.dict(os.environ, ENV):
            r = ie.enrich(h)
        self.assertEqual(r["verdict"], "malicious")
        self.assertIn("AgentTesla", r["tags"])
        mb_call = next(c for c in http.calls if "mb-api" in c[0])
        self.assertEqual(mb_call[1]["form"]["query"], "get_info")


class TestCVE(unittest.TestCase):
    def setUp(self):
        ie.CisaKEV._cache = None

    def run_cve(self, cve, kev_list, cvss=9.8, epss="0.94"):
        nvd = {"vulnerabilities": [{"cve": {
            "published": "2024-04-12", "descriptions": [{"lang": "en", "value": "desc"}],
            "weaknesses": [{"description": [{"value": "CWE-77"}]}],
            "metrics": {"cvssMetricV31": [{"cvssData": {
                "baseScore": cvss, "baseSeverity": "CRITICAL", "vectorString": "AV:N"}}]}}}]}
        http = fake_http([
            ("known_exploited", {"vulnerabilities": kev_list}),
            ("services.nvd.nist.gov", nvd),
            ("api.first.org", {"data": [{"epss": epss, "percentile": "0.999",
                                         "date": "2026-10-22"}]}),
        ])
        with mock.patch.object(ie, "HTTP", http):
            return ie.enrich(cve), http

    def test_kev_p1(self):
        r, _ = self.run_cve("CVE-2024-3400", [{
            "cveID": "CVE-2024-3400", "vendorProject": "Palo Alto Networks",
            "product": "PAN-OS", "dateAdded": "2024-04-12", "dueDate": "2024-04-19",
            "knownRansomwareCampaignUse": "Unknown"}])
        self.assertEqual(r["verdict"], "exploited")
        self.assertEqual(r["priority"], "P1")
        self.assertIn("IN CISA KEV", r["summary"])

    def test_not_in_kev_scored(self):
        r, _ = self.run_cve("CVE-2099-0001", [], cvss=7.5, epss="0.01")
        self.assertEqual(r["verdict"], "not_known_exploited")
        self.assertEqual(r["priority"], "P3")

    def test_kev_failure_is_undetermined_not_p4(self):
        http = fake_http([("known_exploited", ie.HTTPError(503)),
                          ("api.first.org", {"data": []})])
        with mock.patch.object(ie, "HTTP", http):
            r = ie.enrich("CVE-2024-3400")
        self.assertEqual(r["verdict"], "undetermined")
        self.assertIsNone(r["priority"])

    def test_kev_downloaded_once(self):
        ie.CisaKEV._cache = None
        http = fake_http([("known_exploited", {"vulnerabilities": []}),
                          ("nvd", {"vulnerabilities": []}), ("first.org", {"data": []})])
        with mock.patch.object(ie, "HTTP", http):
            ie.enrich("CVE-2099-0001")
            ie.enrich("CVE-2099-0002")
        self.assertEqual(sum("known_exploited" in c[0] for c in http.calls), 1)


class TestCLI(unittest.TestCase):
    def test_exit_code_and_file_input(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("# comment\n10.0.0.1\n10.0.0.1  # dup\nnot-an-ioc\n")
            path = fh.name
        with mock.patch.object(ie, "HTTP", fake_http([])):
            rc = ie.main(["-f", path, "--format", "summary"])
        self.assertEqual(rc, 0)
        os.unlink(path)


if __name__ == "__main__":
    unittest.main()
