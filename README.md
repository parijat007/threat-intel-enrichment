# ioc-enrich

Multi-source IOC enrichment that returns one normalized JSON verdict per indicator. It is built to feed a SOAR playbook or a local LLM as a tool call.

- **Inputs:** IPv4/IPv6, domains, URLs, MD5/SHA1/SHA256, CVE IDs. Defanged input (`hxxp`, `[.]`) is refanged automatically.
- **Lookup only:** nothing is ever uploaded or submitted for scanning.
- **Internal IPs stay internal:** RFC1918, loopback, link-local and reserved addresses are never sent to any provider.
- **Fail-safe verdicts:** if no source answers, or the CISA KEV lookup fails, the verdict is `undetermined`. It is never reported as clean or low priority.
- **No dependencies:** Python 3.9+ standard library only.

## Providers

| Provider | Types | Key (env var) | Signup |
|---|---|---|---|
| VirusTotal v3 | IP, domain, URL, hash | `VT_API_KEY` (required) | virustotal.com |
| AbuseIPDB | IP | `ABUSEIPDB_API_KEY` (required) | abuseipdb.com |
| GreyNoise Community | IPv4 | `GREYNOISE_API_KEY` (optional) | greynoise.io |
| AlienVault OTX | IP, domain, URL, hash | `OTX_API_KEY` (optional) | otx.alienvault.com |
| URLhaus (abuse.ch) | domain, IPv4, URL, MD5/SHA256 | `ABUSECH_AUTH_KEY` (required) | auth.abuse.ch |
| MalwareBazaar (abuse.ch) | hash | `ABUSECH_AUTH_KEY` (same key) | auth.abuse.ch |
| CISA KEV | CVE | none | — |
| NVD 2.0 | CVE | `NVD_API_KEY` (optional, raises rate limit) | nvd.nist.gov |
| FIRST EPSS | CVE | none | — |

Providers without a required key are skipped and listed under `sources.skipped`. Run `python3 ioc_enrich.py --list-providers` to see what is active.

## Usage

```bash
export VT_API_KEY=... ABUSEIPDB_API_KEY=... ABUSECH_AUTH_KEY=... OTX_API_KEY=...

python3 ioc_enrich.py 185.220.101.1 hxxps://bad[.]example/x CVE-2024-3400
python3 ioc_enrich.py -f iocs.txt --format jsonl          # one JSON per line
python3 ioc_enrich.py -f iocs.txt --format summary        # one line per IOC
python3 ioc_enrich.py 1.2.3.4 --no-findings               # compact, for LLM context
python3 ioc_enrich.py 1.2.3.4 --providers greynoise,otx   # restrict sources
```

The exit code is `2` if any indicator is `malicious` or `exploited`, otherwise `0`. Use it to gate pipeline steps.

## Output

```json
{
  "indicator": "185.220.101.1",
  "type": "ipv4",
  "verdict": "malicious",          // malicious | suspicious | benign | unknown | undetermined | internal
  "confidence": "high",            // agreeing sources: 3+ high, 2 medium, else low
  "malicious_sources": ["virustotal", "abuseipdb", "greynoise", "otx"],
  "tags": ["tor", "scanner", "..."],
  "summary": "ipv4 185.220.101.1: MALICIOUS (4 malicious, 0 suspicious, 0 benign of 4 sources answering); tags: ...",
  "findings": [ { "provider": "otx", "signal": "malicious",
                  "details": { "pulse_count": 40, "attack_techniques": ["T1090"] },
                  "reference": "https://otx.alienvault.com/..." } ],
  "sources": { "answered": 4, "skipped": [], "errors": {} }
}
```

For CVEs, the output adds `priority`:

| Priority | Condition |
|---|---|
| P1 | Listed in CISA KEV |
| P2 | EPSS ≥ 10% or CVSS ≥ 9.0 |
| P3 | CVSS ≥ 7.0 |
| P4 | Everything else |

### Verdict thresholds

These live in each provider's `lookup()` and in `aggregate()`. Tune them to your environment.

| Source | Malicious | Suspicious | Benign |
|---|---|---|---|
| VirusTotal | ≥3 engines | 1–2 engines, or ≥2 suspicious | harmless votes, 0 malicious |
| AbuseIPDB | confidence ≥75 | confidence ≥25 | whitelisted |
| GreyNoise | classified malicious | — | classified benign, or RIOT (known business service) |
| OTX | ≥5 pulses | 1–4 pulses | whitelisted |
| URLhaus / MalwareBazaar | listed | host listed, no online URLs | — |

**Aggregate verdict:**
- **Malicious:** 2+ malicious sources, or 1 malicious source and no benign ones.
- **Suspicious:** any other malicious or suspicious signal. A malicious hit that conflicts with a benign one lands here.

## Using it with a local LLM

Expose the script as a single tool, e.g. `enrich_ioc(indicators: list[str]) -> json`, that runs it with `--no-findings --format jsonl`. Have the model reason from `summary`, `verdict`, `confidence` and `tags`. Tell it to treat `undetermined` as "needs analyst review", not as clean.

Example Ollama or OpenAI-compatible tool schema:

```json
{"type": "function", "function": {
  "name": "enrich_ioc",
  "description": "Look up reputation for IPs, domains, URLs, file hashes and CVEs. Lookup only.",
  "parameters": {"type": "object", "properties": {
    "indicators": {"type": "array", "items": {"type": "string"}}}, "required": ["indicators"]}}}
```

Or import it directly in Python:

```python
import ioc_enrich
result = ioc_enrich.enrich("8.8.8.8")
```

## Operational notes

- **Rate limits:** free tiers are tight (VirusTotal public API is 4 requests/min and 500/day). For bulk work, add caching and backoff, or use enterprise keys.
- **Terms of service:** several free tiers prohibit commercial or production use. Confirm licensing before using this in a corporate pipeline.
- **Data exposure:** lookups disclose the indicator to the provider. Do not query values that are themselves sensitive, such as internal hostnames or unreleased sample hashes.
- **Adding a provider:** subclass `Provider`, set `name`, `types` and `key_env`, implement `lookup()` to return a `Finding`, and append it to `PROVIDERS`.

## Tests

```bash
python3 -m unittest test_ioc_enrich.py -v   # offline; all HTTP is mocked
```
