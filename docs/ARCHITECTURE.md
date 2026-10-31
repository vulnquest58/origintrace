# Architecture

Five stages, one direction of data flow. Each stage is independently testable and
the pipeline holds no hidden state.

```
                 ScanContext
                      │
   ┌──────────────────┼──────────────────┐
   │                  │                  │
baseline ──> discovery ──> classification ──> validation ──> scoring
   │                  │                  │
   └─ probe.baseline  └─ discover.*      └─ intel.*
                                          └─ validate.*
```

## Stage 1 — baseline

`pipeline._baseline()` fetches the public page and stores:

| Field | Used by | Why |
|---|---|---|
| `baseline_title` | validation | title equality is a cheap corroboration |
| `baseline_body_hash` | validation | detects "identical" without keeping the body twice |
| `_baseline_body` (attribute) | validation | similarity needs the text |
| `baseline_favicon` | validation | favicon hash is the most portable signal |
| `stats["baseline_hfp"]` | validation | header shape, volatile values stripped |

A failed baseline is **not** fatal. It becomes a warning and the run continues
with weaker signals; reporting nothing would hide a real origin behind a flaky
TLS handshake.

> The raw body lives in an attribute rather than `stats` on purpose: `stats` is
> serialised into the JSON report, and dumping a 250 KB page into it would make
> every report useless.

## Stage 2 — discovery (passive only)

No packets are sent to the target here. Sources are plain callables returning
`(ip, detail)` pairs:

| Source | What it asks | Failure behaviour |
|---|---|---|
| `dns` | current A records | empty list |
| `mx` | mail exchangers, which usually bypass the CDN | empty list |
| `ct` | crt.sh for hostnames under the target | empty list |
| `internetdb` | Shodan InternetDB for *sibling* hostnames on the same IPs | empty list |

Sources fail independently. One dead API adds a warning and the scan continues;
that is tested explicitly (`test_pipeline.py`).

`httpx.Client(trust_env=False)` is mandatory here — an operator behind a
corporate proxy would otherwise receive the proxy's answer for every host and
report the proxy's IP as an origin.

## Stage 3 — classification

`intel.cdn_owner()` against 3,131 CIDR ranges. The result is stamped on the
candidate and **edge nodes are never probed**: a CDN answers for thousands of
sites, so a content match there is meaningless and the request is wasted. This is
the single biggest runtime saving on a CDN-protected target.

WAF and hosting lookup happen here too, so the classifier can distinguish an
exposed origin from a protected one later.

## Stage 4 — validation

Per candidate, in descending order of signal strength:

1. **Certificate identity** — `probe.certificate()` reads the SAN list. TLS
   verification is off (`CERT_NONE`) because origin servers commonly present
   expired or self-signed certificates; the *contents* are still authoritative
   about which names the server serves. This is documented at the call site, not
   hidden.
2. **Vhost behaviour** — `probe.probe_vhost()` connects to the IP while sending
   `Host: target` and SNI for the target. Three outcomes:
   * challenge page → `CHALLENGE_PAGE`, stop (we never reached the site)
   * catch-all → `CATCH_ALL_VHOST`, stop (similarity is meaningless)
   * otherwise → similarity, title and header comparisons
3. **Catch-all canary** — ask the same IP for `origintrace-canary.invalid`. If it
   answers with the same content, the server serves everything.
4. **Favicon** — one extra request, skipped when the candidate is already
   disqualified.

### Why the catch-all check exists

This is the most common false positive in origin tooling. A shared host or a
misconfigured nginx default server returns the same page for *every* Host
header. Without the canary, such a server scores `VHOST_IDENTICAL` for any domain
you point at it.

## Stage 5 — scoring

`evidence.score_all()` sorts descending. The model is described in
[`EVIDENCE-MODEL.md`](EVIDENCE-MODEL.md).

## Rule engine (optional)

Two separate risk profiles, deliberately separated:

* **`detection`** inspects the baseline response — headers, cookies, body
  markers. Read-only, always safe, evaluates when `--rules` is passed.
* **`probes`** sends the rule's paths. Some are attack-shaped (an SSRF parameter,
  an auth-bypass header). Off unless `--probe-rules` is passed, because firing
  them blindly gets researchers banned.

A probe hit is only `confirmed` when the status matched **and** a soft-404 guard
saw different content for a random path — otherwise every SPA router's `200 OK`
becomes a finding.

## Error handling philosophy

| Situation | Behaviour | Rationale |
|---|---|---|
| Baseline fails | warn, continue | weaker signals still work |
| One discovery source fails | warn, continue | sources are independent |
| TLS handshake fails | emit nothing for that kind | absence of a certificate is normal |
| Candidate unreachable | `UNREACHABLE` evidence → `REJECTED` | recorded, not silently dropped |
| Malformed rule file | skip that rule, log | one bad YAML must not stop the scan |
| Dataset missing/malformed | log, feature degrades | offline use must not crash |

Nothing is swallowed silently: every degraded path produces either a warning on
the context (visible in the report) or a named evidence kind.

## Testing strategy

All 53 tests run offline. The network layer is replaced at the module boundary:

```python
monkeypatch.setattr(pipeline.probe, "baseline", lambda *a, **k: fake_response)
monkeypatch.setattr(pipeline.discovery, "discover", lambda *a, **k: {"203.0.113.9": [...]})
```

This means CI proves the *decision logic* rather than internet reachability. The
scoring weights are pinned by tests, so an accidental change to the model fails
the build.

## Extension points

| Want to add | Where | Contract |
|---|---|---|
| A discovery source | `discover.py` | return `(ip, detail)` pairs; empty on failure |
| A new signal | `models.EvidenceKind` + `evidence.WEIGHTS` + a module that emits it | add to `EVIDENCE-MODEL.md` too |
| A detection rule | `rules/<category>/*.yaml` | `name`, `detection`, optional `probes` |
| A report format | `report.py` | return `str` from a `ScanContext` |
