# The evidence model

This document explains every number in `origintrace/evidence.py`. If you change a
weight, change this file in the same commit — the tests only enforce internal
consistency, not agreement with this reasoning.

## The problem being solved

Given a domain and a pile of candidate IPs, decide:

1. Does this IP serve the site?
2. Is it the *origin*, or the CDN in front of it, or an unrelated server?

Doing this with a checklist produces false positives. Doing it with a single
signal produces either false positives (content match on a CDN) or false
negatives (a certificate is unavailable). Doing it with weighted, independent
evidence and a visible threshold is the compromise this tool takes.

## Why saturation instead of addition

Naive addition has two failure modes:

* A candidate with six mediocre signals outscores one with a decisive
  certificate, even though the certificate is the stronger claim.
* Two signals for the same underlying fact (a certificate *and* the SAN list it
  contains) double-count.

Saturation fixes both:

```
combined = 1 - Π (1 - wᵢ)
```

| Signals | Sum | Saturated |
|---|---|---|
| 0.5 + 0.5 | 1.00 | 0.75 |
| 0.5 × 3 | 1.50 | 0.875 |
| 0.92 | 0.92 | 0.92 |
| 0.92 + 0.5 | 1.42 | 0.96 |

The result is monotonic, bounded, and the same regardless of order — all three
properties are asserted in `tests/test_evidence.py`.

## The weights

### Identity (hard to fake)

| Kind | Weight | Reasoning |
|---|---|---|
| `TLS_EXACT_SAN` | 0.92 | A public CA issued a certificate for exactly this name to whoever controls this IP. This is the closest thing to proof the tool has. |
| `TLS_SAN_MATCH` | 0.80 | A SAN entry names the domain but not as the primary CN — slightly weaker, still authoritative. |
| `TLS_WILDCARD_SAN` | 0.55 | `*.example.com` covers the name, but the certificate could have been issued to a sibling host. It proves control of the zone, not of this specific host. |
| `TLS_JARM_MATCH` | 0.45 | TLS stack fingerprint identical to the baseline: same negotiated version, cipher and ALPN. Independent of both DNS and certificates, so it corroborates a certificate match rather than duplicating it. |
| `TLS_CERT_REUSED` | 0.45 | The same certificate bytes as the baseline, for a name that does *not* match. Suggests a shared deploy, which is weaker than a name match. |

Threshold rationale: `TLS_EXACT_SAN` alone clears 0.60, intentionally. A
certificate naming the domain cannot plausibly have been issued to an unrelated
host, and requiring a second signal would hide real origins behind a TLS-less
port 80 only server.

### Behaviour (strong but imitable)

| Kind | Weight | Reasoning |
|---|---|---|
| `VHOST_IDENTICAL` | 0.75 | The IP returns the same page when asked for the target's hostname. Close to a definition of "serves this site", but a mirror or a parked copy behaves identically. |
| `FAVICON_MATCH` | 0.58 | Survives CDNs and content edits, and is expensive to match by accident. Not decisive alone: CDN-hosted favicons come from the origin, so this can be true of an edge node too — which is why edge nodes are excluded before scoring. |
| `CONTENT_SIMILAR` | 0.50 | Similar but not identical: usually a staging copy or a partially-updated deploy. |
| `HEADER_FINGERPRINT_MATCH` | 0.40 | Same header *shape* after volatile values (dates, request ids, cache state) are stripped. Stack-level, not content-level. |
| `TITLE_MATCH` | 0.35 | `<title>` equality. Cheap, and copies are common. |
| `REDIRECT_CHAIN_MATCH` | 0.35 | Same redirect targets — the app's routing, visible from outside. |
| `ETAG_MATCH` | 0.30 | Same entity tag for a static asset: suggests the same build, but ETags are per-path and sometimes recycled. |

### Provenance (hints, not proof)

| Kind | Weight | Reasoning |
|---|---|---|
| `CERT_TRANSPARENCY` | 0.30 | A certificate was once issued to a hostname resolving here. Strong historically, weak now — the host may have moved. |
| `PASSIVE_DNS_HISTORY` | 0.28 | Same reasoning, different feed. |
| `SPF_OR_MX_LEAK` | 0.22 | Mail servers bypass CDNs, so their IPs are often the same network as the origin. Often a *sibling*, not the web server itself. |
| `SUBDOMAIN_UNIQUE_IP` | 0.20 | The IP serves exactly one name in the discovered set — the inverse of shared hosting. Weak but cheap. |
| `OPERATOR_SUPPLIED` | 0.10 | A human typed it in. Useful for `--explain`, worth almost nothing for scoring, and included so the report can show it. |

No single provenance signal clears 0.60. That is deliberate: "this IP appeared in
a passive DNS feed" is not an origin claim.

### Annotation (zero pull)

`HOSTED_ON_CDN`, `BEHIND_WAF`, `DEFAULT_PAGE` carry weight `0.0`. They classify a
candidate and appear in the report, but must not move the score — otherwise a CDN
would look *more* like an origin for being a CDN.

### Disqualifiers (subtracted)

| Kind | Weight | Reasoning |
|---|---|---|
| `UNREACHABLE` | 0.90 | Nothing answered. |
| `CATCH_ALL_VHOST` | 0.85 | The server serves the same content for a canary hostname that cannot resolve. Any content similarity is therefore meaningless. |
| `GENERIC_PARKING_PAGE` | 0.80 | A registrar parking page. |
| `CHALLENGE_PAGE` | 0.70 | A WAF interstitial — we never reached the site. |
| `SHARED_HOSTING` | 0.25 | Real host, but other tenants share it, so a bypass is partial. |

The penalty is capped at the combined positive score, so a candidate with no
supporting evidence floors at `0.0` rather than going negative.

## Thresholds

| Constant | Value | Meaning |
|---|---|---|
| `ORIGIN_THRESHOLD` | 0.60 | Below this, no origin claim is made. |
| `REJECT_THRESHOLD` | 0.18 | Below this the candidate is dropped from the report entirely. |
| `SAME_SITE_THRESHOLD` | 0.78 | Content similarity that counts as "the same site". |
| `DIFFERENT_THRESHOLD` | 0.45 | Below this, clearly a different page. |

`0.60` was chosen so that `TLS_EXACT_SAN` (0.92) alone qualifies,
`VHOST_IDENTICAL` + `TITLE_MATCH` (0.837) qualifies, and the strongest provenance
pair (`CT` + `MX`, ≈ 0.45) does not.

## Similarity metric

`difflib.SequenceMatcher.ratio()` alone scores two short, genuinely different
pages at 0.74 purely because they share HTML scaffolding. The metric is therefore
a blend:

```
similarity = 0.5 * sequence_ratio + 0.5 * jaccard(tokens)
```

Both operate on a body that has been normalised first: whitespace collapsed,
lower-cased, long hex strings and timestamps replaced with a space. Without that
normalisation, two requests to the same server score low because the page
contains a nonce.

## Known limits

* **Wildcard DNS.** A target resolving everything to one IP produces dozens of
  identical candidates; `--max` caps the work but cannot tell which is real.
* **Origin behind mTLS or an IP allowlist.** Unreachable from outside, so no
  evidence can be gathered. The tool reports `UNCERTAIN`, which is honest.
* **Shared origin.** Several sites on one origin IP: the certificate may name a
  sibling, producing `TLS_WILDCARD_SAN` rather than an exact match.
* **No JARM yet.** JARM requires sending ten crafted ``ClientHello`` records
  byte-for-byte, which needs a hand-written TLS record layer. What ships instead
  is :mod:`origintrace.tlsfp`, which fingerprints the *negotiated* parameters
  (version, cipher, ALPN, legacy-protocol support). That is independent of DNS
  and certificates and costs one handshake, but two different stacks can
  negotiate the same suite — so it corroborates, it does not conclude. Implementing
  full JARM is the highest-value next step.
