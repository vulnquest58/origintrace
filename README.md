# origintrace

**Find the server behind a CDN â€” and know why you believe it.**

Most origin-discovery tools hand you forty IP addresses and leave the hard part
to you. origintrace is built around the opposite idea: every claim about an IP
has to be backed by named, weighted evidence, and the tool shows its work.

```bash
origintrace example.com
```

```
  target    example.com
  baseline  200 Â· Example Domain
  found     2 address(es), 2 behind a CDN

  ORIGIN  not identified
          candidates found but none matched strongly enough to call an origin

  candidates
    172.66.147.243   CDN            0   cdn:Cloudflare Â· hosted_on_cdn
    104.20.23.154    CDN            0   cdn:Cloudflare Â· hosted_on_cdn
```

That is a correct answer, not a failure. `example.com` sits behind Cloudflare and
does not leak an origin. A tool that printed an IP here would be guessing.

---

## Why another origin tool

The existing options stop at *discovery* and never answer *"is this really the
site?"*, which is where false positives come from. Three specific failure modes
are handled here:

| Failure mode | What most tools do | What origintrace does |
|---|---|---|
| **Catch-all vhost** â€” a server answering *any* hostname with the real page | Reports it as the origin | Probes a canary hostname; a match disqualifies the candidate |
| **CDN edge node** â€” the proxy itself matching on content | Reports the CDN IP | Classifies against 3,131 CIDR ranges first and never probes an edge |
| **Parked / mirror page** â€” looks similar, is not the site | Scores it as a match | Blended sequence + token similarity, with a threshold tuned on real pages |

## Install

```bash
pip install .            # from a checkout
pip install -e ".[dev]"  # development
```

Requires Python 3.9+. Datasets and the YAML rule library ship **inside** the
package, so an installed copy works offline and needs no API keys.

Verify an install:

```bash
origintrace --datasets     # 3131 CDN networks / 45 WAF signatures / 66 ASNs
origintrace --list-rules   # 25 rules loaded
```

## Usage

```bash
# basic
origintrace example.com

# every technique at once, streaming results as each source finishes
origintrace example.com --all --progress

# advanced passive sources only (SPF, robots, CSP, wayback, reverse-IP, ...)
origintrace example.com --extended

# machine-readable, for pipelines
origintrace example.com --json

# save both JSON and Markdown
origintrace example.com --save ./reports

# explain one decision from a run
origintrace example.com --explain 203.0.113.9

# identify the stack from the bundled rule library
origintrace example.com --rules
```

### Options

| Flag | Meaning |
|---|---|
| `-d, --domain NAME` | target domain when the positional argument is an IP |
| `--all` | enable every technique (`--extended` + `--hints` + TLS fingerprint) |
| `--extended` | advanced passive sources (see below) |
| `--progress` | stream each source's result to stderr as it completes |
| `--json` / `--markdown` | output format |
| `--save DIR` | write both artefacts |
| `-v, --verbose` | list every candidate, not just the top few |
| `--sub NAME` | extra subdomain hint (repeatable) |
| `--hints` | also try the built-in hint wordlist |
| `--no-tls` | skip certificate identity checks |
| `--no-tlsfp` | skip TLS stack fingerprint comparison |
| `--jarm` | run the active JARM-style TLS fingerprint (ten `ClientHello`s per host) |
| `--no-favicon` | skip favicon comparison |
| `--timeout N` | per-request timeout (default 8s) |
| `--max N` | cap candidates to validate (default 40) |
| `--rules` | detect the stack using the rule library |
| `--probe-rules` | **send** the rules' probe paths (see below) |
| `--datasets` | print dataset counts |
| `--list-rules` | print the rule library |
| `--version` | print the version and exit |

## Techniques

Nineteen independent methods, each producing named evidence.

### Passive discovery (no traffic to the target)

| Source | What it leaks | Flag |
|---|---|---|
| DNS A records | the reference point | always |
| MX records | mail servers, which rarely sit behind a CDN | always |
| Certificate Transparency (crt.sh) | hostnames issued certificates | always |
| Shodan InternetDB | sibling hostnames on the same address | always |
| Subdomain hints | `direct`, `origin`, `staging`, `internal`, â€¦ | `--hints` |
| **SPF record** | `ip4:`/`a:`/`include:` entries name mail infrastructure | `--extended` |
| **DMARC record** | `rua=`/`ruf=` reporting hosts | `--extended` |
| **TXT verification** | hosts that claimed the domain | `--extended` |
| **robots.txt** | admin and staging hosts listed by name | `--extended` |
| **sitemap.xml** | hosts the marketing site never links to | `--extended` |
| **Content-Security-Policy** | every origin the page is allowed to talk to | `--extended` |
| **Generic header scan** | any header embedding a hostname under the domain | `--extended` |
| **Certificate SAN expansion** | siblings on the site's own certificate | `--extended` |
| **Reverse-IP** | other hostnames on the same address | `--extended` |
| **Wayback Machine** | hostnames from before the CDN existed | `--extended` |

### Active validation (one `GET /` per candidate)

| Check | Question it answers |
|---|---|
| Certificate SAN | Does this IP hold a certificate naming the domain? |
| Vhost behaviour | Does it serve the site when asked for this `Host`? |
| **Catch-all canary** | Does it serve *anything* for any hostname? (disqualifies) |
| Content similarity | Is the page the same, after stripping nonces? |
| Favicon hash | Same icon? Survives CDNs and content edits. |
| Header fingerprint | Same stack, after removing volatile headers? |
| Title match | Same `<title>`? |
| **TLS stack fingerprint** | Same negotiated version/cipher/ALPN? Independent of DNS and certificates. |
| **JARM-style fingerprint** | Same answer to ten deliberately unusual `ClientHello`s? (`--jarm`) |
| Challenge detection | Is a WAF interstitial refusing us? (disqualifies) |

### Safety guard

Non-routable addresses â€” private, loopback, link-local, multicast, reserved and
documentation ranges â€” are **dropped at discovery time**. A leaked internal
hostname (an MX pointing at `10.32.10.95`) must never cause a probe of the
operator's own network. This is tested explicitly.

## TLS fingerprinting: two layers, one honest limit

| Layer | Cost | What it sees | Module |
|---|---|---|---|
| **Stack fingerprint** | 1 handshake | negotiated version, cipher, ALPN, legacy-protocol support | `tlsfp.py` |
| **JARM-style** | ~20 connections | the server's answer to ten *deliberately unusual* `ClientHello`s | `jarm.py` |

The second layer exists because the first cannot separate stacks that agree on
TLS 1.3 + AES-256-GCM. Varying the cipher order, the extension set and the ALPN
list makes the server reveal its preferences, which differ between vendors and
between an edge and the origin behind it.

**Limitation, stated plainly:** this is *JARM-style*, not byte-compatible with
Salesforce JARM. The probe table follows the published ten probes and the output
is a 62-character fingerprint (30 hex + `.` + 32 hex), but the exact packet bytes
are built here rather than replayed from the reference implementation. Two
consequences:

* fingerprints from this tool **discriminate** stacks correctly (verified against
  live hosts: `iana.org`, `badssl.com` and Cloudflare-fronted sites all differ);
* they are **not comparable** with values in public JARM databases.

Byte-compatibility needs the ten reference packets replayed verbatim. That is a
well-scoped follow-up, and until it lands the weight (`TLS_JARM_MATCH`, 0.45)
reflects a corroborating signal rather than proof.

Measured on live hosts during development:

```
iana.org          ca5af2537d91b0fe928518750e5d74.e3b0c44298fc1c149afbf4c8996fb924
badssl.com        701ddd16c7048ce02e4ae52ef32004.7d0228bedcaf78899179f2cb20b900cb
cloudflare-fronted 3ceab2c84328909c80395d2c67ed21.4f349fb90db45cb71fc292fd804d3488
```

Two things broke while building it, and both are now covered by tests:

* a TLS 1.3 probe without `key_share` is rejected with `alert 109`
  (`missing_extension`) and measures nothing;
* reading fixed byte offsets out of the `ServerHello` returned `0000` for every
  server, which made every fingerprint identical. The parser now walks the
  extension block and reads the real version from `supported_versions`.

## The evidence model in one page

Each observation is an `Evidence` with a **kind**, a **weight** and a
**confidence**. Weights are declared once in `origintrace/evidence.py`; modules
never do arithmetic.

Signals are grouped by how hard they are to fake:

| Group | Examples | Max weight |
|---|---|---|
| **Identity** | certificate SAN names the domain, TLS stack match | 0.92 |
| **Behaviour** | vhost returns the same page, same favicon | 0.75 |
| **Provenance** | certificate transparency, MX leak | 0.30 |

They combine with saturation, not addition:

```
score = 1 - Î (1 - wáµ¢)
```

Three 0.5 signals give `0.875`, not `1.5`. This is why ten weak hints can never
outvote one certificate, and why a single strong signal cannot be inflated past
1.0 by noise.

**Negative evidence is subtractive and named.** A catch-all vhost is not "the
absence of proof" â€” it is disproof, worth 0.85, and the report says so.

### Verdict classes

| Class | Meaning |
|---|---|
| `EXPOSED_ORIGIN` | Serves the site and is not a CDN |
| `PROTECTED_ORIGIN` | Serves the site but still behind a WAF |
| `SHADOW_ORIGIN` | Serves the site but is shared hosting (score < 0.80) |
| `EDGE_NODE` | A CDN address â€” the thing you are trying to bypass |
| `HOSTING_ORIGIN` | Confirmed hosting provider |
| `UNCERTAIN` | Some evidence, below the 0.60 threshold |
| `REJECTED` | Disqualified (unreachable, catch-all, default page) |

Full reasoning, including why each weight has its value, is in
[`docs/EVIDENCE-MODEL.md`](docs/EVIDENCE-MODEL.md).

## How a scan runs

```
baseline  ->  discovery  ->  classification  ->  validation  ->  scoring
```

1. **Baseline** â€” fetch the public page. Everything later is compared to it.
2. **Discovery** â€” passive only: DNS, MX, certificate transparency, Shodan
   InternetDB. No packets to the target yet.
3. **Classification** â€” CDN/WAF/hosting lookup against the bundled datasets. Edge
   nodes are scored but never probed.
4. **Validation** â€” per candidate: certificate SAN, vhost behaviour, catch-all
   canary, content similarity, favicon, TLS stack.
5. **Scoring** â€” combine evidence, classify, rank.

Details and the failure handling for each stage are in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Safety and scope

- **Only plain `GET /` requests.** No exploitation, no fuzzing, no payloads.
- `--probe-rules` is the single exception and is **off by default**, because some
  bundled probe paths (an SSRF parameter, an auth-bypass header) are real attacks
  and will get you banned from a program if you fire them blindly.
- TLS verification is disabled when reading certificates. This is deliberate:
  origin servers routinely present expired or self-signed certificates and the
  SAN entries are still the strongest identity signal available. The certificate
  is read and *not trusted*; see `probe.certificate()`.
- The tool refuses nothing on its own â€” **you** are responsible for having
  authorisation. The scope reminder is printed on every run and is not
  suppressible.

## Datasets

| Dataset | Entries | Source |
|---|---|---|
| CDN CIDR ranges | 3,131 networks / 15 providers | published provider ranges |
| WAF signatures | 45 vendors | header names, header values, cookies, body markers |
| Hosting ASNs | 66 providers | shared-hosting / cloud ASNs |

Two WAF files are shipped: `waf_signatures.json` is the ported dataset and
matches header *names*; `waf_signatures_extra.json` layers header *value* rules on
top, because most vendors identify themselves in `server` or `via`. Keeping them
separate makes the provenance of every added rule obvious.

Refresh them with your own feeds; the loaders tolerate missing or malformed files
and log a warning instead of crashing.

## Rule library

25 YAML rules across frameworks, web servers, databases, DevOps tooling, mail
servers and monitoring. A rule has a `detection` block (always evaluated) and a
`probes` block (only with `--probe-rules`).

```yaml
name: nextjs
category: Framework
detection:
  body_patterns:
    - pattern: "__NEXT_DATA__"
      confidence: 95
probes:
  - path: "/__nextjs_build_id"
    method: GET
    risk: LOW
```

## Testing

```bash
pytest
```

156 tests, all offline â€” the network is faked so the suite proves decision logic,
not your internet connection. The tests pin every weight, so a silent change to
the scoring model fails the build. The non-routable-address guard has its own
parametrised cases because getting it wrong means probing the operator's own
network.

## Project layout

```
origintrace/
  models.py      data model: Candidate, Evidence, Verdict, ScanContext
  evidence.py    weights, saturation, classification
  intel.py       CDN / WAF / hosting datasets
  discover.py    passive source driver + safety guard
  sources.py     advanced passive sources (SPF, CSP, robots, wayback, ...)
  probe.py       HTTP, TLS, DNS primitives
  tlsfp.py       TLS stack fingerprinting (negotiated parameters)
  jarm.py        JARM-style active TLS fingerprint (ten crafted ClientHellos)
  validate.py    certificate identity, vhost behaviour, similarity
  rules.py       YAML detection engine
  pipeline.py    stage orchestration + live progress
  report.py      console / JSON / Markdown
  cli.py         argument parsing
  data/          shipped datasets
  rules/         25 YAML rules
tests/           156 offline tests
docs/            architecture and evidence model
```

## Licence

MIT. See [`LICENSE`](LICENSE).

Use it only against systems you are authorised to test.

