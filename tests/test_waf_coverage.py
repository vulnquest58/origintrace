"""WAF and CDN coverage across vendors, not just Cloudflare.

The dataset originally matched header *names* only, so vendors that announce
themselves in the value of ``server`` or ``via`` were invisible. These cases pin
the fix: each vendor's public header shape must be recognised.
"""

from __future__ import annotations

import pytest

from origintrace import intel

#: ``(vendor, headers)`` — header shapes taken from vendor documentation and
#: public writeups. A regression here means a real target would be missed.
WAF_CASES = [
    ("cloudflare", {"cf-ray": "8a1b2c3d", "server": "cloudflare"}),
    ("akamai_kona", {"server": "AkamaiGHost"}),
    ("imperva_incapsula", {"x-iinfo": "9-12345-12346", "x-cdn": "Incapsula"}),
    ("f5_bigip", {"server": "BIG-IP", "x-wa-info": "4"}),
    ("aws_waf", {"x-amzn-waf-action": "block"}),
    ("sucuri", {"server": "Sucuri/Cloudproxy"}),
    ("fastly", {"x-fastly-request-id": "abc"}),
    ("azure_waf", {"x-azure-ref": "abc"}),
    ("barracuda", {"server": "Barracuda"}),
    ("fortinet_fortiweb", {"server": "FortiWeb"}),
    ("citrix_netscaler", {"server": "NetScaler"}),
    ("wallarm", {"x-wallarm-waf-check": "1"}),
    ("mod_security", {"x-mod-security": "1"}),
    ("wordfence", {"x-wf-block": "1"}),
    ("radware_appwall", {"server": "radware"}),
    ("stackpath", {"server": "StackPath"}),
    ("reblaze", {"server": "Reblaze"}),
    ("keycdn", {"server": "keycdn"}),
    ("bunnycdn_waf", {"server": "BunnyCDN"}),
    ("zscaler", {"server": "Zscaler"}),
]


@pytest.mark.parametrize("vendor,headers", WAF_CASES)
def test_waf_vendor_is_detected(vendor, headers):
    detected = intel.detect_waf(headers)
    assert detected == vendor, f"{vendor} not recognised (got {detected!r})"


@pytest.mark.parametrize("vendor,ip", [
    ("Akamai", "23.32.0.1"),
    ("Fastly", "151.101.1.1"),
    ("CloudFront", "13.32.0.1"),
    ("Imperva", "45.60.0.1"),
    ("Vercel", "76.76.21.1"),
    ("Cloudflare", "104.16.1.1"),
])
def test_cdn_range_is_classified(vendor, ip):
    assert intel.cdn_owner(ip) == vendor


def test_body_marker_detects_a_waf_without_headers():
    """Some WAFs strip their own headers from the block page."""
    detected = intel.detect_waf({}, body="Access Denied - Sucuri Website Firewall")
    assert detected == "sucuri"


def test_cookie_marker_detects_a_waf():
    detected = intel.detect_waf({"server": "nginx"},
                                cookies=["__cf_bm=abc"])
    assert detected == "cloudflare"


def test_overlay_does_not_break_the_porting_provenance():
    """The original dataset file must stay untouched by the overlay."""
    base = intel.WAF_SIG_FILE.read_text(encoding="utf-8")
    # Fastly is added by the overlay only; the ported file must not contain it.
    assert '"fastly"' not in base.lower()


def test_unknown_headers_are_not_claimed_as_a_waf():
    assert intel.detect_waf({"server": "nginx/1.24.0",
                             "x-powered-by": "PHP/8.2"}) is None
