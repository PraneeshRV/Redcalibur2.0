"""Prove the proxy Sigma rules: valid Sigma, catches the attack, quiet on benign.

Same three-check contract as the AD pack, over proxy-category events.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # detections/

from evaluator import load_rule, matches  # noqa: E402

SIGMA_DIR = Path(__file__).resolve().parents[1] / "sigma"
RULE_PATHS = sorted(SIGMA_DIR.glob("*.yml"))
RULE_STEMS = [p.stem for p in RULE_PATHS]

VECTORS: dict[str, dict[str, list[dict]]] = {
    "nonbrowser_ua_trusted_sites": {
        "attack": [
            {  # python pulling a payload stage from a GitHub raw paste
                "cs-method": "GET", "cs-host": "raw.githubusercontent.com",
                "c-uri": "/u/x/payload/main/stage.ps1", "sc-status": 200,
                "UserAgent": "python-requests/2.31.0",
            },
            {  # curl fetching a Discord CDN attachment
                "cs-method": "GET", "cs-host": "cdn.discordapp.com",
                "c-uri": "/attachments/1/2/payload.lnk", "sc-status": 200,
                "UserAgent": "curl/8.5.0",
            },
        ],
        "benign": [
            {  # a browser on the same trusted site is normal
                "cs-method": "GET", "cs-host": "raw.githubusercontent.com",
                "c-uri": "/openssl/openssl/master/README.md", "sc-status": 200,
                "UserAgent": "Mozilla/5.0 (Windows NT 10.0) Chrome/128.0",
            },
            {  # python is fine on sites not in the abuse set
                "cs-method": "GET", "cs-host": "pypi.org",
                "c-uri": "/simple/", "sc-status": 200,
                "UserAgent": "python-requests/2.31.0",
            },
            {  # curl to the company mirror is normal
                "cs-method": "GET", "cs-host": "mirror.corp.internal",
                "c-uri": "/repo/rpm", "sc-status": 200,
                "UserAgent": "curl/8.5.0",
            },
        ],
    },
    "tunnel_service_domains": {
        "attack": [
            {"cs-method": "GET", "cs-host": "abc-123-xyz.ngrok-free.app",
             "c-uri": "/", "sc-status": 200, "UserAgent": "Mozilla/5.0"},
            {"cs-method": "POST", "cs-host": "q7ud-random-words.trycloudflare.com",
             "c-uri": "/task", "sc-status": 200, "UserAgent": "Go-http-client/1.1"},
        ],
        "benign": [
            {"cs-method": "GET", "cs-host": "github.com",
             "c-uri": "/", "sc-status": 200, "UserAgent": "Mozilla/5.0"},
            {"cs-method": "GET", "cs-host": "app.corp.internal",
             "c-uri": "/vpn", "sc-status": 200, "UserAgent": "Mozilla/5.0"},
        ],
    },
    "risky_download_extension": {
        "attack": [
            {"cs-method": "GET", "cs-host": "files.example-cdn.net",
             "c-uri": "/setup.iso", "sc-status": 200, "UserAgent": "Mozilla/5.0"},
            {"cs-method": "GET", "cs-host": "cdn.example.com",
             "c-uri": "/invoice.lnk", "sc-status": 200, "UserAgent": "Mozilla/5.0"},
        ],
        "benign": [
            {  # ordinary document
                "cs-method": "GET", "cs-host": "static.example.com",
                "c-uri": "/report.pdf", "sc-status": 200, "UserAgent": "Mozilla/5.0"},
            {  # risky name but the download failed: no delivery
                "cs-method": "GET", "cs-host": "cdn.example.com",
                 "c-uri": "/app.js", "sc-status": 404, "UserAgent": "Mozilla/5.0"},
            {  # uploads are out of scope for a download rule
                "cs-method": "POST", "cs-host": "upload.example.com",
                 "c-uri": "/backup.lnk", "sc-status": 200, "UserAgent": "Mozilla/5.0"},
        ],
    },
}


@pytest.mark.parametrize("path", RULE_PATHS, ids=RULE_STEMS)
def test_rule_is_valid_sigma(path):
    """The rule parses under the Sigma spec via pySigma."""
    sigma = pytest.importorskip("sigma.collection")
    collection = sigma.SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
    assert len(collection.rules) == 1
    rule = collection.rules[0]
    assert rule.title
    assert rule.detection.detections
    assert str(rule.id)


@pytest.mark.parametrize("stem", RULE_STEMS)
def test_rule_catches_attack(stem):
    rule = load_rule(SIGMA_DIR / f"{stem}.yml")
    for event in VECTORS[stem]["attack"]:
        assert matches(rule, event), f"{stem} missed attack event {event}"


@pytest.mark.parametrize("stem", RULE_STEMS)
def test_rule_quiet_on_benign(stem):
    rule = load_rule(SIGMA_DIR / f"{stem}.yml")
    for event in VECTORS[stem]["benign"]:
        assert not matches(rule, event), f"{stem} fired on benign event {event}"
