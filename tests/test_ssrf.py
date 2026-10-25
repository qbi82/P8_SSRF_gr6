"""Real HTTP/DNS tests, run unchanged against BEFORE, AFTER and network-only."""
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest
import requests

pytestmark = [pytest.mark.integration,
              pytest.mark.skipif(not os.environ.get("BASE_URL"), reason="Docker lab not selected")]
PUBLIC = "93.184.216.10"
PRIVATE = "169.254.169.10"
FLAG = "FLAG{SSRF-dosiegnieto-uslugi-wewnetrznej}"


@pytest.fixture(scope="module")
def lab():
    session = requests.Session()
    session.trust_env = False
    base = os.environ["BASE_URL"].rstrip("/")
    health = session.get(base + "/health", timeout=5).json()
    records = []
    out = Path(os.environ["EVIDENCE_DIR"]) if os.environ.get("EVIDENCE_DIR") else None

    def fetch(test_id, url, expected):
        response = session.get(base + "/fetch", params={"url": url}, timeout=18)
        record = dict(id=test_id, url=url, request=response.request.url,
                      status=response.status_code, expected=expected,
                      headers=dict(response.headers), body=response.text,
                      utc=datetime.now(timezone.utc).isoformat())
        records.append(record)
        if out:
            out.mkdir(parents=True, exist_ok=True)
            (out / (test_id + ".txt")).write_text(
                "GET " + response.request.url + "\n\nHTTP " + str(response.status_code) +
                "\n" + "\n".join(f"{k}: {v}" for k,v in response.headers.items()) +
                "\n\n" + response.text, encoding="utf-8")
        assert response.status_code == expected, record
        return response

    value = dict(session=session, base=base, health=health, fetch=fetch,
                 blocked=403 if health["mode"] == "hardened" else
                 502 if health.get("egress") else 200,
                 rebinder=os.environ.get("REBINDER_URL", "http://rebinder:8053"))
    yield value
    if out:
        (out / "results.json").write_text(json.dumps(
            dict(health=health, records=records), indent=2, ensure_ascii=False), encoding="utf-8")
        lines = ["P8 SSRF - rzeczywiste wyniki HTTP", json.dumps(health), ""]
        lines += [f"{r['id']}: HTTP {r['status']} (oczekiwano {r['expected']}) {r['url']}" for r in records]
        (out / "summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    session.close()


@pytest.mark.parametrize("test_id,url,marker", [
    ("T1", "http://internal-api/admin", FLAG),
    ("T2", "http://169.254.169.254/latest/meta-data/iam/security-credentials/demo-role", "token-fikcyjny-SSRF-lab"),
    ("T4", "http://redirect.test/to-internal", FLAG),
    ("T5a", "http://private.test/admin", FLAG),
    ("T6", "file:///etc/passwd", "root:x:0:0:"),
])
def test_attack_cases(lab, test_id, url, marker):
    expected = 200 if test_id == "T6" and lab["health"]["mode"] == "vulnerable" else lab["blocked"]
    response = lab["fetch"](test_id, url, expected)
    assert (marker in response.text) == (expected == 200)
    if expected == 403:
        assert response.json()["reason"]


def test_T3_alternative_loopback(lab):
    response = lab["fetch"]("T3", "http://127.1/", 403 if lab["health"]["mode"] == "hardened" else 502)
    assert FLAG not in response.text


def test_T5b_real_dns_rebinding(lab):
    session = lab["session"]
    session.post(lab["rebinder"] + "/reset", timeout=5).raise_for_status()
    first = lab["fetch"]("T5b-first", "http://rebind.test/", 200)
    assert "SAFE_FIXTURE" in first.text  # A second DNS lookup inside one fetch would leak internal data.
    after_first = session.get(lab["rebinder"] + "/state", timeout=5).json()
    assert after_first["answers"] == [PUBLIC], after_first
    second = lab["fetch"]("T5b", "http://rebind.test/admin", lab["blocked"])
    assert (FLAG in second.text) == (lab["blocked"] == 200)
    state = session.get(lab["rebinder"] + "/state", timeout=5).json()
    assert state["answers"] == [PUBLIC, PRIVATE], state
    if os.environ.get("EVIDENCE_DIR"):
        Path(os.environ["EVIDENCE_DIR"], "T5b-dns-history.json").write_text(
            json.dumps(state, indent=2), encoding="utf-8")


def test_T7_legal_target(lab):
    assert "SAFE_FIXTURE" in lab["fetch"]("T7", "http://cdn.test/", 200).text


def test_legal_relative_redirect(lab):
    assert "SAFE_FIXTURE" in lab["fetch"]("T7-redirect", "http://cdn.test/relative", 200).text


@pytest.mark.parametrize("case,path,expected", [
    ("L1", "/large", 413), ("L2", "/slow", 504), ("L3", "/loop", 403),
])
def test_hardened_limits(lab, case, path, expected):
    if lab["health"]["mode"] != "hardened":
        pytest.skip("Limits belong to the remediated code")
    lab["fetch"](case, "http://cdn.test" + path, expected)
