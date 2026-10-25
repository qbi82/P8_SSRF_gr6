import ssl
from unittest.mock import Mock

import pytest
import ssrf_policy as policy

HOSTS = ["cdn.test", "redirect.test", "rebind.test"]
PUBLIC = "93.184.216.10"


class Response:
    def __init__(self, body=b"SAFE_FIXTURE", status=200, headers=None):
        self.body = body
        self.status = status
        self.headers = headers or {}
        self.closed = False

    def read1(self, size, decode_content=False):
        chunk, self.body = self.body[:size], self.body[size:]
        return chunk

    def close(self):
        self.closed = True


@pytest.fixture
def public_dns(monkeypatch):
    resolver = Mock(return_value=(PUBLIC,))
    monkeypatch.setattr(policy, "resolve_addresses", resolver)
    return resolver


@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "gopher://cdn.test/", "ftp://cdn.test/",
    "http://cdn.test.evil.test/", "http://cdn.test@evil.test/",
    "http://user:pass@cdn.test/", "http://cdn.test:8080/", "http://cdn.test:0/",
    "http://cdn.test:65536/", "http://cdn.test/#fragment", "http://cdn.test/\r\nHost:evil",
    "http://cdn.test\\@evil.test/", "http:///path", "http://[::1", "",
])
def test_invalid_input_never_resolves(url, public_dns):
    with pytest.raises(policy.PolicyError):
        policy.validate_target(url, HOSTS)
    public_dns.assert_not_called()


@pytest.mark.parametrize("address", [
    "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.0.1", "169.254.169.254",
    "0.0.0.0", "100.64.0.1", "224.0.0.1", "240.0.0.1", "192.0.2.1",
    "::1", "::", "fe80::1", "fc00::1", "ff02::1", "::ffff:127.0.0.1",
    "::ffff:93.184.216.10", "2001:db8::1",
])
def test_forbidden_ip_even_for_allowlisted_host(address, monkeypatch):
    monkeypatch.setattr(policy, "resolve_addresses", lambda *_: (address,))
    with pytest.raises(policy.PolicyError, match="non_public_ip"):
        policy.validate_target("http://cdn.test/", HOSTS)


def test_rejects_mixed_public_and_private_dns_answers(monkeypatch):
    monkeypatch.setattr(policy, "resolve_addresses", lambda *_: (PUBLIC, "::1"))
    with pytest.raises(policy.PolicyError, match="non_public_ip"):
        policy.validate_target("http://cdn.test/", HOSTS)


@pytest.mark.parametrize("hostname,url_host", [
    ("127.1", "127.1"), ("0x7f000001", "0x7f000001"),
    ("2130706433", "2130706433"), ("::1", "[::1]"),
])
def test_alternative_loopback_notation_uses_actual_os_resolution(hostname, url_host):
    # Deliberately allow the spelling so this tests the resolved-IP control itself.
    with pytest.raises(policy.PolicyError, match="non_public_ip"):
        policy.validate_target("http://" + url_host + "/", [hostname])


def test_canonical_host_and_preserved_query(public_dns):
    target = policy.validate_target("https://CDN.TEST./a?q=one%20two", HOSTS)
    assert (target.hostname, target.port, target.path, target.ip) == (
        "cdn.test", 443, "/a?q=one%20two", PUBLIC)


def test_pins_first_dns_answer_instead_of_resolving_hostname_again(monkeypatch):
    dns = Mock(side_effect=[(PUBLIC,), ("169.254.169.10",)])
    monkeypatch.setattr(policy, "resolve_addresses", dns)
    pool = Mock()
    pool.urlopen.return_value = Response()
    constructor = Mock(return_value=pool)
    monkeypatch.setattr(policy.urllib3, "HTTPConnectionPool", constructor)
    assert policy.fetch_hardened("http://rebind.test/", HOSTS) == (b"SAFE_FIXTURE", 200)
    assert dns.call_count == 1
    assert constructor.call_args.kwargs["host"] == PUBLIC
    request = pool.urlopen.call_args
    assert request.kwargs["headers"]["Host"] == "rebind.test"
    assert request.kwargs["redirect"] is False
    assert request.kwargs["retries"] is False


def test_https_keeps_sni_and_certificate_verification(public_dns, monkeypatch):
    pool = Mock()
    pool.urlopen.return_value = Response()
    constructor = Mock(return_value=pool)
    monkeypatch.setattr(policy.urllib3, "HTTPSConnectionPool", constructor)
    policy.fetch_hardened("https://cdn.test/", HOSTS)
    options = constructor.call_args.kwargs
    assert options["host"] == PUBLIC
    assert options["server_hostname"] == options["assert_hostname"] == "cdn.test"
    assert options["cert_reqs"] == ssl.CERT_REQUIRED


@pytest.mark.parametrize("location", [
    "http://internal-api/admin", "http://169.254.169.254/", "file:///etc/passwd",
    "//127.0.0.1/", "http://cdn.test:8080/",
])
def test_redirect_target_checked_before_second_connection(location, public_dns, monkeypatch):
    transport = Mock(return_value=(Mock(), Response(status=302, headers={"Location": location})))
    monkeypatch.setattr(policy, "open_pinned", transport)
    with pytest.raises(policy.PolicyError):
        policy.fetch_hardened("http://redirect.test/", HOSTS)
    assert transport.call_count == 1


def test_rebinding_between_redirects_is_rejected(monkeypatch):
    monkeypatch.setattr(policy, "resolve_addresses", Mock(side_effect=[(PUBLIC,), ("10.0.0.1",)]))
    transport = Mock(return_value=(Mock(), Response(status=302, headers={"Location": "/next"})))
    monkeypatch.setattr(policy, "open_pinned", transport)
    with pytest.raises(policy.PolicyError, match="non_public_ip"):
        policy.fetch_hardened("http://rebind.test/", HOSTS)
    assert transport.call_count == 1


def test_relative_redirect_works(public_dns, monkeypatch):
    transport = Mock(side_effect=[
        (Mock(), Response(status=302, headers={"Location": "/safe"})),
        (Mock(), Response()),
    ])
    monkeypatch.setattr(policy, "open_pinned", transport)
    assert policy.fetch_hardened("http://cdn.test/redirect", HOSTS) == (b"SAFE_FIXTURE", 200)
    assert transport.call_args.args[0].path == "/safe"


def test_redirect_loop_is_bounded(public_dns, monkeypatch):
    transport = Mock(side_effect=lambda *_: (Mock(), Response(status=302, headers={"Location": "/loop"})))
    monkeypatch.setattr(policy, "open_pinned", transport)
    with pytest.raises(policy.PolicyError, match="too_many_redirects"):
        policy.fetch_hardened("http://cdn.test/loop", HOSTS)
    assert transport.call_count == policy.MAX_REDIRECTS + 1


@pytest.mark.parametrize("known_length", [True, False])
def test_large_response_rejected_and_closed(known_length, public_dns, monkeypatch):
    monkeypatch.setattr(policy, "MAX_BYTES", 8)
    response = Response(b"x" * 9, headers={"Content-Length": "9"} if known_length else {})
    pool = Mock()
    monkeypatch.setattr(policy, "open_pinned", lambda *_: (pool, response))
    with pytest.raises(policy.ResponseTooLarge):
        policy.fetch_hardened("http://cdn.test/", HOSTS)
    assert response.closed
    pool.close.assert_called_once()


def test_compressed_response_not_decompressed(public_dns, monkeypatch):
    monkeypatch.setattr(policy, "open_pinned", lambda *_: (
        Mock(), Response(headers={"Content-Encoding": "gzip"})))
    with pytest.raises(policy.PolicyError, match="encoded_response_not_allowed"):
        policy.fetch_hardened("http://cdn.test/", HOSTS)


def test_dns_failure_is_fail_closed(monkeypatch):
    import socket
    monkeypatch.setattr(policy.socket, "getaddrinfo", Mock(side_effect=socket.gaierror()))
    with pytest.raises(policy.PolicyError, match="dns_failed"):
        policy.validate_target("http://cdn.test/", HOSTS)


def test_dns_wait_is_bounded(monkeypatch):
    future = Mock()
    future.result.side_effect = policy.FutureTimeout()
    future.add_done_callback.side_effect = lambda callback: callback(future)
    monkeypatch.setattr(policy._executor, "submit", Mock(return_value=future))
    with pytest.raises(policy.PolicyError, match="dns_timeout"):
        policy.validate_target("http://cdn.test/", HOSTS)
    future.result.assert_called_once_with(timeout=policy.DNS_TIMEOUT)


def test_endpoint_reports_denial_and_timeout(monkeypatch, caplog):
    import app as web
    monkeypatch.setattr(web, "VULNERABLE", False)
    client = web.app.test_client()
    monkeypatch.setattr(web, "fetch_hardened", Mock(side_effect=policy.PolicyError("non_public_ip")))
    response = client.get("/fetch", query_string={"url": "http://private.test/"})
    assert response.status_code == 403
    assert response.json["reason"] == "non_public_ip"
    assert "ODRZUCONO" in caplog.text
    monkeypatch.setattr(web, "fetch_hardened", Mock(side_effect=TimeoutError()))
    assert client.get("/fetch", query_string={"url": "http://cdn.test/"}).status_code == 504
