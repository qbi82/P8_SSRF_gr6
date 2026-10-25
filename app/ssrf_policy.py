"""Validate every hop and connect to the exact validated numeric IP address."""
import ipaddress
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import certifi
import urllib3

MAX_BYTES = 1024 * 1024
MAX_REDIRECTS = 3
FETCH_BUDGET = 10.0
DNS_TIMEOUT = 2.0
CONNECT_TIMEOUT = 2.0
READ_TIMEOUT = 3.0
_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="dns")
_slots = threading.BoundedSemaphore(4)


class PolicyError(ValueError):
    pass


class ResponseTooLarge(ValueError):
    pass


@dataclass(frozen=True)
class Target:
    scheme: str
    hostname: str
    port: int
    ip: str
    path: str
    authority: str


def resolve_addresses(hostname, port):
    if not _slots.acquire(blocking=False):
        raise PolicyError("dns_busy")
    try:
        future = _executor.submit(socket.getaddrinfo, hostname, port,
                                  socket.AF_UNSPEC, socket.SOCK_STREAM)
    except Exception:
        _slots.release()
        raise
    future.add_done_callback(lambda _: _slots.release())
    try:
        answers = future.result(timeout=DNS_TIMEOUT)
    except FutureTimeout as exc:
        future.cancel()
        raise PolicyError("dns_timeout") from exc
    except socket.gaierror as exc:
        raise PolicyError("dns_failed") from exc
    return tuple(dict.fromkeys(answer[4][0] for answer in answers))


def validate_target(url, allowed_hosts):
    if not isinstance(url, str) or not url or len(url) > 2048:
        raise PolicyError("invalid_url")
    if "\\" in url or any(ord(c) <= 32 or ord(c) == 127 for c in url):
        raise PolicyError("invalid_url_characters")
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            raise PolicyError("scheme_not_allowed")
        if parsed.username is not None or parsed.password is not None:
            raise PolicyError("credentials_not_allowed")
        raw_host = parsed.hostname
        if not raw_host or "%" in raw_host or parsed.fragment:
            raise PolicyError("invalid_host_or_fragment")
        hostname = raw_host.encode("idna").decode("ascii").lower().rstrip(".")
        port = parsed.port or (443 if scheme == "https" else 80)
    except (UnicodeError, ValueError) as exc:
        if isinstance(exc, PolicyError):
            raise
        raise PolicyError("invalid_url") from exc
    allowed = {h.strip().lower().rstrip(".") for h in allowed_hosts}
    if hostname not in allowed:
        raise PolicyError("host_not_allowed")
    if port not in (80, 443) or parsed.port == 0:
        raise PolicyError("port_not_allowed")
    addresses = resolve_addresses(hostname, port)
    if not addresses:
        raise PolicyError("dns_empty")
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise PolicyError("invalid_dns_address") from exc
        if (not ip.is_global or ip.is_multicast or ip.is_reserved or
                ip.is_loopback or ip.is_link_local or ip.is_unspecified or
                (ip.version == 6 and ip.ipv4_mapped is not None)):
            raise PolicyError("non_public_ip")
    authority = "[" + hostname + "]" if ":" in hostname else hostname
    if port != (443 if scheme == "https" else 80):
        authority += ":" + str(port)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return Target(scheme, hostname, port, addresses[0], path, authority)


def open_pinned(target, remaining):
    timeout = urllib3.Timeout(connect=min(CONNECT_TIMEOUT, remaining),
                              read=min(READ_TIMEOUT, remaining), total=remaining)
    options = dict(host=target.ip, port=target.port, timeout=timeout, retries=False)
    if target.scheme == "https":
        pool = urllib3.HTTPSConnectionPool(
            **options, server_hostname=target.hostname, assert_hostname=target.hostname,
            cert_reqs=ssl.CERT_REQUIRED, ca_certs=certifi.where())
    else:
        pool = urllib3.HTTPConnectionPool(**options)
    try:
        response = pool.urlopen("GET", target.path, redirect=False, retries=False,
                                preload_content=False, headers={
                                    "Host": target.authority,
                                    "Accept-Encoding": "identity",
                                    "User-Agent": "P8-SSRF-lab/1.0",
                                })
        return pool, response
    except Exception:
        pool.close()
        raise


def fetch_hardened(url, allowed_hosts):
    deadline = time.monotonic() + FETCH_BUDGET
    for hop in range(MAX_REDIRECTS + 1):
        target = validate_target(url, allowed_hosts)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("fetch_budget_exceeded")
        pool, response = open_pinned(target, remaining)
        try:
            if response.status in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")
                if not location:
                    raise PolicyError("redirect_without_location")
                if hop == MAX_REDIRECTS:
                    raise PolicyError("too_many_redirects")
                url = urljoin(url, location)
                continue
            if response.headers.get("Content-Encoding", "identity").lower() not in ("", "identity"):
                raise PolicyError("encoded_response_not_allowed")
            length = response.headers.get("Content-Length")
            if length is not None:
                try:
                    size = int(length)
                except ValueError as exc:
                    raise PolicyError("invalid_content_length") from exc
                if size < 0:
                    raise PolicyError("invalid_content_length")
                if size > MAX_BYTES:
                    raise ResponseTooLarge("response_too_large")
            data = bytearray()
            while True:
                if time.monotonic() >= deadline:
                    raise TimeoutError("fetch_budget_exceeded")
                chunk = response.read1(min(65536, MAX_BYTES + 1 - len(data)), decode_content=False)
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > MAX_BYTES:
                    raise ResponseTooLarge("response_too_large")
            return bytes(data), response.status
        finally:
            response.close()
            pool.close()
    raise PolicyError("too_many_redirects")
