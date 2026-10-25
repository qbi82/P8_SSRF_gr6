"""
Aplikacja z funkcja "pobierz zasob z URL" (podglad/import).
To jest serce projektu SSRF.

Podzial pracy:
  - Jakub  -> wersja PODATNA (VULNERABLE=1): endpoint pobiera dowolny URL bez kontroli.
  - Kolega -> wersja z POPRAWKA (VULNERABLE=0): uzupelnia funkcje is_url_allowed().

Dzieki przelacznikowi VULNERABLE ten sam kod obsluguje oba warianty,
wiec testy BEFORE/AFTER uruchamia sie bez zmiany aplikacji - tylko zmiana zmiennej.
"""
import os
import logging
import requests
from flask import Flask, request, jsonify
import urllib3
from ssrf_policy import validate_target, fetch_hardened, PolicyError, ResponseTooLarge

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ssrf-app")

VULNERABLE = os.environ.get("VULNERABLE", "0") == "1"
ALLOWED_HOSTS = [h.strip() for h in os.environ.get("ALLOWED_HOSTS", "").split(",") if h.strip()]


def is_url_allowed(url: str):
    """Return the policy decision; the fetch path also retains the validated IP.

    Rules and bounded HTTP transport live in ssrf_policy.py. The endpoint uses
    fetch_hardened directly so DNS is not resolved again after validation.
    """
    try:
        validate_target(url, ALLOWED_HOSTS)
        return True, None
    except PolicyError as exc:
        return False, str(exc)


@app.route("/health")
def health():
    return jsonify(status="ok", mode="vulnerable" if VULNERABLE else "hardened",
                   egress=os.environ.get("ENABLE_EGRESS", "0") == "1")


@app.route("/fetch")
def fetch():
    """GET /fetch?url=... -> serwer pobiera URL i zwraca tresc."""
    url = request.args.get("url", "")
    if not url:
        return jsonify(error="podaj parametr ?url="), 400

    if not VULNERABLE:
        # Validation returns the resolved address to the transport directly.
        # Calling is_url_allowed() and then requests.get(url) would resolve DNS twice.
        try:
            body, status = fetch_hardened(url, ALLOWED_HOSTS)
            log.info("fetch allowed status=%s bytes=%s", status, len(body))
            return body, status, {"Content-Type": "text/plain; charset=utf-8"}
        except PolicyError as exc:
            log.warning("ODRZUCONO fetch reason=%s", exc)
            return jsonify(error="cel niedozwolony", reason=str(exc)), 403
        except ResponseTooLarge:
            log.warning("ODRZUCONO fetch reason=response_too_large")
            return jsonify(error="response_too_large"), 413
        except (urllib3.exceptions.TimeoutError, TimeoutError):
            log.warning("fetch failed reason=timeout")
            return jsonify(error="upstream_timeout"), 504
        except Exception:
            log.exception("fetch failed")
            return jsonify(error="upstream_failed"), 502

    try:
        # Naiwna obsluga schematu file:// - jak w aplikacjach uzywajacych urllib.
        # To celowy blad wersji podatnej: pozwala odczytac lokalny plik serwera.
        if url.lower().startswith("file://"):
            path = url[len("file://"):]
            with open(path, "r", errors="replace") as f:
                data = f.read(4096)   # limit, zeby nie wyrzucic ogromnego pliku
            log.info("fetch file url=%s -> 200 (odczyt lokalny)", url)
            return (data, 200, {"Content-Type": "text/plain; charset=utf-8"})

        # Wersja podatna: zadnej kontroli - serwer idzie, gdzie mu kaze uzytkownik.
        with requests.Session() as session:
            session.trust_env = False
            resp = session.get(url, timeout=5, allow_redirects=True)
        log.info("fetch url=%s -> %s", url, resp.status_code)
        return (resp.text, resp.status_code, {"Content-Type": "text/plain; charset=utf-8"})
    except Exception as e:
        log.info("fetch url=%s -> blad: %s", url, e)
        return jsonify(error=str(e)), 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
