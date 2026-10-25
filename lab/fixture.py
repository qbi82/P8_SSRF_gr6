"""Local legal target and attacker-controlled redirects; no external requests."""
import time
from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/")
@app.route("/safe")
def safe():
    return "SAFE_FIXTURE: legalny zasob z allowlisty\n", 200


@app.route("/to-internal")
def to_internal():
    return redirect("http://internal-api/admin", code=302)


@app.route("/relative")
def relative():
    return redirect("/safe", code=302)


@app.route("/loop")
def loop():
    return redirect("/loop", code=302)


@app.route("/slow")
def slow():
    time.sleep(4)
    return "SLOW_FIXTURE\n"


@app.route("/large")
def large():
    return "x" * (1024 * 1024 + 1)


@app.after_request
def audit(response):
    print(f"fixture host={request.host} path={request.path} status={response.status_code}", flush=True)
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
