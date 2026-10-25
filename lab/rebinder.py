"""Deterministic own-lab authoritative DNS: first A public, later A private, TTL 0."""
import threading
from dnslib import A, DNSRecord, QTYPE, RR
from dnslib.server import BaseResolver, DNSServer
from flask import Flask, jsonify

lock = threading.Lock()
history = []
app = Flask(__name__)


class Resolver(BaseResolver):
    def resolve(self, request, handler):
        reply = request.reply()
        name = str(request.q.qname).lower()
        if name == "rebind.test." and QTYPE[request.q.qtype] == "A":
            with lock:
                address = "93.184.216.10" if not history else "169.254.169.10"
                history.append(address)
                index = len(history)
            reply.add_answer(RR(name, QTYPE.A, ttl=0, rdata=A(address)))
            print(f"REBIND A query={index} answer={address} ttl=0", flush=True)
        return reply


@app.post("/reset")
def reset():
    with lock:
        history.clear()
    return jsonify(status="reset")


@app.get("/state")
def state():
    with lock:
        return jsonify(answers=list(history), queries=len(history))


if __name__ == "__main__":
    resolver = Resolver()
    DNSServer(resolver, port=5353, address="0.0.0.0").start_thread()
    DNSServer(resolver, port=5353, address="0.0.0.0", tcp=True).start_thread()
    app.run(host="0.0.0.0", port=8053)
