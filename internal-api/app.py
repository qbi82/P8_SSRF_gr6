"""
Usluga WEWNETRZNA - panel, ktory nigdy nie powinien byc osiagalny z zewnatrz.
Dostepna tylko w sieci 'internal'. To jest cel ataku T1.
"""
from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/")
def root():
    return jsonify(service="internal-api", info="usluga wewnetrzna - tylko dla sieci wewnetrznej")


@app.route("/admin")
def admin():
    # Fikcyjne dane - dowod, ze atakujacy dosiegnal zasobu wewnetrznego.
    return jsonify(
        panel="admin",
        secret_flag="FLAG{SSRF-dosiegnieto-uslugi-wewnetrznej}",
        users=["admin", "serwis-backup"],
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
