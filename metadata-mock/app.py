"""
Symulowany chmurowy serwis metadanych (jak 169.254.169.254 w AWS/Azure/GCP).
WSZYSTKO FIKCYJNE. Sluzy wylacznie do pokazania skutku SSRF w labie.
To jest cel ataku T2.
"""
from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/")
def root():
    return "metadata-mock (srodowisko laboratoryjne, dane fikcyjne)\n"


@app.route("/latest/meta-data/iam/security-credentials/demo-role")
def creds():
    # Fikcyjne poswiadczenia - imitujemy wyciek tokena przez SSRF.
    return jsonify(
        AccessKeyId="AKIA-FIKCYJNE-DO-LABU",
        SecretAccessKey="sekret-fikcyjny-tylko-do-demonstracji",
        Token="token-fikcyjny-SSRF-lab",
        Note="Dane nieprawdziwe - wygenerowane na potrzeby projektu P8.",
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
