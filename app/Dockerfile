FROM python:3.12-slim
WORKDIR /srv
RUN apt-get update && apt-get install -y --no-install-recommends iptables util-linux && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py ssrf_policy.py ./
COPY entrypoint.sh egress-rules.sh ./
RUN sed -i 's/\r$//' entrypoint.sh egress-rules.sh && chmod +x entrypoint.sh egress-rules.sh
ENTRYPOINT ["/srv/entrypoint.sh"]
