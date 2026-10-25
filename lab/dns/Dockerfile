FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends dnsmasq-base && rm -rf /var/lib/apt/lists/*
COPY dnsmasq.conf /etc/dnsmasq.conf
CMD ["dnsmasq", "--keep-in-foreground", "--log-facility=-"]
