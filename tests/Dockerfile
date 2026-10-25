FROM python:3.12-slim
WORKDIR /suite
COPY app/requirements.txt /tmp/app-requirements.txt
RUN pip install --no-cache-dir -r /tmp/app-requirements.txt pytest==9.1.1 dnslib==0.9.26
COPY app ./app
COPY tests ./tests
COPY pytest.ini ./
CMD ["python", "-m", "pytest", "-q"]
