FROM python:3.12-slim
WORKDIR /lab
RUN pip install --no-cache-dir flask==3.0.3 dnslib==0.9.26
COPY fixture.py rebinder.py ./
CMD ["python", "fixture.py"]
