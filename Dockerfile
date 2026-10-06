FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home monitor
COPY aiticket aiticket
RUN mkdir -p /data /keys /logs && chown monitor:monitor /data /keys /logs
USER monitor
ENV AITICKET_DATA=/data AITICKET_KEY_FILE=/keys/encryption.key PYTHONUNBUFFERED=1
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=3)"
CMD ["python", "-m", "aiticket", "serve", "--host", "0.0.0.0"]
