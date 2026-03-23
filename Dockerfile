# Dockerfile — #15 Deploy server on cloud
FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY server.py protocol.py config_loader.py messages_pb2.py config.yaml ./
COPY gen_certs.py ./

# Generate certs at build time (override with volume mount for production)
RUN python gen_certs.py

# Expose TLS port and dashboard port
EXPOSE 6767 8080

# Allow config override via environment variables
ENV TLS_HOST=0.0.0.0
ENV TLS_PORT=6767
ENV AUTH_TOKEN=changeme-token-1234
ENV DASHBOARD_PORT=8080

CMD ["python", "server.py", \
     "--host", "0.0.0.0", \
     "--config", "config.yaml"]
