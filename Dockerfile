FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application and default configs
COPY lightcone-tunnel.py .
COPY config_client.yaml config_server.yaml ./

# Default config symlink
RUN ln -sf config_client.yaml config.yaml

# Entry point with default config
ENTRYPOINT ["python3", "/app/lightcone-tunnel.py"]
CMD ["/app/config.yaml"]
