# Lightcone Tunnel

> **A single-file, cross-platform UDP tunnel with SOCKS5/HTTP proxy, RS-FEC anti-packet-loss engine, and full-cone NAT forwarding for unstable or censored networks.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)]()


## About

**Lightcone Tunnel** is a single-file, cross-platform UDP tunnel that provides SOCKS5/HTTP proxy on the client side and full-cone NAT forwarding on the server side. It is designed for network environments where stability is poor or restrictions are present.

Key features:

- **Anti-packet-loss**: RS-FEC (Reed-Solomon forward error correction) — with `(12,4)` configuration, recovers from up to 25% packet loss
- **Anti-DPI**: No fixed magic bytes, random packet sizes (800–1200 bytes), Burst-mode jitter
- **Secure**: ChaCha20-Poly1305 AEAD encryption with 64-bit anti-replay protection
- **Cross-platform**: Windows / Linux with both GUI and CLI interfaces


## What It Does

| Role | Function |
| :--- | :--- |
| **Client** | Starts SOCKS5 (port 1080) and HTTP proxy (port 8080), receives traffic from browsers/applications, encrypts it, and forwards it to the server via UDP tunnel |
| **Server** | Listens on UDP port, decrypts traffic, reconstructs streams, and forwards them to the target service (e.g., internal SSH, web server) |

**Typical use cases:**

- Browser traffic routed through SOCKS5 proxy to bypass restrictions
- Port forwarding over unreliable networks (similar to SSH forwarding but over UDP with FEC)
- Remote access to SSH/RDP/web services


## Technical Overview

**Encryption protocol (outer layer):**

```
[RandomPrefix 4B] [Seq 8B] [Timestamp 8B] [PadLen 1B] [Nonce 12B] [ChaCha20 Ciphertext]
```

- No fixed magic bytes — eliminates signatures like `LCT1`
- 64-bit sequence numbers — monotonic, never wrap
- ChaCha20-Poly1305 AEAD authenticated encryption

**FEC protocol (inside encrypted payload, invisible from outside):**

```
[Group ID 8B] [ShardIdx 1B] [N 1B] [M 1B] [RawLen 2B] [Shard Data]
```

- 64-bit Group ID — never wraps
- Zero-latency delivery — uncorrupted shards are delivered immediately; FEC recovery only triggers when loss occurs
- `zfec` C-extension accelerated; falls back to pure Python XOR when `zfec` is unavailable

**Anti-DPI mechanisms:**

- Packet sizes randomized between 800–1200 bytes — no fixed pattern
- Burst Mode: micro-sleep (0.1–0.3ms) every 12 packets — breaks timing patterns


## Deployment

### Option 1: Pre-built GUI (Recommended)

Download the `LightconeManager` executable for your platform from the Releases page and double-click to run.

- **Windows**: `LightconeManager.exe`
- **Linux**: `LightconeManager` (set executable: `chmod +x`)

**Using the GUI:**

1. First launch automatically creates `configs/default_client.yaml`
2. Edit configuration (server address, PSK, FEC parameters, etc.), click Save
3. Click **Start Engine**

Configurations are stored in `configs/` directory — you can switch between multiple profiles.

### Option 2: CLI Mode (Headless)

**Install dependencies first**

```bash
pip install -r requirements.txt
```

**Start the client:**

```bash
python lightcone-tunnel.py config_client.yaml
```

**Start the server:**

```bash
python lightcone-tunnel.py config_server.yaml
```

### Option 3: Docker Deployment

**Dockerfile:**

```dockerfile
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
```

**docker-compose.yml:**

```yaml
services:
  lightcone-server:
    build: .
    container_name: lightcone-server
    restart: always
    network_mode: host
    volumes:
      - ./config_server.yaml:/app/config.yaml:ro
    command: ["/app/config.yaml"]
    deploy:
      resources:
        limits:
          memory: 512M

  lightcone-client:
    build: .
    container_name: lightcone-client
    restart: always
    network_mode: host
    volumes:
      - ./config_client.yaml:/app/config.yaml:ro
    command: ["/app/config.yaml"]
    deploy:
      resources:
        limits:
          memory: 256M
```

**Run services:**

```bash
# Build and run server
docker compose up -d --build lightcone-server

# Build and run client
docker compose up -d --build lightcone-client

# View logs
docker compose logs -f
```

### Configuration Examples

**Client (`config_client.yaml`):**

```yaml
role: "client"
server_addr: "tunnel.example.com:8443"
psk: "YourStrongSecretPSKKeyHere"
socks_port: 1080
http_port: 8080
fec_data_shards: 12
fec_parity_shards: 4
max_concurrent_streams: 1024
log_level: "info"
```

**Server (`config_server.yaml`):**

```yaml
role: "server"
server_addr: "0.0.0.0:8443"
psk: "YourStrongSecretPSKKeyHere"
fec_data_shards: 12
fec_parity_shards: 4
max_concurrent_streams: 1024
log_level: "info"
```

### Verification

```bash
# Test SOCKS5
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me

# Test HTTP proxy
curl -x http://127.0.0.1:8080 https://ifconfig.me
```


## Building from Source

### Install Dependencies

```bash
# Clone repository
git clone https://github.com/u3dsteve/lightcone-tunnel
cd lightcone-tunnel

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# Install core dependencies
pip install -r requirements.txt

# Install GUI dependencies (if building GUI)
pip install -r requirements-gui.txt

# Install packaging tool
pip install pyinstaller
```

### Package Executables

**Automatic build (detects current platform):**

```bash
python build.py

# Outputs:
# Windows: dist/LightconeManager.exe
# Linux:   dist/LightconeManager
```

## Contributing

Issues and pull requests are welcome. Please open an issue first to discuss your idea before submitting a PR.

**Code guidelines:**

- Core tunnel logic stays in `lightcone-tunnel.py` (single-file)
- GUI logic in `lightcone-manager.py`
- Configuration fields follow `config_client.yaml` / `config_server.yaml`
- Use English comments

**Development setup:**

```bash
git clone https://github.com/u3dsteve/lightcone-tunnel
cd lightcone-tunnel
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-gui.txt
pip install pyinstaller
```
