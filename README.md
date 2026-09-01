# Lightcone Tunnel

> A single-file, cross-platform UDP tunnel with SOCKS5/HTTP proxy, RS-FEC anti-packet-loss engine, full-cone NAT forwarding, and a strict Memory-Aware Adaptive Engine for unstable or censored networks.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)]()


## About

**Lightcone Tunnel** is a single-file, cross-platform UDP tunnel that provides SOCKS5/HTTP proxy on the client side and full-cone NAT forwarding on the server side. It is designed for network environments where stability is poor or restrictions are present.

Key features:

- **Memory-Aware Adaptive Engine**: Dynamically calculates TCP/UDP buffer sizes, connection limits, and scan windows based on available RAM to strictly prevent Out-of-Memory (OOM) crashes.
- **Latency-Based Tuning**: Automatically optimizes ARQ, NACK cooldowns, and FEC timeouts based on the expected RTT for high-latency/weak-signal environments.
- **Anti-packet-loss**: RS-FEC (Reed-Solomon forward error correction) — with `(12,4)` configuration, recovers from up to 25% packet loss, featuring automatic algorithm negotiation (`zfec` vs XOR).
- **Anti-DPI**: No fixed magic bytes, random padding, encrypted headers, and Burst-mode jitter.
- **Secure**: ChaCha20-Poly1305 AEAD encryption with 64-bit anti-replay protection.
- **Cross-platform**: Windows / Linux with both GUI and CLI interfaces.


## What It Does

| Role | Function |
| :--- | :--- |
| **Client** | Starts SOCKS5 (port 1080) and HTTP proxy (port 8080), receives traffic from browsers/applications, encrypts it, and forwards it to the server via UDP tunnel |
| **Server** | Listens on UDP port, decrypts traffic, reconstructs streams, and forwards them to the target service (e.g., internal SSH, web server) |

**Typical use cases:**

- Browser traffic routed through SOCKS5 proxy to bypass restrictions
- Port forwarding over unreliable/high-latency networks (similar to SSH forwarding but over UDP with FEC)
- Remote access to SSH/RDP/web services on constrained edge devices


## Technical Overview

**Encryption protocol (outer layer):**

```
[RandomPad 4B] [Seq 8B] [Timestamp 8B] [PadLen 1B] [Nonce 12B] [ChaCha20 Ciphertext]
```

- No fixed magic bytes — eliminates signatures like `LCT1`
- 64-bit sequence numbers — monotonic, never wrap
- ChaCha20-Poly1305 AEAD authenticated encryption

**FEC protocol (inside encrypted payload, invisible from outside):**

```
[Group ID 8B] [ShardIdx 1B] [N 1B] [M 1B (MSB for zfec)] [RawLen 2B] [Shard Data]
```

- 64-bit Group ID — never wraps
- Zero-latency delivery — uncorrupted shards are delivered immediately; FEC recovery only triggers when loss occurs
- Smart algorithm negotiation — uses MSB (Most Significant Bit) of M to negotiate `zfec` C-extension usage safely across different environments, preventing data corruption if dependencies mismatch.

**Anti-OOM & Memory Defenses:**

- Strict integration with Linux `resource.RLIMIT_AS` (Virtual Memory limits)
- Graceful connection eviction at 90% capacity
- Safe buffer downscaling if user overrides `max_concurrent_streams` beyond safe memory bounds


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

RUN pip install --no-cache-dir cryptography pyyaml zfec

COPY lightcone-tunnel.py /app/lightcone-tunnel.py

ENTRYPOINT ["python3", "/app/lightcone-tunnel.py"]
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


## Configuration Examples

### Client (`config_client.yaml`)

```yaml
# Lightcone Tunnel v4.2.2 - Client Configuration
# Production Release: Memory-Aware Adaptive Engine & Strict Defenses

role: "client"                           # Node operation mode: "client" or "server"
server_addr: "tunnel.example.com:8443"   # Server domain or IPv4/IPv6 address with UDP port
psk: "YourStrongSecretPSKKeyHere"        # Pre-shared key for ChaCha20-Poly1305 AEAD encryption

# Local Ingress Proxy Settings
socks_port: 1080                         # Local SOCKS5 proxy port (supports TCP & UDP Associate)
http_port: 8080                          # Local HTTP/HTTPS CONNECT proxy port

# Memory & Latency Adaptive Engine
# The engine dynamically calculates TCP/UDP buffer sizes, timeouts, and scan windows.
available_memory_mb: 512                 # Max memory limit in MB. Controls OS virtual memory limits (RLIMIT_AS).
expected_latency_ms: 100                 # Expected RTT latency to the server in ms. Used to tune timeouts.

# Optional: Hard limit for concurrent TCP streams and UDP sessions.
# Note: If set higher than the memory-derived limit, buffers will safely downscale to prevent OOM.
max_concurrent_streams: 1024

# RS-FEC (Forward Error Correction) Settings
# Set both to 0 to disable FEC. Both client and server MUST use identical N/M settings.
fec_data_shards: 12                      # Number of data shards (N)
fec_parity_shards: 4                     # Number of parity shards (M)

# System Settings
log_level: "info"                        # Log verbosity: "debug", "info", "warning", "error"
```

### Server (`config_server.yaml`)

```yaml
# Lightcone Tunnel v4.2.2 - Server Configuration
# Production Release: Memory-Aware Adaptive Engine & Strict Defenses

role: "server"                           # Node operation mode: "client" or "server"
server_addr: "0.0.0.0:8443"              # UDP listening host and port
psk: "YourStrongSecretPSKKeyHere"        # Pre-shared key (must match client's PSK exactly)

# Memory & Latency Adaptive Engine
# The engine dynamically calculates TCP/UDP buffer sizes, timeouts, and scan windows.
available_memory_mb: 512                 # Max memory limit in MB. Aligns with cgroup/Docker limits.
expected_latency_ms: 100                 # Expected RTT latency to clients in ms. Used to tune timeouts.

# Optional: Hard limit for concurrent outbound sockets and Full-Cone NAT entries.
max_concurrent_streams: 1024

# RS-FEC (Forward Error Correction) Settings
# Set both to 0 to disable FEC. Both client and server MUST use identical N/M settings.
fec_data_shards: 12                      # Number of data shards (N)
fec_parity_shards: 4                     # Number of parity shards (M)

# System Settings
log_level: "info"                        # Log verbosity: "debug", "info", "warning", "error"
```


## Verification

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
