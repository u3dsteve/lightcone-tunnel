# Lightcone Tunnel

> **Anti-DPI UDP Tunnel with SOCKS5/HTTP Proxy, RS-FEC Packet Loss Recovery, and Full-Cone NAT Forwarding**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)](https://github.com/u3dsteve/lightcone-tunnel/releases)
[![GitHub Stars](https://img.shields.io/github/stars/u3dsteve/lightcone-tunnel)](https://github.com/u3dsteve/lightcone-tunnel/stargazers)
[![GitHub Issues](https://img.shields.io/github/issues/u3dsteve/lightcone-tunnel)](https://github.com/u3dsteve/lightcone-tunnel/issues)

---

## What is Lightcone Tunnel?

**Lightcone Tunnel** is a single-file, cross-platform **UDP tunnel** that combines **SOCKS5/HTTP proxy** with **RS-FEC forward error correction** and **anti-DPI traffic obfuscation**. It is designed for network environments with **high packet loss**, **unstable connections**, or **deep packet inspection (DPI)** restrictions.

**Key capabilities:**

| Capability | Description |
| :--- | :--- |
| **Anti-DPI Obfuscation** | No fixed magic bytes, randomized packet sizes (800–1200 bytes), Burst-mode jitter |
| **RS-FEC Anti-Packet-Loss** | Reed-Solomon forward error correction with `(12,4)` configuration — recovers from up to 25% packet loss |
| **ChaCha20-Poly1305 AEAD** | Authenticated encryption with 64-bit monotonic anti-replay protection |
| **SOCKS5 / HTTP Proxy** | Full TCP CONNECT and UDP ASSOCIATE support with Full-Cone NAT forwarding |
| **IPv4 / IPv6 Dual-Stack** | Seamless handling of both address families |
| **DDNS Resilience** | Automatic background DNS refresh every 60 seconds |
| **Cross-Platform GUI** | Windows and Linux desktop manager with multi-language support |
| **Docker Ready** | Pre-built Docker image for server/CLI deployment |

---

## Why Lightcone Tunnel?

### Compared to Other Solutions

| Solution | Anti-DPI | FEC | SOCKS5/HTTP Proxy | Full-Cone NAT | GUI | Single-File |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Lightcone Tunnel** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| tinyfecVPN | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| UDPspeeder | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| Shadowsocks | ⚠️ | ❌ | ✅ | ❌ | ✅ | ❌ |
| WireGuard | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ |
| OpenVPN | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |

**What makes Lightcone Tunnel different:**

- **Anti-DPI by design**, not as an afterthought — no protocol signatures, randomized packet sizing, Burst-mode jitter
- **RS-FEC built into the tunnel** — recovers lost packets without application-layer retransmission
- **Dual proxy modes** — SOCKS5 and HTTP in one binary
- **Full-Cone NAT UDP forwarding** — supports UDP-dependent applications (VoIP, gaming)
- **Cross-platform GUI** — non-technical users can manage the tunnel
- **Single-file executable** — no complex installation

---

## Who Is This For?

- **Network Engineers** — deploying tunnels in high-loss or DPI-restricted environments
- **System Administrators** — setting up secure proxy gateways for internal networks
- **DevOps Engineers** — integrating tunnels into CI/CD or containerized deployments
- **Privacy-Conscious Users** — bypassing censorship with encrypted, obfuscated traffic
- **Gamers / VoIP Users** — maintaining stable UDP connections over lossy links

---

## Quick Start

### Option 1: Pre-built GUI (Recommended for End Users)

Download the `LightconeManager` executable from the Releases page:

```bash
# Windows: Double-click LightconeManager.exe
# Linux: chmod +x LightconeManager && ./LightconeManager
```

### Option 2: CLI Mode (Headless)

```bash
# Install dependencies
pip install -r requirements.txt

# Start as client
python lightcone-tunnel.py config_client.yaml

# Start as server
python lightcone-tunnel.py config_server.yaml
```

### Option 3: Docker (Production-Ready)

```bash
# Build the image
./build-docker.sh

# Run client with default config
docker run --rm -v $(pwd)/config_client.yaml:/app/config.yaml lightcone-tunnel:latest

# Run server
docker run --rm -v $(pwd)/config_server.yaml:/app/config.yaml lightcone-tunnel:latest /app/config.yaml
```

---

## Technical Overview

### Protocol Architecture

```
[Application] → SOCKS5/HTTP → [Client] → Encryption → FEC → UDP → [Server] → Decryption → [Target]
```

### Encryption Layer (Visible to DPI)

```
[RandomPrefix 4B] [Seq 8B] [Timestamp 8B] [PadLen 1B] [Nonce 12B] [ChaCha20 Ciphertext]
```

- **No fixed magic bytes** — no `LCT1` or other identifiable signatures
- **64-bit sequence numbers** — monotonic, never wrap
- **ChaCha20-Poly1305 AEAD** — authenticated encryption with integrity protection

### FEC Layer (Inside Encrypted Payload)

```
[Group ID 8B] [ShardIdx 1B] [N 1B] [M 1B] [RawLen 2B] [Shard Data]
```

- **64-bit Group ID** — never wraps, supports indefinite 7×24 operation
- **Zero-latency delivery** — uncorrupted shards delivered immediately
- **zfec C-extension accelerated** — falls back to pure Python XOR when unavailable

### Anti-DPI Mechanisms

| Mechanism | Description |
| :--- | :--- |
| **No Magic Bytes** | First 4 bytes randomized per packet |
| **Dynamic Payload Sizing** | 800–1200 bytes random chunk size |
| **Burst-Mode Jitter** | 0.1–0.3ms micro-sleep every 12 packets |
| **Dynamic Padding** | 0–15 random bytes appended to each datagram |

---

## Configuration

### Client Configuration (`config_client.yaml`)

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

### Server Configuration (`config_server.yaml`)

```yaml
role: "server"
server_addr: "0.0.0.0:8443"
psk: "YourStrongSecretPSKKeyHere"
fec_data_shards: 12
fec_parity_shards: 4
max_concurrent_streams: 1024
log_level: "info"
```

### FEC Parameter Tuning

| Configuration | Overhead | Loss Tolerance | Use Case |
| :--- | :--- | :--- | :--- |
| `(0, 0)` | 0% | 0% | Clean networks (FEC disabled) |
| `(8, 2)` | ~25% | ~20% | Moderate packet loss |
| `(12, 4)` | ~33% | ~25% | High packet loss (default) |
| `(16, 4)` | ~25% | ~20% | Very high throughput |

---

## Verification

```bash
# Test SOCKS5 proxy
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me

# Test HTTP proxy
curl -x http://127.0.0.1:8080 https://ifconfig.me

# Check server UDP binding
ss -ulpn | grep 8443
```

---

## Building from Source

### Clone and Install Dependencies

```bash
git clone https://github.com/u3dsteve/lightcone-tunnel
cd lightcone-tunnel
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Package Executables (GUI)

```bash
pip install pyinstaller
python build.py

# Output: dist/LightconeManager.exe (Windows) or dist/LightconeManager (Linux)
```

### Docker Image

```bash
./build-docker.sh
```

---

## Project Structure

```
lightcone-tunnel/
├── lightcone-tunnel.py          # Core tunnel engine (CLI)
├── lightcone-manager.py         # GUI management application
├── build.py                     # PyInstaller packaging script
├── build-docker.sh              # Docker image builder
├── Dockerfile                   # Docker build definition
├── docker-compose.yaml          # Docker Compose configuration
├── config_client.yaml           # Client configuration template
├── config_server.yaml           # Server configuration template
├── requirements.txt             # Core dependencies
├── requirements-gui.txt         # GUI dependencies
└── configs/                     # User configuration storage (auto-created)
```

---

## Roadmap

| Version | Feature | Status |
| :--- | :--- | :--- |
| v1.2.0 | RS-FEC Anti-Packet-Loss Engine | ✅ Released |
| v1.4.4 | Cross-Platform GUI Manager | ✅ Released |
| v1.5.0 | TUN Mode Support (VPN-like) | 🚧 Planned |
| v1.6.0 | Multi-User PSK Management | 📋 Planned |

---

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

---

## License

MIT License — see [LICENSE](LICENSE) file for details.

---

## Related Projects

- [Tunnel Agent](https://github.com/u3dsteve/tunnel-agent) — Lightweight TCP-over-UDP forwarder with RS-FEC
- [tinyfecVPN](https://github.com/wangyu-/tinyfecVPN) — VPN with FEC for lossy links
- [UDPspeeder](https://github.com/wangyu-/UDPspeeder) — UDP tunnel with FEC

---

## Keywords

```
udp-tunnel, anti-dpi, socks5-proxy, http-proxy, fec, forward-error-correction, reed-solomon, chacha20-poly1305, anti-replay, full-cone-nat, python, asyncio, network-tunnel, obfuscation, security, encryption, ddns, cross-platform, gui, docker
```

---

## Why Open Source?

Lightcone Tunnel was built by network engineers who needed a reliable tunnel for high-loss, DPI-restricted environments. We're open-sourcing it because we believe the tools that make our networks more resilient should be available to everyone.

If you've ever struggled with packet loss, DPI blocking, or rebuilding your network configuration from scratch — this is for you.

---

*Built by network engineers, for network engineers.*
