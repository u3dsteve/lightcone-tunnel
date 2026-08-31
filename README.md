# Lightcone Tunnel

> **A single-file, cross-platform UDP tunnel with SOCKS5/HTTP proxy, RS-FEC anti-packet-loss engine, and full-cone NAT forwarding for unstable or censored networks.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)]()

---

## 📖 Overview

**Lightcone Tunnel** is a high-performance UDP tunnel that encapsulates TCP/UDP traffic through encrypted, anti-DPI UDP datagrams. It functions as a **SOCKS5/HTTP proxy** on the client side and a **Full-Cone NAT forwarder** on the server side, making it ideal for:

- 🌐 **Bypassing network restrictions** — Anti-DPI obfuscation defeats deep packet inspection
- 📡 **Unstable networks** — RS-FEC recovers from packet loss without TCP retransmission overhead
- 🔒 **Secure remote access** — ChaCha20-Poly1305 AEAD encryption with anti-replay protection
- 🖥️ **Desktop-friendly** — Cross-platform GUI for non-technical users

---

## ✨ Key Features

### 🔐 Security & Anti-DPI
- **ChaCha20-Poly1305 AEAD** encryption with 64-bit monotonic sequence anti-replay
- **No fixed protocol signatures** — randomized 4-byte per-packet prefix eliminates `LCT1` magic bytes
- **Dynamic payload sizing** — 800-1200 bytes random chunk size defeats length-based fingerprinting
- **Burst-mode packet scheduling** — 0.1-0.3ms jitter per 12 packets destroys timing pattern detection

### 🛡️ Anti-Packet-Loss (RS-FEC)
- **Reed-Solomon Forward Error Correction** with configurable (N, M) parameters
- **64-bit Group ID** — never wraps, supports indefinite 7×24 operation
- **Zero-latency delivery** — uncorrupted data shards delivered immediately, no FEC group wait
- **Automatic fallback** — pure Python XOR fallback when `zfec` C-extension is unavailable

### 🖥️ Cross-Platform GUI
- **Multi-configuration management** — create, edit, delete up to 10 config profiles
- **One-click start/stop** — no command line required
- **Real-time log viewer** — live tunnel output with auto-scroll and export
- **Multi-language support** — English, 简体中文, 繁體中文
- **Single-instance lock** — prevents accidental dual-launch

### 🌍 Network Capabilities
- **SOCKS5 proxy** with TCP CONNECT and UDP ASSOCIATE (Full-Cone NAT)
- **HTTP/HTTPS CONNECT proxy** — works with browsers and standard tools
- **IPv4/IPv6 dual-stack** — seamless address family handling
- **DDNS resilience** — automatic background DNS refresh every 60 seconds
- **Full-Cone NAT UDP forwarding** — symmetric NAT traversal for UDP-based applications

### 🚀 Performance & Reliability
- **Asynchronous I/O** — Python `asyncio` for high-concurrency multiplexing
- **Resource auto-reclamation** — idle TCP streams and UDP sessions cleaned after 5 minutes
- **Connection rate-limiting** — configurable concurrent stream limit (default: 1024)
- **Memory-safe** — no `RLIMIT_AS` hard limit; delegate to container/systemd

---

## 📦 Project Structure

```
lightcone-tunnel/
├── lightcone-tunnel.py          # Core tunnel engine (CLI)
├── lightcone-manager.py         # GUI management application
├── build.py                     # PyInstaller packaging script
├── config_client.yaml           # Client configuration template
├── config_server.yaml           # Server configuration template
├── requirements.txt             # Core dependencies
├── requirements-gui.txt         # GUI dependencies
├── configs/                     # User config storage (auto-created)
│   └── default_client.yaml
└── README.md
```

---

## 🚀 Quick Start

### Option 1: Download Pre-built Release (Recommended)

Download the latest release from [GitHub Releases](https://github.com/u3dsteve/lightcone-tunnel/releases):

```bash
# Windows: Download LightconeManager.exe, double-click to run
# Linux: Download LightconeManager, chmod +x, then run
```

**The GUI requires no Python installation.**

### Option 2: Run from Source

```bash
# Clone the repository
git clone https://github.com/u3dsteve/lightcone-tunnel
cd lightcone-tunnel

# Install dependencies (recommended: use virtual environment)
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements-gui.txt

# Start the GUI
python lightcone-manager.py
```

### Option 3: CLI Mode (Headless)

```bash
# Start as client
python lightcone-tunnel.py config_client.yaml

# Start as server
python lightcone-tunnel.py config_server.yaml
```

---

## 📋 Configuration

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

### FEC Parameter Guide

| Setting | Tolerance | Bandwidth Overhead | Use Case |
| :--- | :--- | :--- | :--- |
| `0, 0` | 0% | 0% | Clean networks (FEC disabled) |
| `8, 2` | ~20% | ~25% | Moderate packet loss |
| `12, 4` | ~25% | ~33% | High packet loss (default) |
| `16, 4` | ~20% | ~25% | Very high throughput |

**Note:** Client and server MUST use identical FEC parameters.

---

## 🔧 Packaging from Source

### Build Executables

```bash
# Install packaging dependencies
pip install pyinstaller

# Run the build script
python build.py

# Output: dist/LightconeManager.exe (Windows) or dist/LightconeManager (Linux)
```

### Manual Build (Windows)

```bash
pyinstaller --onefile --windowed --name LightconeManager \
    --add-data "lightcone-tunnel.py;." \
    --collect-all nicegui \
    --hidden-import cryptography \
    --hidden-import cryptography.hazmat.primitives.ciphers.aead \
    --hidden-import zfec \
    lightcone-manager.py
```

### Manual Build (Linux)

```bash
pyinstaller --onefile --windowed --name LightconeManager \
    --add-data "lightcone-tunnel.py:." \
    --collect-all nicegui \
    --hidden-import cryptography \
    --hidden-import cryptography.hazmat.primitives.ciphers.aead \
    --hidden-import zfec \
    lightcone-manager.py
```

### Prerequisites for Linux Native GUI (Optional)

If you want native window support (instead of browser mode):

```bash
# System dependencies
sudo apt install python3-gi python3-gi-cairo gir1.2-gtk-3.0 gir1.2-webkit2-4.1

# Python dependencies
pip install pywebview[gtk]
```

---

## 📊 Performance

### Bandwidth Impact (Burst Mode)

| Scenario | Throughput | Latency Impact |
| :--- | :--- | :--- |
| No jitter | Physical bandwidth limit | None |
| Burst Mode (12 packets, 0.1-0.3ms) | ~320 Mbps+ | Minimal |

### FEC Overhead

| Configuration | Overhead | Recovery Capability |
| :--- | :--- | :--- |
| N=12, M=4 | ~33% | Up to 25% packet loss |
| N=8, M=2 | ~25% | Up to 20% packet loss |

---

## 🔍 Verification

```bash
# Check server UDP binding
ss -ulpn | grep 8443

# Test SOCKS5 proxy
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me

# Test HTTP proxy
curl -x http://127.0.0.1:8080 https://ifconfig.me
```

---

## 🐛 Troubleshooting

### GUI won't start on Linux
```bash
# Ensure XDG_RUNTIME_DIR is set
export XDG_RUNTIME_DIR=/run/user/$(id -u)

# Run with browser mode (if native fails)
# (GUI already uses browser mode by default in packaged builds)
```

### "Port already in use" error
```bash
# Check what's using the port
ss -tulpn | grep 1080
# Change socks_port in config file
```

### FEC decode timeouts appear frequently
- Increase `fec_decode_timeout` (not yet exposed in GUI config form; can be adjusted in source for now)
- Or adjust FEC parameters to match your network conditions

### Tunnel runs but no traffic passes
- Verify PSK matches on both client and server
- Check firewall allows UDP on configured port
- Confirm server's `server_addr` is reachable (client resolves via DDNS)

---

## 📝 Version History

| Version | Key Changes |
| :--- | :--- |
| **v1.2.4** | GUI: single-instance lock, exit confirmation, @ui.refreshable refactor, multiprocessing guard |
| **v1.2.3** | GUI: browser mode (no pywebview dependency), automatic browser launch |
| **v1.2.2** | GUI: Linux native window support (pywebview), build system fixes |
| **v1.2.1** | GUI: cross-platform packaging, configurable FEC, multi-language |
| **v1.2.0** | RS-FEC anti-packet-loss engine, 64-bit Group ID |
| **v1.1.6** | Full path Burst Mode (TCP + UDP) |
| **v1.1.5** | Anti-DPI: removed MAGIC_BYTES, dynamic payload sizing |
| **v1.1.0** | Initial release |

---

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request.

### Development Setup

```bash
git clone https://github.com/u3dsteve/lightcone-tunnel
cd lightcone-tunnel
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-gui.txt
pip install pyinstaller
```

### Code Style
- Follow PEP 8
- Keep core tunnel engine single-file (`lightcone-tunnel.py`)
- GUI should be a separate module (`lightcone-manager.py`)
- Use English comments for main code logic

---

## 📄 License

MIT License — see [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

Built by network engineers who migrate machines and secure networks — shared for everyone who does the same.
