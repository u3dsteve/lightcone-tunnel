# Lightcone Tunnel v1.2.0 Deployment Guide



This guide details the deployment of Lightcone Tunnel v1.2.0 on Linux environments using standard `systemd` services or Docker containers.

---

## Environment & Prerequisites



Python 3.9+ and essential cryptographic/FEC dependencies are required.

* **Operating System**: Linux (Ubuntu 20.04+, Debian 11+, RHEL 8+)


* **Python Runtime**: Python 3.9 or higher


* **Python Dependencies**: `cryptography`, `pyyaml`, `zfec` (optional, recommended for hardware-accelerated RS-FEC)


* **Firewall Rules**:


* **Server**: Allow incoming UDP traffic on port `8443`.


* **Client**: Expose local TCP/UDP port `1080` (SOCKS5) and TCP port `8080` (HTTP Proxy).





---

## Key Features



* **AEAD Security**: ChaCha20-Poly1305 authenticated encryption with anti-replay protection.


* **RS-FEC Anti-Packet-Loss Engine (v1.2.0)**: Reed-Solomon Forward Error Correction with 64-bit Group ID framing, active zero-latency delivery, `zfec` C-extension acceleration, and automatic pure Python XOR fallback.
* **Full-Cone NAT UDP Forwarding**: Full UDP associate support with symmetric NAT traversal.


* **IPv6 Dual-Stack Support**: Seamlessly handles both IPv4 and IPv6 addresses.


* **DDNS Resilience**: Automatic background DNS resolution refreshes every 60 seconds.


* **Anti-DPI Traffic Obfuscation**:


* No fixed protocol signatures (randomized per-packet 4-byte prefix)


* Dynamic payload size randomization (800-1200 bytes per chunk)


* Burst-mode packet scheduling with micro-second jitter (0.1-0.3ms per 12 packets)




* **Resource Auto-Reclamation**: Idle TCP streams, UDP sessions, and stale FEC group decoders are automatically cleaned up.



---

## Configuration Reference



### Client Config (`config_client.yaml`)



```yaml
role: "client"
psk: "YourSuperSecretPassphrase321"     # Must match server exactly
server_addr: "tunnel.example.com:8443"  # Server endpoint (supports DDNS)
socks_port: 1080                        # SOCKS5 proxy port
http_port: 8080                         # HTTP/HTTPS CONNECT proxy port

# RS-FEC (Reed-Solomon Forward Error Correction) Settings
# Set both to 0 to disable. Both client and server MUST use identical settings.
fec_data_shards: 10                     # Number of data shards (N)
fec_parity_shards: 3                    # Number of parity shards (M)

max_concurrent_streams: 1024            # Concurrent stream limit
log_level: "info"                       # debug | info

```

### Server Config (`config_server.yaml`)



```yaml
role: "server"
psk: "YourSuperSecretPassphrase321"     # Must match client exactly
server_addr: "0.0.0.0:8443"             # Listen on all interfaces

# RS-FEC (Reed-Solomon Forward Error Correction) Settings
# Must match client settings for successful payload reconstruction.
fec_data_shards: 10                     # Number of data shards (N)
fec_parity_shards: 3                    # Number of parity shards (M)

max_concurrent_streams: 1024            # Concurrent stream limit
log_level: "info"                       # debug | info

```

> **Note:** Hard memory bounds should be configured via Systemd `MemoryMax=` or Docker `--memory` at the host level for production stability.
> 
> 

---

## Method 1: Native Systemd Deployment



### 1. Install Dependencies



Run the following command on both Server and Client nodes:

```bash
pip3 install cryptography pyyaml zfec

```

### 2. File Setup



Place the script and configuration files in `/opt/lightcone/`:

```bash
sudo mkdir -p /opt/lightcone
sudo cp lightcone-tunnel.py /opt/lightcone/lightcone-tunnel.py
sudo chmod +x /opt/lightcone/lightcone-tunnel.py

```

Place `config_server.yaml` on the server node and `config_client.yaml` on the client node inside `/opt/lightcone/`.

### 3. Server Systemd Service



Create `/etc/systemd/system/lightcone-server.service`:

```ini
[Unit]
Description=Lightcone Tunnel Server Engine
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/lightcone
ExecStart=/usr/bin/python3 /opt/lightcone/lightcone-tunnel.py /opt/lightcone/config_server.yaml
Restart=always
RestartSec=3
LimitNOFILE=65535
# Optional memory limit
# MemoryMax=512M

[Install]
WantedBy=multi-user.target

```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now lightcone-server
sudo systemctl status lightcone-server

```

### 4. Client Systemd Service



Create `/etc/systemd/system/lightcone-client.service`:

```ini
[Unit]
Description=Lightcone Tunnel Client Engine
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/lightcone
ExecStart=/usr/bin/python3 /opt/lightcone/lightcone-tunnel.py /opt/lightcone/config_client.yaml
Restart=always
RestartSec=3
LimitNOFILE=65535
# Optional memory limit
# MemoryMax=256M

[Install]
WantedBy=multi-user.target

```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now lightcone-client
sudo systemctl status lightcone-client

```

---

## Method 2: Docker & Docker Compose Deployment



### 1. Dockerfile



Create a single `Dockerfile` in your working directory:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir cryptography pyyaml zfec

COPY lightcone-tunnel.py /app/lightcone-tunnel.py

ENTRYPOINT ["python3", "/app/lightcone-tunnel.py"]

```

### 2. Docker Compose (`docker-compose.yml`)



Deploy using `host` network mode for lower UDP latency and full SOCKS5 UDP Associate support.

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

### 3. Run Services



```bash
# Build and run server
docker compose up -d --build lightcone-server

# Build and run client
docker compose up -d --build lightcone-client

# View live logs
docker compose logs -f

```

---

## Verification & Connectivity Test



Verify operational status directly via proxy requests.

1. **Verify Server UDP Port Binding**:



```bash
ss -ulpn | grep 8443

```

2. **Test SOCKS5 TCP Connectivity**:



```bash
curl -x socks5h://127.0.0.1:1080 https://ifconfig.me

```

3. **Test HTTP Proxy Connectivity**:



```bash
curl -x http://127.0.0.1:8080 https://ifconfig.me

```

---

## Version History



| Version | Key Changes |
| --- | --- |
| v1.2.0 | Production Release: RS-FEC Anti-Packet-Loss engine (`zfec`/XOR fallback), 64-bit Group ID binary headers, and FEC YAML parameters |
| v1.1.6 | Full path Burst Mode coverage (TCP + UDP both directions); all data paths now include anti-DPI jitter

 |
| v1.1.5 | Anti-DPI features: removed MAGIC_BYTES, dynamic payload sizing, TCP Burst Mode jitter

 |
| v1.1.4 | Configurable `max_concurrent_streams` via YAML; removed `RLIMIT_AS` memory hard limit

 |
| v1.1.3 | Client UDP session idle reclamation; shebang fix

 |
| v1.1.2 | SOCKS5 UDP Associate & Server NAT rate-limit shielding

 |
| v1.1.1 | Naked IPv6 parsing fix; rate-limit hardening; cold-start guard

 |

---

## Troubleshooting



### Issue: High latency or low throughput



* **Cause**: Congested network or overly aggressive Burst Mode settings.


* **Solution**: Adjust `BURST_PACKET_COUNT` and `BURST_SLEEP_MAX` in the source code if needed.



### Issue: "Connection refused" on SOCKS5/HTTP port



* **Check**: Ensure `socks_port` and `http_port` are not already in use:



```bash
ss -tulpn | grep -E "1080|8080"

```

### Issue: "DDNS Target IP updated" log messages appear frequently



* **This is normal**: The client refreshes DNS every 60 seconds. If the IP changes, the tunnel automatically switches to the new endpoint without restart.



### Issue: Server not receiving traffic



* **Check**: Firewall rules on the server must allow UDP traffic on the configured port:



```bash
sudo iptables -L -n | grep 8443

```
