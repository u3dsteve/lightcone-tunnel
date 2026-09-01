#!/usr/bin/env python3
"""
Lightcone Tunnel - High-Performance Anti-DPI UDP Tunnel & Proxy Solution
Single-file executable supporting Client (SOCKS5/HTTP Proxy) & Server (Full-Cone NAT Forwarder)
Production Release v1.2.3 (Added NAT Keep-Alive Heartbeat, StreamAssembler & Fixed TCP Blackhole)
"""

import argparse
import asyncio
import hashlib
import logging
import os
import random
import resource
import socket
import struct
import sys
import time
from typing import Dict, Tuple, Optional, Set, List
from urllib.parse import urlparse
import yaml

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

try:
    import zfec
except ImportError:
    zfec = None


# ============================================================================
# Constants & Protocol Configuration
# ============================================================================
CMD_TCP_DATA  = 0x01
CMD_TCP_CLOSE = 0x02
CMD_UDP_DATA  = 0x03
CMD_HEARTBEAT = 0x04           # NAT Keep-alive heartbeat

ATYP_IPV4   = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6   = 0x04

MAX_PAYLOAD_SIZE = 1000        # Shrink to 1000 to prevent UDP MTU IP fragmentation drop
TIMESTAMP_TOLERANCE_SEC = 30.0 # Time sync window tolerance
IDLE_TIMEOUT_SEC = 300.0       # Resource auto-reclamation timeout (5 mins)
CONNECT_TIMEOUT_SEC = 10.0     # Connection timeout to prevent infinite wait trap
HEARTBEAT_INTERVAL_SEC = 20.0  # NAT Keep-alive interval (prevent router NAT expiration)
DEFAULT_MAX_CONCURRENT_STREAMS = 1024 # Default fallback application rate-limiting threshold

BURST_PACKET_COUNT = 12        # Send N packets continuously before applying micro-sleep
BURST_SLEEP_MIN = 0.0001       # Min micro-sleep duration (0.1ms)
BURST_SLEEP_MAX = 0.0003       # Max micro-sleep duration (0.3ms)


def get_chunk_size() -> int:
    return random.randint(800, MAX_PAYLOAD_SIZE)


# ============================================================================
# Crypto, Nonce Safety & Sliding-Window Anti-Replay Shield
# ============================================================================
class TunnelSecurity:
    def __init__(self, psk: str):
        key = hashlib.sha256(psk.encode('utf-8')).digest()
        self.cipher = ChaCha20Poly1305(key)
        self.seen_sequences: Dict[int, float] = {}
        self.seq_counter = 0

    def pack_and_encrypt(self, payload: bytes) -> bytes:
        self.seq_counter = (self.seq_counter + 1) & 0xFFFFFFFFFFFFFFFF
        timestamp = int(time.time())
        
        pad_len = os.urandom(1)[0] % 16
        padding = os.urandom(pad_len)
        
        random_prefix = os.urandom(4)
        meta_header = random_prefix + struct.pack("!QQB", self.seq_counter, timestamp, pad_len)
        
        nonce = struct.pack("!IQ", timestamp & 0xFFFFFFFF, self.seq_counter)
        encrypted_payload = self.cipher.encrypt(nonce, payload + padding, meta_header)
        
        return meta_header + nonce + encrypted_payload

    def decrypt_and_unpack(self, datagram: bytes) -> Optional[bytes]:
        if len(datagram) < 21 + 12 + 16:
            return None

        meta_header = datagram[:21]
        nonce = datagram[21:33]
        ciphertext = datagram[33:]

        seq, timestamp, pad_len = struct.unpack("!QQB", meta_header[4:])

        now = time.time()
        if abs(now - timestamp) > TIMESTAMP_TOLERANCE_SEC:
            return None

        if seq in self.seen_sequences:
            return None
        self.seen_sequences[seq] = now

        if len(self.seen_sequences) > 2000:
            expired = [s for s, t in self.seen_sequences.items() if now - t > TIMESTAMP_TOLERANCE_SEC]
            for s in expired:
                del self.seen_sequences[s]

        try:
            decrypted = self.cipher.decrypt(nonce, ciphertext, meta_header)
            if pad_len > 0:
                decrypted = decrypted[:-pad_len]
            return decrypted
        except Exception:
            return None


# ============================================================================
# FEC (Forward Error Correction) Reed-Solomon Engine
# ============================================================================
class FECGroupEncoder:
    def __init__(self, data_shards: int, parity_shards: int):
        self.n = data_shards
        self.m = parity_shards
        self.group_id = 0
        self.buffer: List[bytes] = []
        self.last_act = time.time()

    def input_packet(self, ciphertext: bytes) -> List[bytes]:
        if self.n <= 0 or self.m <= 0:
            return [ciphertext]

        now = time.time()
        out_packets = []

        if self.buffer and (now - self.last_act > 0.020):
            out_packets.extend(self._flush_parity())

        self.last_act = now
        idx = len(self.buffer)
        self.buffer.append(ciphertext)

        header = struct.pack("!QBBBH", self.group_id, idx, self.n, self.m, len(ciphertext))
        out_packets.append(header + ciphertext)

        if len(self.buffer) == self.n:
            out_packets.extend(self._flush_parity())

        return out_packets

    def _flush_parity(self) -> List[bytes]:
        if not self.buffer:
            return []
        
        out_packets = []
        max_len = max(len(p) for p in self.buffer)
        
        padded_shards = [p.ljust(max_len, b'\x00') for p in self.buffer]
        while len(padded_shards) < self.n:
            padded_shards.append(b'\x00' * max_len)

        if zfec:
            encoder = zfec.Encoder(self.n, self.n + self.m)
            parity_blocks = encoder.encode(padded_shards)
        else:
            xor_block = bytearray(max_len)
            for shard in padded_shards:
                for i in range(max_len):
                    xor_block[i] ^= shard[i]
            parity_blocks = [bytes(xor_block)] * self.m

        for p_idx, p_data in enumerate(parity_blocks, start=self.n):
            header = struct.pack("!QBBBH", self.group_id, p_idx, self.n, self.m, max_len)
            out_packets.append(header + p_data)

        self.group_id = (self.group_id + 1) & 0xFFFFFFFFFFFFFFFF
        self.buffer.clear()
        return out_packets


class FECGroupDecoder:
    def __init__(self, timeout_sec: float = 3.0):
        self.groups: Dict[Tuple[object, int], Dict] = {}
        self.timeout_sec = timeout_sec

    def process_datagram(self, peer_addr: object, datagram: bytes, fec_enabled: bool) -> List[bytes]:
        if not fec_enabled or len(datagram) < 13:
            return [datagram]

        group_id, idx, n, m, raw_len = struct.unpack("!QBBBH", datagram[:13])
        payload = datagram[13:]
        now = time.time()

        key = (peer_addr, group_id)
        if key not in self.groups:
            self.groups[key] = {
                'shards': {},
                'raw_lens': {},
                'n': n,
                'm': m,
                'time': now
            }

        grp = self.groups[key]
        grp['shards'][idx] = payload
        grp['raw_lens'][idx] = raw_len

        recovered = []

        if idx < n:
            recovered.append(payload[:raw_len])

        received_data_indices = {i for i in grp['shards'].keys() if i < n}
        total_received = len(grp['shards'])

        if len(received_data_indices) < n and total_received >= n:
            max_len = max(len(s) for s in grp['shards'].values())
            
            src_shards = []
            src_indices = []

            for s_idx, s_bytes in sorted(grp['shards'].items())[:n]:
                src_shards.append(s_bytes.ljust(max_len, b'\x00'))
                src_indices.append(s_idx)

            if zfec:
                decoder = zfec.Decoder(n, n + m)
                decoded_shards = decoder.decode(src_shards, src_indices)
                
                for d_idx, d_data in enumerate(decoded_shards):
                    if d_idx not in received_data_indices:
                        orig_len = grp['raw_lens'].get(d_idx, max_len)
                        if orig_len > 0:
                            recovered.append(d_data[:orig_len])

            self.groups.pop(key, None)

        elif len(received_data_indices) == n:
            self.groups.pop(key, None)

        return recovered

    def sweep_stale_groups(self):
        now = time.time()
        stale_keys = [k for k, v in self.groups.items() if now - v['time'] > self.timeout_sec]
        for k in stale_keys:
            self.groups.pop(k, None)


# ============================================================================
# Binary Multiplexing Frame Protocol Encoder / Decoder & Stream Assembler
# ============================================================================
class StreamAssembler:
    def __init__(self):
        self.writer = None
        self.expected_seq = 0
        self.buffer = {}
        self.connecting = True

    def set_writer(self, writer):
        self.writer = writer
        self.connecting = False
        self.flush()

    def receive(self, seq: int, payload: bytes):
        if seq >= self.expected_seq:
            if len(self.buffer) < 1024:
                self.buffer[seq] = payload
        self.flush()

    def flush(self):
        if not self.writer or self.connecting:
            return
        while self.expected_seq in self.buffer:
            data = self.buffer.pop(self.expected_seq)
            if data:
                try:
                    self.writer.write(data)
                except Exception as e:
                    pass
            self.expected_seq += 1

    def close(self):
        if self.writer:
            try:
                self.writer.close()
            except Exception:
                pass


class MultiplexFrame:
    @staticmethod
    def pack(stream_id: int, cmd: int, atyp: int, seq: int, host: str, port: int, payload: bytes) -> bytes:
        header = struct.pack("!IBBI", stream_id, cmd, atyp, seq)
        if atyp == ATYP_IPV4:
            addr_bytes = socket.inet_aton(host) + struct.pack("!H", port)
        elif atyp == ATYP_DOMAIN:
            host_bytes = host.encode('utf-8')
            addr_bytes = struct.pack("!B", len(host_bytes)) + host_bytes + struct.pack("!H", port)
        elif atyp == ATYP_IPV6:
            addr_bytes = socket.inet_pton(socket.AF_INET6, host) + struct.pack("!H", port)
        else:
            addr_bytes = b""
        return header + addr_bytes + payload

    @staticmethod
    def unpack(data: bytes) -> Tuple[int, int, int, int, str, int, bytes]:
        stream_id, cmd, atyp, seq = struct.unpack("!IBBI", data[:10])
        idx = 10
        host, port = "", 0

        if atyp == ATYP_IPV4:
            host = socket.inet_ntoa(data[idx:idx+4])
            port = struct.unpack("!H", data[idx+4:idx+6])[0]
            idx += 6
        elif atyp == ATYP_DOMAIN:
            d_len = data[idx]
            idx += 1
            host = data[idx:idx+d_len].decode('utf-8')
            idx += d_len
            port = struct.unpack("!H", data[idx:idx+2])[0]
            idx += 2
        elif atyp == ATYP_IPV6:
            host = socket.inet_ntop(socket.AF_INET6, data[idx:idx+16])
            port = struct.unpack("!H", data[idx+16:idx+18])[0]
            idx += 18

        return stream_id, cmd, atyp, seq, host, port, data[idx:]


# ============================================================================
# Client Engine: SOCKS5 (TCP/UDP Associate) & HTTP Ingress
# ============================================================================
class ClientEngine:
    def __init__(self, config: dict):
        self.config = config
        self.max_concurrent_streams = config.get("max_concurrent_streams", DEFAULT_MAX_CONCURRENT_STREAMS)
        self.sec = TunnelSecurity(config["psk"])
        self.server_host, self.server_port = config["server_addr"].split(":")
        self.server_port = int(self.server_port)
        self.server_ip = None
        
        self.fec_data_shards = config.get("fec_data_shards", 0)
        self.fec_parity_shards = config.get("fec_parity_shards", 0)
        self.fec_enabled = self.fec_data_shards > 0 and self.fec_parity_shards > 0
        self.fec_encoder = FECGroupEncoder(self.fec_data_shards, self.fec_parity_shards) if self.fec_enabled else None
        self.fec_decoder = FECGroupDecoder()

        self.streams: Dict[int, Tuple[StreamAssembler, float]] = {}
        self.udp_sessions: Dict[int, Tuple[Tuple[str, int], asyncio.DatagramTransport, float]] = {}
        
        self.next_stream_id = 1
        self.transport = None

    async def resolve_ddns_once(self):
        try:
            info = await asyncio.to_thread(socket.getaddrinfo, self.server_host, self.server_port)
            if info:
                new_ip = info[0][4][0]
                if new_ip != self.server_ip:
                    logging.info(f"[DDNS] Target IP updated: {self.server_host} -> {new_ip}")
                    self.server_ip = new_ip
                else:
                    logging.info(f"[DDNS] IP unchanged: {self.server_host} -> {new_ip}")
            else:
                logging.warning(f"[DDNS] No address found for {self.server_host}")
        except Exception as e:
            logging.warning(f"[DDNS] Resolution failed for {self.server_host}: {e}")

    async def resolve_ddns(self):
        while True:
            await self.resolve_ddns_once()
            if self.server_ip:
                logging.debug(f"[DDNS] Current server IP: {self.server_ip}")
            await asyncio.sleep(60)

    async def heartbeat_loop(self):
        """Periodically ping the server to keep the router's NAT UDP mapping alive."""
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL_SEC)
            if self.server_ip and self.transport:
                try:
                    # stream_id=0, seq=0, host="0.0.0.0", port=0
                    frame = MultiplexFrame.pack(0, CMD_HEARTBEAT, ATYP_IPV4, 0, "0.0.0.0", 0, b"")
                    self.send_to_server(frame)
                except Exception as e:
                    logging.debug(f"[Heartbeat] Error: {e}")

    async def cleanup_idle_loop(self):
        while True:
            await asyncio.sleep(30)
            now = time.time()
            stale_streams = [sid for sid, (_, last_act) in list(self.streams.items()) if now - last_act > IDLE_TIMEOUT_SEC]
            for sid in stale_streams:
                conn = self.streams.pop(sid, None)
                if conn:
                    assembler, _ = conn
                    assembler.close()
                    logging.debug(f"[Clean Sweep] Closed idle client TCP stream {sid}")

            stale_udp_sessions = [sid for sid, (_, _, last_act) in list(self.udp_sessions.items()) if now - last_act > IDLE_TIMEOUT_SEC]
            for sid in stale_udp_sessions:
                item = self.udp_sessions.pop(sid, None)
                if item:
                    item[1].close()
                    logging.debug(f"[Clean Sweep] Closed idle client UDP session {sid}")

            if self.fec_enabled:
                self.fec_decoder.sweep_stale_groups()

    async def handle_socks5(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        stream_id = None
        atyp = ATYP_IPV4
        host = ""
        port = 0
        udp_transport = None

        try:
            logging.info(f"[SOCKS5] New connection from {writer.get_extra_info('peername')}")
            ver, nmethods = struct.unpack("!BB", await reader.readexactly(2))
            await reader.readexactly(nmethods)
            writer.write(b"\x05\x00")
            await writer.drain()

            ver, cmd, _, atyp = struct.unpack("!BBBB", await reader.readexactly(4))
            
            if atyp == ATYP_IPV4:
                host = socket.inet_ntoa(await reader.readexactly(4))
            elif atyp == ATYP_DOMAIN:
                d_len = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(d_len)).decode('utf-8')
            elif atyp == ATYP_IPV6:
                host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
            port = struct.unpack("!H", await reader.readexactly(2))[0]

            if cmd == 0x01:  # TCP CONNECT
                if len(self.streams) >= self.max_concurrent_streams:
                    logging.warning("[SOCKS5] Concurrent stream limit reached, rejecting connection.")
                    writer.close()
                    return

                writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                
                stream_id = self.next_stream_id
                self.next_stream_id += 1
                
                assembler = StreamAssembler()
                assembler.set_writer(writer)
                self.streams[stream_id] = (assembler, time.time())
                seq = 0

                packet_counter = 0
                while True:
                    data = await reader.read(get_chunk_size())
                    if not data:
                        break
                    self.streams[stream_id] = (assembler, time.time())
                    frame = MultiplexFrame.pack(stream_id, CMD_TCP_DATA, atyp, seq, host, port, data)
                    self.send_to_server(frame)
                    seq += 1

                    packet_counter += 1
                    if packet_counter % BURST_PACKET_COUNT == 0:
                        await asyncio.sleep(random.uniform(BURST_SLEEP_MIN, BURST_SLEEP_MAX))

            elif cmd == 0x03:  # UDP ASSOCIATE
                if len(self.udp_sessions) >= self.max_concurrent_streams:
                    logging.warning("[SOCKS5 UDP] UDP session limit reached, rejecting.")
                    writer.close()
                    return

                loop = asyncio.get_running_loop()
                stream_id = self.next_stream_id
                self.next_stream_id += 1

                class Socks5UDPRelay(asyncio.DatagramProtocol):
                    def __init__(self, engine, sid):
                        self.engine = engine
                        self.sid = sid
                        self.packet_counter = 0
                        self.transport = None

                    def connection_made(self, transport):
                        self.transport = transport

                    def datagram_received(self, data, addr):
                        if len(data) < 10:
                            return
                        if len(data) > 1350:
                            logging.warning(f"[SOCKS5 UDP] Oversized UDP packet ({len(data)} bytes). May be dropped by MTU limits.")

                        rsv, frag, u_atyp = struct.unpack("!HBB", data[:4])
                        idx = 4
                        if u_atyp == ATYP_IPV4:
                            d_host = socket.inet_ntoa(data[idx:idx+4])
                            d_port = struct.unpack("!H", data[idx+4:idx+6])[0]
                            idx += 6
                        elif u_atyp == ATYP_DOMAIN:
                            d_len = data[idx]
                            idx += 1
                            d_host = data[idx:idx+d_len].decode('utf-8')
                            idx += d_len
                            d_port = struct.unpack("!H", data[idx:idx+2])[0]
                            idx += 2
                        elif u_atyp == ATYP_IPV6:
                            d_host = socket.inet_ntop(socket.AF_INET6, data[idx:idx+16])
                            d_port = struct.unpack("!H", data[idx+18:idx+18])[0]
                            idx += 18
                        else:
                            return

                        u_payload = data[idx:]
                        self.engine.udp_sessions[self.sid] = (addr, self.transport, time.time())

                        self.packet_counter += 1
                        current_count = self.packet_counter

                        async def send_burst_udp():
                            if current_count % BURST_PACKET_COUNT == 0:
                                await asyncio.sleep(random.uniform(BURST_SLEEP_MIN, BURST_SLEEP_MAX))
                            frame = MultiplexFrame.pack(self.sid, CMD_UDP_DATA, u_atyp, 0, d_host, d_port, u_payload)
                            self.engine.send_to_server(frame)

                        asyncio.create_task(send_burst_udp())

                udp_transport, _ = await loop.create_datagram_endpoint(
                    lambda: Socks5UDPRelay(self, stream_id), local_addr=("0.0.0.0", 0)
                )
                _, relay_port = udp_transport.get_extra_info("sockname")

                reply = struct.pack("!BBBB4sH", 0x05, 0x00, 0x00, 0x01, socket.inet_aton("127.0.0.1"), relay_port)
                writer.write(reply)
                await writer.drain()

                while await reader.read(1024):
                    pass

        except Exception as e:
            logging.error(f"[SOCKS5] Error handling client stream: {e}", exc_info=True)
        finally:
            writer.close()
            if udp_transport:
                udp_transport.close()
            if stream_id is not None:
                self.udp_sessions.pop(stream_id, None)
                if stream_id in self.streams:
                    self.streams.pop(stream_id, None)
                    try:
                        frame = MultiplexFrame.pack(stream_id, CMD_TCP_CLOSE, atyp, 0, host, port, b"")
                        self.send_to_server(frame)
                    except Exception:
                        pass

    async def handle_http_proxy(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        logging.info(f"[HTTP] New connection from {writer.get_extra_info('peername')}")
        stream_id = None
        atyp = ATYP_DOMAIN
        host = ""
        port = 80

        try:
            header_line = await reader.readline()
            if not header_line:
                return
            
            parts = header_line.decode('utf-8', errors='ignore').split()
            if len(parts) < 2:
                return

            if len(self.streams) >= self.max_concurrent_streams:
                logging.warning("[HTTP Proxy] Concurrent stream limit reached, rejecting connection.")
                writer.close()
                return

            method, url = parts[0], parts[1]
            stream_id = self.next_stream_id
            self.next_stream_id += 1

            if method == "CONNECT":
                if url.startswith("["):
                    end_idx = url.find("]")
                    if end_idx != -1:
                        host = url[1:end_idx]
                        rest = url[end_idx+1:]
                        port = int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else 443
                        atyp = ATYP_IPV6
                    else:
                        return
                else:
                    is_ipv6_raw = False
                    try:
                        socket.inet_pton(socket.AF_INET6, url)
                        host = url
                        port = 443
                        atyp = ATYP_IPV6
                        is_ipv6_raw = True
                    except socket.error:
                        pass

                    if not is_ipv6_raw:
                        if url.count(":") > 1:
                            host_part, port_part = url.rsplit(":", 1)
                            if port_part.isdigit():
                                try:
                                    socket.inet_pton(socket.AF_INET6, host_part)
                                    host = host_part
                                    port = int(port_part)
                                    atyp = ATYP_IPV6
                                    is_ipv6_raw = True
                                except socket.error:
                                    pass
                        if not is_ipv6_raw:
                            if ":" in url:
                                host, port_str = url.rsplit(":", 1)
                                port = int(port_str) if port_str.isdigit() else 443
                                try:
                                    socket.inet_aton(host)
                                    atyp = ATYP_IPV4
                                except socket.error:
                                    atyp = ATYP_DOMAIN
                            else:
                                host = url
                                port = 443
                                try:
                                    socket.inet_aton(host)
                                    atyp = ATYP_IPV4
                                except socket.error:
                                    atyp = ATYP_DOMAIN

                while True:
                    line = await reader.readline()
                    if line in (b"\r\n", b"\n", b""):
                        break
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
                seq = 0
            else:
                parsed = urlparse(url)
                host = parsed.hostname or ""
                port = parsed.port or 80
                
                if host.startswith("[") and host.endswith("]"):
                    host = host[1:-1]
                    atyp = ATYP_IPV6
                else:
                    try:
                        socket.inet_aton(host)
                        atyp = ATYP_IPV4
                    except socket.error:
                        try:
                            socket.inet_pton(socket.AF_INET6, host)
                            atyp = ATYP_IPV6
                        except socket.error:
                            atyp = ATYP_DOMAIN
                
                seq = 0
                frame = MultiplexFrame.pack(stream_id, CMD_TCP_DATA, atyp, seq, host, port, header_line)
                self.send_to_server(frame)
                seq += 1

            assembler = StreamAssembler()
            assembler.set_writer(writer)
            self.streams[stream_id] = (assembler, time.time())

            packet_counter = 0
            while True:
                data = await reader.read(get_chunk_size())
                if not data:
                    break
                self.streams[stream_id] = (assembler, time.time())
                frame = MultiplexFrame.pack(stream_id, CMD_TCP_DATA, atyp, seq, host, port, data)
                self.send_to_server(frame)
                seq += 1

                packet_counter += 1
                if packet_counter % BURST_PACKET_COUNT == 0:
                    await asyncio.sleep(random.uniform(BURST_SLEEP_MIN, BURST_SLEEP_MAX))

        except Exception as e:
            logging.error(f"[HTTP Proxy] Error handling client stream: {e}", exc_info=True)
        finally:
            writer.close()
            if stream_id is not None and stream_id in self.streams:
                self.streams.pop(stream_id, None)
                try:
                    frame = MultiplexFrame.pack(stream_id, CMD_TCP_CLOSE, atyp, 0, host, port, b"")
                    self.send_to_server(frame)
                except Exception:
                    pass

    def send_to_server(self, payload: bytes):
        if self.server_ip and self.transport:
            encrypted = self.sec.pack_and_encrypt(payload)
            if self.fec_enabled and self.fec_encoder:
                packets = self.fec_encoder.input_packet(encrypted)
                for pkt in packets:
                    self.transport.sendto(pkt, (self.server_ip, self.server_port))
            else:
                self.transport.sendto(encrypted, (self.server_ip, self.server_port))

    async def start(self):
        loop = asyncio.get_running_loop()
        await self.resolve_ddns_once()
        asyncio.create_task(self.resolve_ddns())
        asyncio.create_task(self.cleanup_idle_loop())
        asyncio.create_task(self.heartbeat_loop())  # Start heartbeat

        class ClientUDPProtocol(asyncio.DatagramProtocol):
            def __init__(self, client_engine):
                self.engine = client_engine
                self.transport = None

            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                payloads = self.engine.fec_decoder.process_datagram(addr, data, self.engine.fec_enabled)
                for decrypted_pkt in payloads:
                    decrypted = self.engine.sec.decrypt_and_unpack(decrypted_pkt)
                    if not decrypted:
                        continue
                    
                    try:
                        stream_id, cmd, atyp, seq, r_host, r_port, payload = MultiplexFrame.unpack(decrypted)
                    except Exception as e:
                        logging.debug(f"[Client Multiplex] Dropped malformed frame: {e}")
                        continue
                    
                    if cmd == CMD_TCP_DATA and stream_id in self.engine.streams:
                        assembler, _ = self.engine.streams[stream_id]
                        self.engine.streams[stream_id] = (assembler, time.time())
                        assembler.receive(seq, payload)

                    elif cmd == CMD_UDP_DATA and stream_id in self.engine.udp_sessions:
                        cli_addr, udp_trans, _ = self.engine.udp_sessions[stream_id]
                        self.engine.udp_sessions[stream_id] = (cli_addr, udp_trans, time.time())
                        
                        if atyp == ATYP_IPV4:
                            addr_bytes = socket.inet_aton(r_host)
                        elif atyp == ATYP_IPV6:
                            addr_bytes = socket.inet_pton(socket.AF_INET6, r_host)
                        else:
                            host_bytes = r_host.encode('utf-8')
                            addr_bytes = struct.pack("!B", len(host_bytes)) + host_bytes
                            
                        socks_hdr = struct.pack("!HBB", 0, 0, atyp) + addr_bytes + struct.pack("!H", r_port)
                        udp_trans.sendto(socks_hdr + payload, cli_addr)

                    elif cmd == CMD_TCP_CLOSE and stream_id in self.engine.streams:
                        conn = self.engine.streams.pop(stream_id, None)
                        if conn:
                            conn[0].close()
                    
                    elif cmd == CMD_HEARTBEAT:
                        pass  # Ignored on purpose

        transport, _ = await loop.create_datagram_endpoint(
            lambda: ClientUDPProtocol(self), local_addr=("0.0.0.0", 0)
        )
        self.transport = transport
        logging.info(f"[START] UDP transport initialized: {self.transport}")

        socks_port = self.config.get("socks_port", 1080)
        http_port = self.config.get("http_port", 8080)

        socks_srv = await asyncio.start_server(self.handle_socks5, "0.0.0.0", socks_port)
        http_srv = await asyncio.start_server(self.handle_http_proxy, "0.0.0.0", http_port)

        logging.info(f"[Lightcone Client] SOCKS5 listening on 0.0.0.0:{socks_port}")
        logging.info(f"[Lightcone Client] HTTP Proxy listening on 0.0.0.0:{http_port}")
        logging.info(f"[Lightcone Client] Concurrent Streams Limit: {self.max_concurrent_streams}")
        if self.fec_enabled:
            logging.info(f"[Lightcone Client] RS-FEC Protection Online (N={self.fec_data_shards}, M={self.fec_parity_shards})")

        await asyncio.gather(socks_srv.serve_forever(), http_srv.serve_forever())


# ============================================================================
# Server Engine: Outbound Forwarding & Full-Cone NAT Sweeper
# ============================================================================
class ServerEngine:
    def __init__(self, config: dict):
        self.config = config
        self.max_concurrent_streams = config.get("max_concurrent_streams", DEFAULT_MAX_CONCURRENT_STREAMS)
        self.sec = TunnelSecurity(config["psk"])

        self.fec_data_shards = config.get("fec_data_shards", 0)
        self.fec_parity_shards = config.get("fec_parity_shards", 0)
        self.fec_enabled = self.fec_data_shards > 0 and self.fec_parity_shards > 0
        self.fec_encoders: Dict[Tuple[str, int], FECGroupEncoder] = {}
        self.fec_decoder = FECGroupDecoder()

        self.tcp_connections: Dict[int, Tuple[StreamAssembler, float]] = {}
        self.udp_nat_table: Dict[int, Tuple[asyncio.DatagramProtocol, float]] = {}

    def send_to_client(self, transport, client_addr, payload: bytes):
        encrypted = self.sec.pack_and_encrypt(payload)
        if self.fec_enabled:
            if client_addr not in self.fec_encoders:
                self.fec_encoders[client_addr] = FECGroupEncoder(self.fec_data_shards, self.fec_parity_shards)
            encoder = self.fec_encoders[client_addr]
            packets = encoder.input_packet(encrypted)
            for pkt in packets:
                transport.sendto(pkt, client_addr)
        else:
            transport.sendto(encrypted, client_addr)

    async def cleanup_idle_loop(self):
        while True:
            await asyncio.sleep(30)
            now = time.time()
            
            stale_tcp = [sid for sid, (_, last_act) in list(self.tcp_connections.items()) if now - last_act > IDLE_TIMEOUT_SEC]
            for sid in stale_tcp:
                conn = self.tcp_connections.pop(sid, None)
                if conn:
                    conn[0].close()
                    logging.debug(f"[Server Clean] Closed zombie TCP connection {sid}")

            stale_udp = [sid for sid, (_, last_act) in list(self.udp_nat_table.items()) if now - last_act > IDLE_TIMEOUT_SEC]
            for sid in stale_udp:
                item = self.udp_nat_table.pop(sid, None)
                if item:
                    item[0].close()
                    logging.debug(f"[Server Clean] Closed stale UDP NAT mapping {sid}")

            if self.fec_enabled:
                self.fec_decoder.sweep_stale_groups()

    def process_tcp_data(self, stream_id: int, atyp: int, seq: int, host: str, port: int, payload: bytes, transport, client_addr):
        now = time.time()
        
        if stream_id not in self.tcp_connections:
            if len(self.tcp_connections) >= self.max_concurrent_streams:
                logging.warning(f"[Server Outbound] Connection limit reached, dropping stream {stream_id}")
                return
            
            assembler = StreamAssembler()
            self.tcp_connections[stream_id] = (assembler, now)
            
            asyncio.create_task(self._connect_and_pipe(stream_id, atyp, host, port, transport, client_addr))
            
        conn = self.tcp_connections.get(stream_id)
        if conn:
            assembler = conn[0]
            self.tcp_connections[stream_id] = (assembler, now)
            assembler.receive(seq, payload)

    async def _connect_and_pipe(self, stream_id, atyp, host, port, transport, client_addr):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=CONNECT_TIMEOUT_SEC
            )
        except Exception as e:
            logging.debug(f"[Server] TCP out failed {host}:{port} - {e}")
            self.tcp_connections.pop(stream_id, None)
            frame = MultiplexFrame.pack(stream_id, CMD_TCP_CLOSE, atyp, 0, host, port, b"")
            self.send_to_client(transport, client_addr, frame)
            return

        conn = self.tcp_connections.get(stream_id)
        if conn:
            assembler = conn[0]
            assembler.set_writer(writer)
        else:
            writer.close()
            return

        seq = 0
        packet_counter = 0
        try:
            while True:
                resp = await reader.read(get_chunk_size())
                if not resp:
                    break
                
                if stream_id in self.tcp_connections:
                    self.tcp_connections[stream_id] = (self.tcp_connections[stream_id][0], time.time())
                    
                frame = MultiplexFrame.pack(stream_id, CMD_TCP_DATA, atyp, seq, host, port, resp)
                self.send_to_client(transport, client_addr, frame)
                seq += 1

                packet_counter += 1
                if packet_counter % BURST_PACKET_COUNT == 0:
                    await asyncio.sleep(random.uniform(BURST_SLEEP_MIN, BURST_SLEEP_MAX))
        except Exception:
            pass
        finally:
            writer.close()
            self.tcp_connections.pop(stream_id, None)
            frame = MultiplexFrame.pack(stream_id, CMD_TCP_CLOSE, atyp, 0, host, port, b"")
            self.send_to_client(transport, client_addr, frame)

    async def handle_outbound_udp_fullcone(self, stream_id: int, host: str, port: int, data: bytes, transport, client_addr):
        loop = asyncio.get_running_loop()
        now = time.time()

        if stream_id not in self.udp_nat_table:
            if len(self.udp_nat_table) >= self.max_concurrent_streams:
                logging.warning(f"[Server UDP] NAT table full ({self.max_concurrent_streams}), dropping packet.")
                return

            class FullConeUDPProtocol(asyncio.DatagramProtocol):
                def __init__(self, server_engine, sid, main_transport, target_client_addr):
                    self.engine = server_engine
                    self.sid = sid
                    self.main_transport = main_transport
                    self.target_client_addr = target_client_addr
                    self.packet_counter = 0
                    self.transport = None

                def connection_made(self, transport):
                    self.transport = transport

                def datagram_received(self, resp_data, remote_addr):
                    self.packet_counter += 1
                    current_count = self.packet_counter

                    async def send_burst_udp_back():
                        if current_count % BURST_PACKET_COUNT == 0:
                            await asyncio.sleep(random.uniform(BURST_SLEEP_MIN, BURST_SLEEP_MAX))
                        r_ip, r_port = remote_addr[0], remote_addr[1]
                        r_atyp = ATYP_IPV6 if ":" in r_ip else ATYP_IPV4
                        frame = MultiplexFrame.pack(
                            self.sid, CMD_UDP_DATA, r_atyp, 0, r_ip, r_port, resp_data
                        )
                        self.engine.send_to_client(self.main_transport, self.target_client_addr, frame)

                    asyncio.create_task(send_burst_udp_back())

            udp_transport, _ = await loop.create_datagram_endpoint(
                lambda: FullConeUDPProtocol(self, stream_id, transport, client_addr), local_addr=("0.0.0.0", 0)
            )
            self.udp_nat_table[stream_id] = (udp_transport, now)

        udp_transport, _ = self.udp_nat_table[stream_id]
        self.udp_nat_table[stream_id] = (udp_transport, now)
        udp_transport.sendto(data, (host, port))

    async def start(self):
        loop = asyncio.get_running_loop()
        host, port = self.config["server_addr"].split(":")
        port = int(port)
        asyncio.create_task(self.cleanup_idle_loop())

        class ServerUDPProtocol(asyncio.DatagramProtocol):
            def __init__(self, server_engine):
                self.engine = server_engine
                self.transport = None

            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                payloads = self.engine.fec_decoder.process_datagram(addr, data, self.engine.fec_enabled)
                for decrypted_pkt in payloads:
                    decrypted = self.engine.sec.decrypt_and_unpack(decrypted_pkt)
                    if not decrypted:
                        continue

                    try:
                        stream_id, cmd, atyp, seq, r_host, r_port, payload = MultiplexFrame.unpack(decrypted)
                    except Exception as e:
                        logging.debug(f"[Server Multiplex] Dropped malformed frame: {e}")
                        continue

                    if cmd == CMD_TCP_DATA:
                        self.engine.process_tcp_data(stream_id, atyp, seq, r_host, r_port, payload, self.transport, addr)
                    elif cmd == CMD_UDP_DATA:
                        asyncio.create_task(
                            self.engine.handle_outbound_udp_fullcone(stream_id, r_host, r_port, payload, self.transport, addr)
                        )
                    elif cmd == CMD_TCP_CLOSE:
                        conn = self.engine.tcp_connections.pop(stream_id, None)
                        if conn:
                            conn[0].close()
                    elif cmd == CMD_HEARTBEAT:
                        pass  # NAT Keep-alive registered automatically by reaching here

        transport, _ = await loop.create_datagram_endpoint(
            lambda: ServerUDPProtocol(self), local_addr=(host, port)
        )
        logging.info(f"[Lightcone Server] Ingress UDP tunnel online at {host}:{port}")
        logging.info(f"[Lightcone Server] Concurrent Streams Limit: {self.max_concurrent_streams}")
        if self.fec_enabled:
            logging.info(f"[Lightcone Server] RS-FEC Protection Online (N={self.fec_data_shards}, M={self.fec_parity_shards})")

        await asyncio.Event().wait()


# ============================================================================
# Main Entry Point & POSIX System Resource Hardening
# ============================================================================
def apply_resource_limits(limit_mb: int):
    if sys.platform != "win32":
        try:
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            target = 65535 if hard == resource.RLIM_INFINITY else hard
            target = max(target, soft)
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, target))
            logging.info(f"[Resource] POSIX File Descriptor Limit set to {target}")
        except Exception as e:
            logging.warning(f"[Resource] Could not set POSIX system limits completely: {e}")


def main():
    parser = argparse.ArgumentParser(description="Lightcone Tunnel Agent")
    parser.add_argument("config", help="Path to config.yaml file")
    args = parser.parse_args()

    if not os.path.exists(args.config):
        print(f"Error: Config file '{args.config}' not found.")
        sys.exit(1)

    with open(args.config, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    log_level = config.get("log_level", "info").upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

    apply_resource_limits(config.get("memory_limit_mb", 256))

    role = config.get("role", "client").lower()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        if role == "client":
            engine = ClientEngine(config)
            loop.run_until_complete(engine.start())
        elif role == "server":
            engine = ServerEngine(config)
            loop.run_until_complete(engine.start())
        else:
            logging.error(f"Unknown role: {role}")
    except KeyboardInterrupt:
        logging.info("Shutting down Lightcone Tunnel gracefully.")


if __name__ == "__main__":
    main()
