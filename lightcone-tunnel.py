#!/usr/bin/env python3
"""
Lightcone Tunnel - High-Performance Anti-DPI UDP Tunnel & Proxy Solution
Production Release v2.0.5 (Extreme Throughput Chunking + Anti-Collapse ARQ)
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
CMD_TCP_DATA   = 0x01
CMD_TCP_CLOSE  = 0x02
CMD_UDP_DATA   = 0x03
CMD_HEARTBEAT  = 0x04
CMD_TCP_RESEND = 0x05           
CMD_TCP_ACK    = 0x06           

ATYP_IPV4   = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6   = 0x04

MAX_PAYLOAD_SIZE = 1000        
TIMESTAMP_TOLERANCE_SEC = 30.0 
IDLE_TIMEOUT_SEC = 300.0       
CONNECT_TIMEOUT_SEC = 10.0     
HEARTBEAT_INTERVAL_SEC = 20.0  
DEFAULT_MAX_CONCURRENT_STREAMS = 1024 
WINDOW_SIZE = 4096             # 4MB 飞行窗口，解除限速封印，千兆狂飙核心！


def get_chunk_size() -> int:
    return MAX_PAYLOAD_SIZE


class StreamCtx:
    def __init__(self, assembler):
        self.assembler = assembler
        self.last_act = time.time()
        self.cache = {}
        self.acked_seq = 0
        self.last_stall_probe = 0


# ============================================================================
# Crypto & Security
# ============================================================================
class TunnelSecurity:
    def __init__(self, psk: str):
        key = hashlib.sha256(psk.encode('utf-8')).digest()
        self.cipher = ChaCha20Poly1305(key)
        self.seen_sequences = {}
        self.seq_counter = 0

    def pack_and_encrypt(self, payload: bytes) -> bytes:
        self.seq_counter = (self.seq_counter + 1) & 0xFFFFFFFFFFFFFFFF
        timestamp = int(time.time())
        pad_len = os.urandom(1)[0] % 16
        padding = os.urandom(pad_len)
        meta_header = os.urandom(4) + struct.pack("!QQB", self.seq_counter, timestamp, pad_len)
        nonce = struct.pack("!IQ", timestamp & 0xFFFFFFFF, self.seq_counter)
        encrypted = self.cipher.encrypt(nonce, payload + padding, meta_header)
        return meta_header + nonce + encrypted

    def decrypt_and_unpack(self, datagram: bytes) -> Optional[bytes]:
        if len(datagram) < 21 + 12 + 16: return None
        meta_header, nonce, ciphertext = datagram[:21], datagram[21:33], datagram[33:]
        seq, timestamp, pad_len = struct.unpack("!QQB", meta_header[4:])
        
        now = time.time()
        if abs(now - timestamp) > TIMESTAMP_TOLERANCE_SEC: return None
        if seq in self.seen_sequences: return None
        self.seen_sequences[seq] = now

        if len(self.seen_sequences) > 5000:
            threshold = now - TIMESTAMP_TOLERANCE_SEC
            expired = [s for s, t in self.seen_sequences.items() if t < threshold]
            for s in expired: del self.seen_sequences[s]

        try:
            decrypted = self.cipher.decrypt(nonce, ciphertext, meta_header)
            return decrypted[:-pad_len] if pad_len > 0 else decrypted
        except Exception: return None


# ============================================================================
# FEC Engine (With Fast-XOR CPU Optimization)
# ============================================================================
def _fast_xor_bytes(shards: List[bytes], max_len: int) -> bytes:
    """Python 层面极速 XOR 算法，解决 zfec 不存在时的 CPU 卡顿问题"""
    res = int.from_bytes(shards[0], 'little')
    for s in shards[1:]:
        res ^= int.from_bytes(s, 'little')
    return res.to_bytes(max_len, 'little')

class FECGroupEncoder:
    def __init__(self, data_shards: int, parity_shards: int):
        self.n = data_shards
        self.m = parity_shards
        self.group_id = 0
        self.buffer = []
        self.last_act = time.time()

    def input_packet(self, ciphertext: bytes) -> List[bytes]:
        if self.n <= 0 or self.m <= 0: return [ciphertext]
        now = time.time()
        out = []
        if self.buffer and (now - self.last_act > 0.020): 
            out.extend(self._flush())
        self.last_act = now
        idx = len(self.buffer)
        self.buffer.append(ciphertext)
        
        out.append(struct.pack("!QBBBH", self.group_id, idx, self.n, self.m, len(ciphertext)) + ciphertext)
        if len(self.buffer) == self.n: 
            out.extend(self._flush())
        return out

    def _flush(self) -> List[bytes]:
        if not self.buffer: return []
        out = []
        max_len = max(len(p) for p in self.buffer)
        padded = [p.ljust(max_len, b'\x00') for p in self.buffer]
        while len(padded) < self.n: padded.append(b'\x00' * max_len)

        if zfec:
            encoder = zfec.Encoder(self.n, self.n + self.m)
            parity_blocks = encoder.encode(padded)
        else:
            parity_blocks = [_fast_xor_bytes(padded, max_len)] * self.m

        for p_idx, p_data in enumerate(parity_blocks, start=self.n):
            out.append(struct.pack("!QBBBH", self.group_id, p_idx, self.n, self.m, max_len) + p_data)
        self.group_id = (self.group_id + 1) & 0xFFFFFFFFFFFFFFFF
        self.buffer.clear()
        return out

class FECGroupDecoder:
    def __init__(self, timeout_sec: float = 3.0):
        self.groups = {}
        self.timeout_sec = timeout_sec

    def process_datagram(self, peer_addr, datagram: bytes, fec_enabled: bool) -> List[bytes]:
        if not fec_enabled or len(datagram) < 13: return [datagram]
        group_id, idx, n, m, raw_len = struct.unpack("!QBBBH", datagram[:13])
        payload = datagram[13:]
        key = (peer_addr, group_id)
        
        if key not in self.groups:
            self.groups[key] = {'shards': {}, 'raw_lens': {}, 'n': n, 'm': m, 'time': time.time()}
        grp = self.groups[key]
        grp['shards'][idx] = payload
        grp['raw_lens'][idx] = raw_len
        
        recovered = []
        if idx < n: recovered.append(payload[:raw_len])
        
        rcv_data_idx = {i for i in grp['shards'].keys() if i < n}
        if len(rcv_data_idx) < n and len(grp['shards']) >= n:
            max_len = max(len(s) for s in grp['shards'].values())
            src_shards = []
            src_indices = []
            for s_idx, s_bytes in sorted(grp['shards'].items())[:n]:
                src_shards.append(s_bytes.ljust(max_len, b'\x00'))
                src_indices.append(s_idx)
            if zfec:
                decoder = zfec.Decoder(n, n + m)
                decoded = decoder.decode(src_shards, src_indices)
                for d_idx, d_data in enumerate(decoded):
                    if d_idx not in rcv_data_idx:
                        olen = grp['raw_lens'].get(d_idx, max_len)
                        if olen > 0: recovered.append(d_data[:olen])
            self.groups.pop(key, None)
        elif len(rcv_data_idx) == n: 
            self.groups.pop(key, None)
        return recovered

    def sweep_stale_groups(self):
        now = time.time()
        expired = [k for k, v in self.groups.items() if now - v['time'] > self.timeout_sec]
        for k in expired: self.groups.pop(k, None)


# ============================================================================
# Stream Assembler & ARQ
# ============================================================================
class StreamAssembler:
    def __init__(self, nack_callback, ack_callback, timeout_sec: float = 15.0):
        self.writer = None
        self.expected_seq = 0
        self.buffer = {}
        self.connecting = True
        self.timeout = timeout_sec
        self.is_broken = False
        
        self.nack_callback = nack_callback
        self.ack_callback = ack_callback
        self.last_nack_time = {}
        self.unacked_count = 0
        self.last_ack_time = time.time()

    def set_writer(self, writer):
        self.writer = writer
        self.connecting = False
        self.flush()

    def receive(self, seq: int, payload: bytes):
        if self.is_broken: return
        now = time.time()

        if seq < self.expected_seq:
            if now - self.last_ack_time > 0.05:
                if self.ack_callback: self.ack_callback(self.expected_seq)
                self.last_ack_time = now
            return

        if seq >= self.expected_seq:
            # 【核心修复】：就算乱序超载，也绝对不能自杀关闭连接！直接丢包，等 ARQ 慢慢补
            if len(self.buffer) < 8192:
                if seq not in self.buffer: 
                    self.buffer[seq] = (payload, now)
            else:
                logging.debug(f"[Assembler] Deep buffer full. Packet {seq} dropped to prevent overflow.")
                return

        if seq > self.expected_seq:
            scan_end = min(seq, self.expected_seq + 64)
            for m_seq in range(self.expected_seq, scan_end):
                if m_seq not in self.buffer:
                    if now - self.last_nack_time.get(m_seq, 0) > 0.1:
                        self.last_nack_time[m_seq] = now
                        if self.nack_callback: self.nack_callback(m_seq)

        if self.buffer:
            min_seq = min(self.buffer.keys())
            if min_seq > self.expected_seq:
                if now - self.buffer[min_seq][1] > self.timeout:
                    self.is_broken = True; self.close(); return

        self.flush()
        
        if self.unacked_count >= 16 or (now - self.last_ack_time > 0.05 and self.unacked_count > 0):
            if self.ack_callback: self.ack_callback(self.expected_seq)
            self.unacked_count = 0; self.last_ack_time = now

    def flush(self):
        if not self.writer or self.connecting or self.is_broken: return
        while self.expected_seq in self.buffer:
            payload, _ = self.buffer.pop(self.expected_seq)
            self.last_nack_time.pop(self.expected_seq, None)
            if payload:
                try: 
                    self.writer.write(payload)
                except Exception: 
                    self.is_broken = True; self.close(); break
            self.expected_seq += 1
            self.unacked_count += 1

    def close(self):
        self.is_broken = True
        self.buffer.clear(); self.last_nack_time.clear()
        if self.writer:
            try: self.writer.close()
            except Exception: pass


class MultiplexFrame:
    @staticmethod
    def pack(stream_id: int, cmd: int, atyp: int, seq: int, host: str, port: int, payload: bytes) -> bytes:
        header = struct.pack("!IBBI", stream_id, cmd, atyp, seq)
        if atyp == ATYP_IPV4: addr = socket.inet_aton(host) + struct.pack("!H", port)
        elif atyp == ATYP_DOMAIN:
            h_bytes = host.encode('utf-8')
            addr = struct.pack("!B", len(h_bytes)) + h_bytes + struct.pack("!H", port)
        elif atyp == ATYP_IPV6: addr = socket.inet_pton(socket.AF_INET6, host) + struct.pack("!H", port)
        else: addr = b""
        return header + addr + payload

    @staticmethod
    def unpack(data: bytes) -> Tuple[int, int, int, int, str, int, bytes]:
        stream_id, cmd, atyp, seq = struct.unpack("!IBBI", data[:10])
        idx = 10; host = ""; port = 0
        if atyp == ATYP_IPV4: 
            host = socket.inet_ntoa(data[idx:idx+4])
            port = struct.unpack("!H", data[idx+4:idx+6])[0]; idx += 6
        elif atyp == ATYP_DOMAIN: 
            d_len = data[idx]; idx += 1
            host = data[idx:idx+d_len].decode('utf-8'); idx += d_len
            port = struct.unpack("!H", data[idx:idx+2])[0]; idx += 2
        elif atyp == ATYP_IPV6: 
            host = socket.inet_ntop(socket.AF_INET6, data[idx:idx+16])
            port = struct.unpack("!H", data[idx+16:idx+18])[0]; idx += 18
        return stream_id, cmd, atyp, seq, host, port, data[idx:]


# ============================================================================
# Core Engine Base
# ============================================================================
class LightconeEngineBase:
    async def active_arq_sweep(self, stream_dict: dict):
        while True:
            await asyncio.sleep(0.1)
            now = time.time()
            for sid, ctx in list(stream_dict.items()):
                if now - ctx.last_act > IDLE_TIMEOUT_SEC:
                    ctx.assembler.close()
                    stream_dict.pop(sid, None)
                    continue
                
                asm = ctx.assembler
                if asm.is_broken: continue
                    
                if asm.buffer:
                    end_seq = min(max(asm.buffer.keys()) + 1, asm.expected_seq + 128)
                    for m_seq in range(asm.expected_seq, end_seq):
                        if m_seq not in asm.buffer:
                            if now - asm.last_nack_time.get(m_seq, 0) > 0.1:
                                asm.last_nack_time[m_seq] = now
                                if asm.nack_callback: asm.nack_callback(m_seq)

                if asm.unacked_count > 0 and (now - asm.last_ack_time > 0.1):
                    if asm.ack_callback: asm.ack_callback(asm.expected_seq)
                    asm.unacked_count = 0; asm.last_ack_time = now


class ClientEngine(LightconeEngineBase):
    def __init__(self, config: dict):
        self.config = config
        self.max_streams = config.get("max_concurrent_streams", DEFAULT_MAX_CONCURRENT_STREAMS)
        self.sec = TunnelSecurity(config["psk"])
        self.s_host, self.s_port = config["server_addr"].split(":")
        self.s_port = int(self.s_port)
        self.s_ip = None
        
        self.fec_n = config.get("fec_data_shards", 0); self.fec_m = config.get("fec_parity_shards", 0)
        self.fec_enabled = self.fec_n > 0 and self.fec_m > 0
        self.fec_encoder = FECGroupEncoder(self.fec_n, self.fec_m) if self.fec_enabled else None
        self.fec_decoder = FECGroupDecoder()

        self.streams: Dict[int, StreamCtx] = {}
        self.udp_sessions: Dict[int, Tuple[Tuple[str, int], asyncio.DatagramTransport, float]] = {}
        self.next_id = 1; self.transport = None

    async def resolve_ddns_once(self):
        try:
            info = await asyncio.to_thread(socket.getaddrinfo, self.s_host, self.s_port)
            if info and info[0][4][0] != self.s_ip:
                self.s_ip = info[0][4][0]; logging.info(f"[DDNS] Target IP updated: {self.s_ip}")
        except Exception: pass

    async def resolve_ddns_loop(self):
        while True:
            await asyncio.sleep(60); await self.resolve_ddns_once()

    async def heartbeat(self):
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL_SEC)
            if self.s_ip and self.transport:
                try: self.send_to_server(MultiplexFrame.pack(0, CMD_HEARTBEAT, ATYP_IPV4, 0, "0.0.0.0", 0, b""))
                except Exception: pass

    async def sweep(self):
        while True:
            await asyncio.sleep(10)
            now = time.time()
            for sid in [s for s, (_, _, act) in list(self.udp_sessions.items()) if now - act > IDLE_TIMEOUT_SEC]:
                item = self.udp_sessions.pop(sid, None)
                if item: item[1].close()
            if self.fec_enabled: self.fec_decoder.sweep_stale_groups()

    async def handle_socks5(self, reader, writer):
        sid = None; atyp = ATYP_IPV4; host = ""; port = 0; u_trans = None
        try:
            ver, nmethods = struct.unpack("!BB", await reader.readexactly(2))
            await reader.readexactly(nmethods)
            writer.write(b"\x05\x00")
            await writer.drain()

            ver, cmd, _, atyp = struct.unpack("!BBBB", await reader.readexactly(4))
            
            if atyp == ATYP_IPV4: host = socket.inet_ntoa(await reader.readexactly(4))
            elif atyp == ATYP_DOMAIN: 
                d_len = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(d_len)).decode('utf-8')
            elif atyp == ATYP_IPV6: host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
            port = struct.unpack("!H", await reader.readexactly(2))[0]

            if cmd == 0x01: # TCP CONNECT
                if len(self.streams) >= self.max_streams: writer.close(); return
                
                writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                sid = self.next_id; self.next_id += 1
                
                def on_nack(m_seq): self.send_to_server(MultiplexFrame.pack(sid, CMD_TCP_RESEND, atyp, m_seq, host, port, b""))
                def on_ack(ack_seq): self.send_to_server(MultiplexFrame.pack(sid, CMD_TCP_ACK, atyp, ack_seq, host, port, b""))
                    
                ctx = StreamCtx(StreamAssembler(on_nack, on_ack))
                ctx.assembler.set_writer(writer); self.streams[sid] = ctx
                seq = 0

                while True:
                    # 【核心突破 2】：巨型分块读取 (64KB)，消除 OS 频繁切换导致的速度天花板
                    data = await reader.read(65536)
                    if not data: break
                    
                    ctx.last_act = time.time()
                    
                    for i in range(0, len(data), MAX_PAYLOAD_SIZE):
                        chunk = data[i:i+MAX_PAYLOAD_SIZE]
                        
                        while seq - ctx.acked_seq > WINDOW_SIZE:
                            if ctx.assembler.is_broken or sid not in self.streams: break
                            await asyncio.sleep(0.01)
                            if time.time() - ctx.last_stall_probe > 0.1:
                                ctx.last_stall_probe = time.time()
                                if ctx.acked_seq in ctx.cache:
                                    self.send_to_server(MultiplexFrame.pack(sid, CMD_TCP_DATA, atyp, ctx.acked_seq, host, port, ctx.cache[ctx.acked_seq]))

                        if ctx.assembler.is_broken or sid not in self.streams: break
                        
                        ctx.cache[seq] = chunk
                        self.send_to_server(MultiplexFrame.pack(sid, CMD_TCP_DATA, atyp, seq, host, port, chunk))
                        seq += 1

            elif cmd == 0x03:
                if len(self.udp_sessions) >= self.max_streams: writer.close(); return
                sid = self.next_id; self.next_id += 1
                
                class URelay(asyncio.DatagramProtocol):
                    def __init__(self, eng, sid): self.eng = eng; self.sid = sid; self.trans = None
                    def connection_made(self, tr): self.trans = tr
                    def datagram_received(self, dt, addr):
                        if len(dt) < 10: return
                        _, _, u_at = struct.unpack("!HBB", dt[:4]); idx = 4
                        if u_at == ATYP_IPV4: dh = socket.inet_ntoa(dt[idx:idx+4]); dp = struct.unpack("!H", dt[idx+4:idx+6])[0]; idx += 6
                        elif u_at == ATYP_DOMAIN: dl = dt[idx]; idx += 1; dh = dt[idx:idx+dl].decode('utf-8'); idx += dl; dp = struct.unpack("!H", dt[idx:idx+2])[0]; idx += 2
                        elif u_at == ATYP_IPV6: dh = socket.inet_ntop(socket.AF_INET6, dt[idx:idx+16]); dp = struct.unpack("!H", dt[idx+16:idx+18])[0]; idx += 18
                        else: return
                        self.eng.udp_sessions[self.sid] = (addr, self.trans, time.time())
                        self.eng.send_to_server(MultiplexFrame.pack(self.sid, CMD_UDP_DATA, u_at, 0, dh, dp, dt[idx:]))
                
                loop = asyncio.get_running_loop()
                u_trans, _ = await loop.create_datagram_endpoint(lambda: URelay(self, sid), local_addr=("0.0.0.0", 0))
                _, relay_port = u_trans.get_extra_info("sockname")
                
                reply = struct.pack("!BBBB4sH", 0x05, 0x00, 0x00, 0x01, socket.inet_aton("127.0.0.1"), relay_port)
                writer.write(reply)
                await writer.drain()
                while await reader.read(1024): pass
                    
        except Exception: pass
        finally:
            writer.close()
            if u_trans: u_trans.close()
            if sid is not None:
                self.udp_sessions.pop(sid, None)
                ctx = self.streams.pop(sid, None)
                if ctx:
                    ctx.assembler.close()
                    try: self.send_to_server(MultiplexFrame.pack(sid, CMD_TCP_CLOSE, atyp, 0, host, port, b""))
                    except Exception: pass

    async def handle_http_proxy(self, reader, writer):
        sid = None; atyp = ATYP_DOMAIN; host = ""; port = 80
        try:
            line = await reader.readline()
            if not line: return
            parts = line.decode('utf-8', errors='ignore').split()
            if len(parts) < 2 or len(self.streams) >= self.max_streams: writer.close(); return
                
            method, url = parts[0], parts[1]
            sid = self.next_id; self.next_id += 1

            if method == "CONNECT":
                host, port_str = url.rsplit(":", 1) if ":" in url else (url, "443")
                port = int(port_str) if port_str.isdigit() else 443
                while True:
                    if (await reader.readline()) in (b"\r\n", b"\n", b""): break
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
                seq = 0
            else:
                parsed = urlparse(url)
                host, port = parsed.hostname or "", parsed.port or 80
                seq = 0
                self.send_to_server(MultiplexFrame.pack(sid, CMD_TCP_DATA, atyp, seq, host, port, line))
                seq += 1

            ctx = StreamCtx(StreamAssembler(
                lambda ms: self.send_to_server(MultiplexFrame.pack(sid, CMD_TCP_RESEND, atyp, ms, host, port, b"")),
                lambda ak: self.send_to_server(MultiplexFrame.pack(sid, CMD_TCP_ACK, atyp, ak, host, port, b""))
            ))
            ctx.assembler.set_writer(writer); self.streams[sid] = ctx
            if method != "CONNECT": ctx.cache[0] = line
            
            while True:
                data = await reader.read(65536)
                if not data: break
                
                ctx.last_act = time.time()
                
                for i in range(0, len(data), MAX_PAYLOAD_SIZE):
                    chunk = data[i:i+MAX_PAYLOAD_SIZE]
                    
                    while seq - ctx.acked_seq > WINDOW_SIZE:
                        if ctx.assembler.is_broken or sid not in self.streams: break
                        await asyncio.sleep(0.01)
                        if time.time() - ctx.last_stall_probe > 0.1:
                            ctx.last_stall_probe = time.time()
                            if ctx.acked_seq in ctx.cache:
                                self.send_to_server(MultiplexFrame.pack(sid, CMD_TCP_DATA, atyp, ctx.acked_seq, host, port, ctx.cache[ctx.acked_seq]))

                    if ctx.assembler.is_broken or sid not in self.streams: break
                    
                    ctx.cache[seq] = chunk
                    self.send_to_server(MultiplexFrame.pack(sid, CMD_TCP_DATA, atyp, seq, host, port, chunk))
                    seq += 1

        except Exception: pass
        finally:
            writer.close()
            ctx = self.streams.pop(sid, None)
            if ctx:
                ctx.assembler.close()
                try: self.send_to_server(MultiplexFrame.pack(sid, CMD_TCP_CLOSE, atyp, 0, host, port, b""))
                except Exception: pass

    def send_to_server(self, payload: bytes):
        if self.s_ip and self.transport:
            enc = self.sec.pack_and_encrypt(payload)
            if self.fec_enabled and self.fec_encoder:
                for pkt in self.fec_encoder.input_packet(enc): self.transport.sendto(pkt, (self.s_ip, self.s_port))
            else: self.transport.sendto(enc, (self.s_ip, self.s_port))

    async def start(self):
        loop = asyncio.get_running_loop()
        await self.resolve_ddns_once()
        asyncio.create_task(self.resolve_ddns_loop())
        asyncio.create_task(self.sweep())
        asyncio.create_task(self.active_arq_sweep(self.streams))
        asyncio.create_task(self.heartbeat())

        class CP(asyncio.DatagramProtocol):
            def __init__(self, eng): self.eng = eng; self.tr = None
            def connection_made(self, tr): self.tr = tr
            def datagram_received(self, data, addr):
                for dpkt in self.eng.fec_decoder.process_datagram(addr, data, self.eng.fec_enabled):
                    dec = self.eng.sec.decrypt_and_unpack(dpkt)
                    if not dec: continue
                    try: sid, cmd, at, seq, rh, rp, pay = MultiplexFrame.unpack(dec)
                    except Exception: continue
                    
                    if cmd == CMD_TCP_DATA and sid in self.eng.streams:
                        ctx = self.eng.streams[sid]; ctx.last_act = time.time()
                        ctx.assembler.receive(seq, pay)
                        
                    elif cmd == CMD_TCP_ACK and sid in self.eng.streams:
                        ctx = self.eng.streams[sid]
                        if seq > ctx.acked_seq:
                            ctx.acked_seq = seq
                            keys_to_del = [k for k in ctx.cache.keys() if k < seq]
                            for k in keys_to_del: del ctx.cache[k]
                            
                    elif cmd == CMD_TCP_RESEND and sid in self.eng.streams:
                        ctx = self.eng.streams[sid]; ctx.last_act = time.time()
                        if seq in ctx.cache:
                            self.eng.send_to_server(MultiplexFrame.pack(sid, CMD_TCP_DATA, at, seq, rh, rp, ctx.cache[seq]))
                            
                    elif cmd == CMD_UDP_DATA and sid in self.eng.udp_sessions:
                        ca, ut, _ = self.eng.udp_sessions[sid]; self.eng.udp_sessions[sid] = (ca, ut, time.time())
                        if at == ATYP_IPV4: ab = socket.inet_aton(rh)
                        elif at == ATYP_DOMAIN: hb = rh.encode('utf-8'); ab = struct.pack("!B", len(hb)) + hb
                        elif at == ATYP_IPV6: ab = socket.inet_pton(socket.AF_INET6, rh)
                        else: return
                        ut.sendto(struct.pack("!HBB", 0, 0, at) + ab + struct.pack("!H", rp) + pay, ca)
                        
                    elif cmd == CMD_TCP_CLOSE:
                        ctx = self.eng.streams.pop(sid, None)
                        if ctx: ctx.assembler.close()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try: 
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8388608)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8388608)
        except Exception: pass
        sock.bind(("0.0.0.0", 0))

        self.transport, _ = await loop.create_datagram_endpoint(lambda: CP(self), sock=sock)
        s_port = self.config.get("socks_port", 1080)
        h_port = self.config.get("http_port", 8080)
        
        ss = await asyncio.start_server(self.handle_socks5, "0.0.0.0", s_port)
        hs = await asyncio.start_server(self.handle_http_proxy, "0.0.0.0", h_port)
        
        logging.info(f"[Client] SOCKS5: {s_port} | HTTP: {h_port} | Ultra-Speed Engine Online")
        await asyncio.gather(ss.serve_forever(), hs.serve_forever())


# ============================================================================
# Server Engine
# ============================================================================
class ServerEngine(LightconeEngineBase):
    def __init__(self, config: dict):
        self.config = config
        self.max_streams = config.get("max_concurrent_streams", DEFAULT_MAX_CONCURRENT_STREAMS)
        self.sec = TunnelSecurity(config["psk"])
        self.fec_n = config.get("fec_data_shards", 0); self.fec_m = config.get("fec_parity_shards", 0)
        self.fec_enabled = self.fec_n > 0 and self.fec_m > 0
        self.fec_encs = {}; self.fec_decoder = FECGroupDecoder()
        
        self.tcp_conns: Dict[int, StreamCtx] = {}
        self.udp_nat: Dict[int, Tuple[asyncio.DatagramProtocol, float]] = {}

    def send_to_client(self, transport, addr, payload: bytes):
        enc = self.sec.pack_and_encrypt(payload)
        if self.fec_enabled:
            if addr not in self.fec_encs: self.fec_encs[addr] = FECGroupEncoder(self.fec_n, self.fec_m)
            for pkt in self.fec_encs[addr].input_packet(enc): transport.sendto(pkt, addr)
        else: transport.sendto(enc, addr)

    async def sweep(self):
        while True:
            await asyncio.sleep(10)
            now = time.time()
            for sid in [s for s, (_, act) in list(self.udp_nat.items()) if now - act > IDLE_TIMEOUT_SEC]:
                item = self.udp_nat.pop(sid, None)
                if item: item[0].close()
            if self.fec_enabled: self.fec_decoder.sweep_stale_groups()

    async def _pipe(self, sid, at, h, p, tr, ca):
        try: 
            reader, writer = await asyncio.wait_for(asyncio.open_connection(h, p), timeout=CONNECT_TIMEOUT_SEC)
        except Exception:
            self.tcp_conns.pop(sid, None)
            self.send_to_client(tr, ca, MultiplexFrame.pack(sid, CMD_TCP_CLOSE, at, 0, h, p, b""))
            return

        ctx = self.tcp_conns.get(sid)
        if ctx: ctx.assembler.set_writer(writer)
        else: writer.close(); return

        seq = 0
        try:
            while True:
                data = await reader.read(65536)
                if not data: break
                
                ctx.last_act = time.time()
                
                for i in range(0, len(data), MAX_PAYLOAD_SIZE):
                    chunk = data[i:i+MAX_PAYLOAD_SIZE]
                    
                    while seq - ctx.acked_seq > WINDOW_SIZE:
                        if ctx.assembler.is_broken or sid not in self.tcp_conns: break
                        await asyncio.sleep(0.01)
                        if time.time() - ctx.last_stall_probe > 0.1:
                            ctx.last_stall_probe = time.time()
                            if ctx.acked_seq in ctx.cache:
                                self.send_to_client(tr, ca, MultiplexFrame.pack(sid, CMD_TCP_DATA, at, ctx.acked_seq, h, p, ctx.cache[ctx.acked_seq]))

                    if ctx.assembler.is_broken or sid not in self.tcp_conns: break
                        
                    ctx.cache[seq] = chunk
                    self.send_to_client(tr, ca, MultiplexFrame.pack(sid, CMD_TCP_DATA, at, seq, h, p, chunk))
                    seq += 1

        except Exception: pass
        finally:
            writer.close()
            ctx = self.tcp_conns.pop(sid, None)
            if ctx:
                ctx.assembler.close()
                self.send_to_client(tr, ca, MultiplexFrame.pack(sid, CMD_TCP_CLOSE, at, 0, h, p, b""))

    async def start(self):
        loop = asyncio.get_running_loop()
        asyncio.create_task(self.sweep())
        asyncio.create_task(self.active_arq_sweep(self.tcp_conns))
        
        h, p = self.config["server_addr"].split(":"); p = int(p)

        class SP(asyncio.DatagramProtocol):
            def __init__(self, eng): self.eng = eng; self.tr = None
            def connection_made(self, tr): self.tr = tr
            def datagram_received(self, data, addr):
                for dpkt in self.eng.fec_decoder.process_datagram(addr, data, self.eng.fec_enabled):
                    dec = self.eng.sec.decrypt_and_unpack(dpkt)
                    if not dec: continue
                    try: sid, cmd, at, seq, rh, rp, pay = MultiplexFrame.unpack(dec)
                    except Exception: continue

                    if cmd == CMD_TCP_DATA:
                        if sid not in self.eng.tcp_conns:
                            if len(self.eng.tcp_conns) >= self.eng.max_streams: return
                            
                            def on_nack(m_seq): self.eng.send_to_client(self.tr, addr, MultiplexFrame.pack(sid, CMD_TCP_RESEND, at, m_seq, rh, rp, b""))
                            def on_ack(ack_seq): self.eng.send_to_client(self.tr, addr, MultiplexFrame.pack(sid, CMD_TCP_ACK, at, ack_seq, rh, rp, b""))
                            
                            ctx = StreamCtx(StreamAssembler(on_nack, on_ack))
                            self.eng.tcp_conns[sid] = ctx
                            asyncio.create_task(self.eng._pipe(sid, at, rh, rp, self.tr, addr))
                        
                        ctx = self.eng.tcp_conns.get(sid)
                        if ctx: 
                            ctx.last_act = time.time()
                            ctx.assembler.receive(seq, pay)
                    
                    elif cmd == CMD_TCP_ACK and sid in self.eng.tcp_conns:
                        ctx = self.eng.tcp_conns[sid]
                        if seq > ctx.acked_seq:
                            ctx.acked_seq = seq
                            keys_to_del = [k for k in ctx.cache.keys() if k < seq]
                            for k in keys_to_del: del ctx.cache[k]
                        
                    elif cmd == CMD_TCP_RESEND and sid in self.eng.tcp_conns:
                        ctx = self.eng.tcp_conns[sid]
                        ctx.last_act = time.time()
                        if seq in ctx.cache: 
                            self.eng.send_to_client(self.tr, addr, MultiplexFrame.pack(sid, CMD_TCP_DATA, at, seq, rh, rp, ctx.cache[seq]))
                            
                    elif cmd == CMD_UDP_DATA:
                        class FullConeUDPProtocol(asyncio.DatagramProtocol):
                            def __init__(self, seng, s_id, main_tr, t_ca):
                                self.seng = seng; self.s_id = s_id; self.main_tr = main_tr; self.t_ca = t_ca; self.tr = None
                            def connection_made(self, tr): self.tr = tr
                            def datagram_received(self, r_dt, r_addr):
                                r_ip, r_port = r_addr[0], r_addr[1]; r_at = ATYP_IPV6 if ":" in r_ip else ATYP_IPV4
                                self.seng.send_to_client(self.main_tr, self.t_ca, MultiplexFrame.pack(self.s_id, CMD_UDP_DATA, r_at, 0, r_ip, r_port, r_dt))
                                
                        if sid not in self.eng.udp_nat:
                            async def create_udp():
                                u_tr, _ = await loop.create_datagram_endpoint(lambda: FullConeUDPProtocol(self.eng, sid, self.tr, addr), local_addr=("0.0.0.0", 0))
                                self.eng.udp_nat[sid] = (u_tr, time.time())
                                u_tr.sendto(pay, (rh, rp))
                            asyncio.create_task(create_udp())
                        else:
                            u_tr, _ = self.eng.udp_nat[sid]; self.eng.udp_nat[sid] = (u_tr, time.time())
                            u_tr.sendto(pay, (rh, rp))

                    elif cmd == CMD_TCP_CLOSE:
                        ctx = self.eng.tcp_conns.pop(sid, None)
                        if ctx: ctx.assembler.close()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try: 
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8388608); sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8388608)
        except Exception: pass
        sock.bind((h, p))

        await loop.create_datagram_endpoint(lambda: SP(self), sock=sock)
        logging.info(f"[Server] Online at {h}:{p} | Ultra-Speed Engine Online")
        await asyncio.Event().wait()


def apply_resource_limits(limit_mb: int):
    if sys.platform != "win32":
        try:
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            target = 65535 if hard == resource.RLIM_INFINITY else hard
            resource.setrlimit(resource.RLIMIT_NOFILE, (max(target, soft), target))
        except Exception: pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("config")
    args = parser.parse_args()
    if not os.path.exists(args.config): sys.exit(1)
        
    with open(args.config, "r", encoding="utf-8") as f: 
        config = yaml.safe_load(f)
    
    logging.basicConfig(level=getattr(logging, config.get("log_level", "info").upper(), logging.INFO), format="%(asctime)s [%(levelname)s] %(message)s")
    
    try: 
        import uvloop; asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        logging.info("[System] uvloop active")
    except ImportError: pass
    
    apply_resource_limits(config.get("memory_limit_mb", 256))
    loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
    
    role = config.get("role", "client").lower()
    try: 
        if role == "client": loop.run_until_complete(ClientEngine(config).start())
        else: loop.run_until_complete(ServerEngine(config).start())
    except KeyboardInterrupt: pass

if __name__ == "__main__": 
    main()
