#!/usr/bin/env python3
"""
Lightcone Tunnel - High-Performance Anti-DPI UDP Tunnel & Proxy Solution
"""

import argparse
import asyncio
import gc
import hashlib
import logging
import os
import random
import resource
import socket
import struct
import sys
import time
from collections import OrderedDict
from typing import Dict, Tuple, Optional, Set, List
from urllib.parse import urlparse
import yaml

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

try:
    import zfec
except ImportError:
    zfec = None

try:
    import numpy as _np
    _HAS_NUMPY = True
except ImportError:
    _np = None
    _HAS_NUMPY = False


# ============================================================================
# Memory Profile & Dynamic Tuning Engine
# ============================================================================
class MemoryProfile:
    def __init__(self, mem_mb: int, latency_ms: int = 100):
        self.mem_mb = max(int(mem_mb), 512)
        self.latency_ms = max(int(latency_ms), 10)
        multiplier = self.mem_mb / 512.0

        self.max_streams = min(int(512 * multiplier), 16384)
        self.max_window_packets = min(int(2048 * multiplier), 16384)
        self.idle_timeout = 120.0 if self.mem_mb <= 512 else min(120.0 * multiplier, 300.0)

        self.udp_buf_size = min(int(8388608 * multiplier), 33554432)
        self.tcp_buf_limit = min(int(1048576 * multiplier), 8388608)

        self.assembler_buf_len = min(int(2048 * multiplier), 16384)
        self.seen_seq_limit = min(int(4000 * multiplier), 32000)

        # [FIX] FEC group table is now bounded but generously sized. The old
        # 2048 limit was hit in normal traffic because it was per-peer.
        self.fec_max_groups = 8192

        self.assembler_timeout = max(15.0, min(60.0, self.latency_ms / 100.0 * 15.0))
        self.fec_timeout = max(0.5, min(5.0, self.latency_ms / 1000.0 * 10.0))
        self.fec_flush_interval = max(0.010, min(0.050, self.latency_ms / 5000.0))
        self.nack_cooldown = max(0.05, min(0.5, self.latency_ms / 1000.0 * 1.5))
        self.nack_cooldown_slow = self.nack_cooldown * 2.0

    def apply_user_config(self, user_streams: Optional[int]):
        if user_streams is None:
            return
        user_streams = int(user_streams)
        if user_streams <= 0:
            logging.warning("[Memory] max_concurrent_streams is 0. Engine will reject all new connections.")
            self.max_streams = 0
            return

        if user_streams > self.max_streams:
            user_streams = min(user_streams, 65535)
            logging.warning(
                f"[Memory] User max_concurrent_streams ({user_streams}) exceeds safe limit "
                f"({self.max_streams}). Downscaling buffers safely."
            )
            ratio = max(0.1, self.max_streams / user_streams)
            self.max_window_packets = max(256, int(self.max_window_packets * ratio))
            self.assembler_buf_len = max(256, int(self.assembler_buf_len * ratio))
            self.tcp_buf_limit = max(131072, int(self.tcp_buf_limit * ratio))
        self.max_streams = user_streams

    def print_profile(self):
        logging.info(f"[Memory Tuner] Configured RAM: {self.mem_mb} MB | Expected Latency: {self.latency_ms} ms")
        logging.info(f"[Memory Tuner] Max Streams: {self.max_streams} | Window Cap: {self.max_window_packets} Pkts")


# ============================================================================
# Protocol Configuration
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

MAX_PAYLOAD_SIZE = 1200
TIMESTAMP_TOLERANCE_SEC = 30.0
CONNECT_TIMEOUT_SEC = 10.0
HEARTBEAT_INTERVAL_SEC = 20.0

# [FIX] Tunables for the hot path.
FEC_SWEEP_INTERVAL = 0.5        # background FEC group GC
ARQ_SWEEP_INTERVAL = 0.1        # per-stream ARQ / ACK servicing
FEC_FLUSH_INTERVAL = 0.05       # partial-group flush cadence
ACK_BATCH_THRESHOLD = 4         # immediate ACK after this many packets
ADDR_CACHE_SIZE = 4096          # upper bound on the encoded-address cache


# ============================================================================
# Encoded-address cache
# ============================================================================
# [FIX] The previous code re-encoded (atyp, host, port) on every single packet
# inside MultiplexFrame.pack(). For a session sending N packets to the same
# destination that was N redundant `struct.pack` + `str.encode` calls. Cache
# the encoded bytes per destination.
_addr_cache: Dict[Tuple[int, str, int], bytes] = {}


def _pack_addr(atyp: int, host: str, port: int) -> bytes:
    key = (atyp, host, port)
    cached = _addr_cache.get(key)
    if cached is not None:
        return cached
    if atyp == ATYP_IPV4:
        addr = socket.inet_aton(host) + struct.pack("!H", port)
    elif atyp == ATYP_DOMAIN:
        h_bytes = host.encode('utf-8')
        addr = struct.pack("!B", len(h_bytes)) + h_bytes + struct.pack("!H", port)
    elif atyp == ATYP_IPV6:
        addr = socket.inet_pton(socket.AF_INET6, host) + struct.pack("!H", port)
    else:
        addr = b""
    if len(_addr_cache) > ADDR_CACHE_SIZE:
        _addr_cache.clear()
    _addr_cache[key] = addr
    return addr


class StreamCtx:
    def __init__(self, assembler, mem: MemoryProfile, resend_data_cb=None):
        self.assembler = assembler
        self.resend_data_cb = resend_data_cb
        self.last_act = time.time()
        # Cache format: seq -> (payload, send_time). send_time == 0 means the
        # payload is a retransmit and must not be used for RTT estimation.
        self.cache = {}
        self.acked_seq = 0
        self.mem = mem

        # Congestion control parameters
        self.cwnd = 32.0
        self.ssthresh = float(mem.max_window_packets)
        self.last_loss_time = 0
        self.last_ack_advance_time = time.time()
        self.last_stall_probe = 0

        # RTT estimation
        self.rtt_estimate = 0.1
        self.rtt_alpha = 0.125

        # Event-driven backpressure: producer blocks on this event while the
        # in-flight packet count is at or above cwnd.
        self.window_event = asyncio.Event()
        self.window_event.set()


# ============================================================================
# Crypto & Security
# ============================================================================
class TunnelSecurity:
    def __init__(self, psk: str, mem: MemoryProfile):
        key = hashlib.sha256(psk.encode('utf-8')).digest()
        self.cipher = ChaCha20Poly1305(key)
        self.seen_sequences = OrderedDict()
        self.seq_counter = 0
        self.mem = mem

    def pack_and_encrypt(self, payload: bytes) -> bytes:
        self.seq_counter = (self.seq_counter + 1) & 0xFFFFFFFFFFFFFFFF
        timestamp = int(time.time())
        pad_len = random.getrandbits(4)
        # [FIX] Previously three separate os.urandom() syscalls per packet
        # (4 + 12 + pad_len bytes). At high pps that is a measurable fraction
        # of CPU. Grab everything in one syscall and slice.
        rnd = os.urandom(4 + 12 + pad_len)
        session_tag = rnd[:4]
        nonce = rnd[4:16]
        padding = rnd[16:16 + pad_len]

        meta_header = session_tag + struct.pack("!QQB", self.seq_counter, timestamp, pad_len)
        encrypted = self.cipher.encrypt(nonce, payload + padding, meta_header)
        return meta_header + nonce + encrypted

    def decrypt_and_unpack(self, datagram: bytes) -> Optional[bytes]:
        if len(datagram) < 21 + 12 + 16:
            return None
        meta_header, nonce, ciphertext = datagram[:21], datagram[21:33], datagram[33:]
        seq, timestamp, pad_len = struct.unpack("!QQB", meta_header[4:])

        now = time.time()
        if abs(now - timestamp) > TIMESTAMP_TOLERANCE_SEC:
            return None
        if seq in self.seen_sequences:
            return None

        self.seen_sequences[seq] = now
        if len(self.seen_sequences) > self.mem.seen_seq_limit:
            self.seen_sequences.popitem(last=False)

        try:
            decrypted = self.cipher.decrypt(nonce, ciphertext, meta_header)
            return decrypted[:-pad_len] if pad_len > 0 else decrypted
        except Exception:
            return None


# ============================================================================
# FEC Engine
# ============================================================================
def _fast_xor_bytes(shards: List[bytes], max_len: int) -> bytes:
    """
    XOR a list of equally-sized byte buffers together.

    [FIX] The old implementation used int.from_bytes / int.to_bytes on the
    whole shard. That is fast in the C runtime but allocates a large Python
    int per shard on every call, creating GC pressure at high packet rates.
    When numpy is available we operate directly on uint8 arrays; otherwise
    we fall back to a plain bytearray XOR loop.
    """
    if not shards:
        return b"\x00" * max_len
    if _HAS_NUMPY and max_len >= 64:
        result = _np.frombuffer(shards[0], dtype=_np.uint8).copy()
        for s in shards[1:]:
            result ^= _np.frombuffer(s, dtype=_np.uint8)
        return result.tobytes()
    res = bytearray(shards[0])
    for s in shards[1:]:
        for i in range(min(len(res), len(s))):
            res[i] ^= s[i]
    return bytes(res)


class FECGroupEncoder:
    def __init__(self, data_shards: int, parity_shards: int, mem: MemoryProfile):
        self.n, self.m = data_shards, parity_shards
        if self.m > 127:
            logging.warning(f"[FEC] Parity shards {self.m} exceeds 127, capping to 127.")
            self.m = 127
        if not zfec and self.m > 1:
            logging.warning("[FEC] zfec module missing. Capping parity shards to 1 for XOR fallback.")
            self.m = 1
        # Guard against zfec's 256-shard ceiling. Doing this up front avoids
        # a runtime exception in the middle of a flush.
        if zfec and self.n + self.m > 256:
            new_m = max(0, 256 - self.n)
            logging.warning(f"[FEC] n+m={self.n + self.m} exceeds zfec's 256 limit, capping m to {new_m}.")
            self.m = new_m

        self.mem = mem
        self.group_id = 0
        self.buffer: List[bytes] = []
        self.last_act = time.time()
        self.m_encoded = self.m | 0x80 if zfec else self.m

        # [FIX] zfec.Encoder construction pre-computes the Vandermonde matrix.
        # Building it once per flush discarded the main benefit of using zfec
        # in the first place. Build it once and reuse.
        self._encoder = zfec.Encoder(self.n, self.n + self.m) if (zfec and self.m > 0 and self.n > 0) else None

    def input_packet(self, ciphertext: bytes) -> List[bytes]:
        if self.n <= 0 or self.m <= 0:
            return [ciphertext]
        now = time.time()
        out = []
        # Partial-group flush: keeps the latency bounded for interactive
        # traffic when fewer than n packets are available in a short window.
        if self.buffer and (now - self.last_act > self.mem.fec_flush_interval):
            out.extend(self._flush())

        self.last_act = now
        idx = len(self.buffer)
        fec_payload = struct.pack("!H", len(ciphertext)) + ciphertext
        self.buffer.append(fec_payload)

        out.append(struct.pack("!QBBBH", self.group_id, idx, self.n, self.m_encoded, len(fec_payload)) + fec_payload)
        if len(self.buffer) == self.n:
            out.extend(self._flush())
        return out

    def _flush(self) -> List[bytes]:
        if not self.buffer:
            return []
        out = []
        max_len = max(len(p) for p in self.buffer)
        padded = [p.ljust(max_len, b'\x00') for p in self.buffer]
        while len(padded) < self.n:
            padded.append(b'\x00' * max_len)

        if self._encoder is not None:
            # zfec.encode returns n+m blocks: the first n are the (padded)
            # data blocks, the rest are the parity we care about.
            parity_blocks = self._encoder.encode(padded)[self.n:]
        else:
            parity_blocks = [_fast_xor_bytes(padded, max_len)] * self.m

        for p_idx, p_data in enumerate(parity_blocks, start=self.n):
            out.append(struct.pack("!QBBBH", self.group_id, p_idx, self.n, self.m_encoded, max_len) + p_data)

        self.group_id = (self.group_id + 1) & 0xFFFFFFFFFFFFFFFF
        self.buffer.clear()
        self.last_act = time.time()
        return out


class FECGroupDecoder:
    def __init__(self, timeout_sec: float, max_groups: int = 8192):
        self.groups: Dict[Tuple[str, int], dict] = {}
        self.timeout_sec = timeout_sec
        self.max_groups = max_groups
        self._zfec_warned = False
        # [FIX] Cache zfec.Decoder instances. Constructing one per decode call
        # re-ran the Vandermonde precomputation and negated zfec's C speed.
        self._zfec_decoders: Dict[Tuple[int, int], "zfec.Decoder"] = {}

    def _get_zfec_decoder(self, n: int, m: int):
        key = (n, m)
        dec = self._zfec_decoders.get(key)
        if dec is None:
            dec = zfec.Decoder(n, n + m)
            if len(self._zfec_decoders) > 32:
                self._zfec_decoders.clear()
            self._zfec_decoders[key] = dec
        return dec

    def process_datagram(self, peer_addr, datagram: bytes, fec_enabled: bool) -> List[bytes]:
        if not fec_enabled or len(datagram) < 13:
            return [datagram]
        group_id, idx, n, m_raw, raw_len = struct.unpack("!QBBBH", datagram[:13])
        if 13 + raw_len > len(datagram):
            logging.debug("[FEC] Truncated FEC packet, dropping")
            return []
        use_zfec = bool(m_raw & 0x80)
        m = m_raw & 0x7F

        payload = datagram[13:13 + raw_len]

        # [FIX] Key the group table on source IP only, not (ip, port). NAT
        # rebinding changes the source port mid-session; keying on the full
        # peer address would split a group's shards across two keys and
        # silently prevent recovery.
        peer_ip = peer_addr[0]
        key = (peer_ip, group_id)

        if key not in self.groups:
            # [FIX] We no longer call sweep_stale_groups() from this hot path.
            # That O(n) scan per new group was a quadratic total cost once
            # the table filled up, and it fired on every incoming packet.
            # Cleanup is now driven by a dedicated background task.
            if len(self.groups) >= self.max_groups:
                # [FIX] Returning the raw datagram on overflow was a bug:
                # the caller would treat FEC-framed bytes as ciphertext and
                # silently drop them after a failed decrypt. Return nothing
                # and let the caller skip the packet.
                logging.debug("[FEC] Group table full, dropping shard")
                return []
            self.groups[key] = {'shards': {}, 'n': n, 'm': m, 'time': time.time(), 'use_zfec': use_zfec}

        grp = self.groups[key]
        grp['shards'][idx] = payload
        grp['time'] = time.time()

        recovered = []
        if idx < n and len(payload) >= 2:
            true_len = struct.unpack("!H", payload[:2])[0]
            if true_len <= len(payload) - 2:
                recovered.append(payload[2:2 + true_len])

        rcv_data_idx = {i for i in grp['shards'].keys() if i < n}
        if len(rcv_data_idx) < n and len(grp['shards']) >= n:
            max_len = max(len(s) for s in grp['shards'].values())
            data_shards = {i: grp['shards'][i] for i in rcv_data_idx}
            if len(data_shards) == n - 1:
                if grp.get('use_zfec', False):
                    if zfec:
                        missing_data_idx = [i for i in range(n) if i not in data_shards]
                        if len(missing_data_idx) == 1:
                            parity_indices = [i for i in grp['shards'].keys() if i >= n]
                            if parity_indices:
                                p_idx = min(parity_indices)
                                src_shards = []
                                src_indices = []
                                for s_idx, s_bytes in sorted(data_shards.items()):
                                    src_shards.append(s_bytes.ljust(max_len, b'\x00'))
                                    src_indices.append(s_idx)
                                src_shards.append(grp['shards'][p_idx].ljust(max_len, b'\x00'))
                                src_indices.append(p_idx)
                                if len(src_shards) == n:
                                    try:
                                        decoder = self._get_zfec_decoder(n, m)
                                        decoded = decoder.decode(src_shards, src_indices)
                                        for d_data in decoded:
                                            if len(d_data) >= 2:
                                                true_len = struct.unpack("!H", d_data[:2])[0]
                                                if true_len <= len(d_data) - 2:
                                                    recovered.append(d_data[2:2 + true_len])
                                    except Exception as e:
                                        logging.debug(f"[FEC] zfec decode error: {e}")
                    else:
                        if not self._zfec_warned:
                            logging.warning("[FEC] Peer encoded with zfec, but zfec is missing locally. FEC recovery disabled.")
                            self._zfec_warned = True
                else:
                    try:
                        p_idx = next(i for i in grp['shards'].keys() if i >= n)
                        p_data = grp['shards'][p_idx].ljust(max_len, b'\x00')
                        if _HAS_NUMPY and max_len >= 64:
                            res = _np.frombuffer(p_data, dtype=_np.uint8).copy()
                            for i in data_shards:
                                res ^= _np.frombuffer(data_shards[i].ljust(max_len, b'\x00'), dtype=_np.uint8)
                            recovered_block = res.tobytes()
                        else:
                            res = bytearray(p_data)
                            for i in data_shards:
                                s = data_shards[i].ljust(max_len, b'\x00')
                                for j in range(max_len):
                                    res[j] ^= s[j]
                            recovered_block = bytes(res)
                        if len(recovered_block) >= 2:
                            true_len = struct.unpack("!H", recovered_block[:2])[0]
                            if true_len <= len(recovered_block) - 2:
                                recovered.append(recovered_block[2:2 + true_len])
                    except Exception as e:
                        logging.debug(f"[FEC] XOR recovery error: {e}")

            self.groups.pop(key, None)
        elif len(rcv_data_idx) == n:
            self.groups.pop(key, None)
        return recovered

    def sweep_stale_groups(self):
        now = time.time()
        # [FIX] Take a snapshot of the keys and iterate it once. The old
        # version built a list comprehension of every expired key on every
        # call, which is wasteful when called periodically.
        stale = [k for k, v in list(self.groups.items()) if now - v['time'] > self.timeout_sec]
        for k in stale:
            self.groups.pop(k, None)


# ============================================================================
# Stream Assembler & ARQ
# ============================================================================
class StreamAssembler:
    def __init__(self, mem: MemoryProfile, nack_callback, ack_callback):
        self.mem = mem
        self.writer = None
        self.expected_seq = 0
        self.buffer = {}
        self.connecting = True
        self.timeout = self.mem.assembler_timeout
        self.is_broken = False

        self.nack_callback = nack_callback
        self.ack_callback = ack_callback
        self.last_nack_time = {}
        self.unacked_count = 0
        self.last_ack_time = time.time()

    def set_writer(self, writer):
        self.writer = writer
        if hasattr(self.writer, 'transport') and hasattr(self.writer.transport, 'set_write_buffer_limits'):
            self.writer.transport.set_write_buffer_limits(high=self.mem.tcp_buf_limit)
        self.connecting = False
        self.flush()

    def receive(self, seq: int, payload: bytes):
        if self.is_broken:
            return
        now = time.time()

        if seq < self.expected_seq:
            if now - self.last_ack_time > 0.05:
                if self.ack_callback:
                    self.ack_callback(self.expected_seq)
                self.last_ack_time = now
            return

        if seq >= self.expected_seq:
            if len(self.buffer) < self.mem.assembler_buf_len:
                if seq not in self.buffer:
                    self.buffer[seq] = (payload, now)
            else:
                if seq == self.expected_seq:
                    self.buffer[seq] = (payload, now)
                else:
                    if self.expected_seq not in self.buffer:
                        if now - self.last_nack_time.get(self.expected_seq, 0) > self.mem.nack_cooldown:
                            self.last_nack_time[self.expected_seq] = now
                            if self.nack_callback:
                                self.nack_callback(self.expected_seq)
                    return

        if seq > self.expected_seq and self.expected_seq not in self.buffer:
            if now - self.last_nack_time.get(self.expected_seq, 0) > self.mem.nack_cooldown:
                self.last_nack_time[self.expected_seq] = now
                if self.nack_callback:
                    self.nack_callback(self.expected_seq)

        if self.buffer:
            min_seq = min(self.buffer.keys())
            if min_seq > self.expected_seq:
                if now - self.buffer[min_seq][1] > self.timeout:
                    logging.debug(f"[Assembler] TCP stream timeout at seq {self.expected_seq}. Closing.")
                    self.is_broken = True
                    self.close()
                    return

        self.flush()

    def flush(self):
        if not self.writer or self.connecting or self.is_broken:
            return

        if getattr(self.writer.transport, 'is_closing', lambda: False)():
            self.is_broken = True
            self.close()
            return

        while self.expected_seq in self.buffer:
            # [FIX] Backpressure: check the transport's write buffer before
            # pushing more data. asyncio's writer.write() happily queues bytes
            # until the process OOMs, so without this check a slow downstream
            # TCP peer could blow up the whole tunnel.
            if hasattr(self.writer, 'transport'):
                try:
                    buf_size = self.writer.transport.get_write_buffer_size()
                except Exception:
                    buf_size = 0
                if buf_size > self.mem.tcp_buf_limit:
                    break

            payload, _ = self.buffer.pop(self.expected_seq)
            self.last_nack_time.pop(self.expected_seq, None)
            if payload:
                try:
                    self.writer.write(payload)
                except (ConnectionResetError, BrokenPipeError):
                    self.is_broken = True
                    self.close()
                    break
                except Exception:
                    self.is_broken = True
                    self.close()
                    break
            self.expected_seq += 1
            self.unacked_count += 1

            # [FIX] Immediate ACK after a small batch. The background sweep
            # runs every 100 ms, so waiting for it would stall the sender's
            # window by up to that long on short bursts.
            if self.unacked_count >= ACK_BATCH_THRESHOLD:
                if self.ack_callback:
                    self.ack_callback(self.expected_seq)
                self.unacked_count = 0
                self.last_ack_time = time.time()

    def close(self):
        self.is_broken = True
        self.buffer = {}
        self.last_nack_time = {}
        if self.writer:
            try:
                self.writer.close()
            except Exception:
                pass


class MultiplexFrame:
    @staticmethod
    def pack(stream_id: int, cmd: int, atyp: int, seq: int, host: str, port: int, payload: bytes) -> bytes:
        header = struct.pack("!IBBI", stream_id, cmd, atyp, seq)
        # [FIX] Encoded destination is cached; see _pack_addr.
        return header + _pack_addr(atyp, host, port) + payload

    @staticmethod
    def unpack(data: bytes) -> Tuple[int, int, int, int, str, int, bytes]:
        if len(data) < 10:
            raise ValueError("Packet too short")
        stream_id, cmd, atyp, seq = struct.unpack("!IBBI", data[:10])
        idx = 10
        host = ""
        port = 0
        if atyp == ATYP_IPV4:
            if len(data) < idx + 6:
                raise ValueError("Truncated IPv4 address")
            host = socket.inet_ntoa(data[idx:idx + 4])
            port = struct.unpack("!H", data[idx + 4:idx + 6])[0]
            idx += 6
        elif atyp == ATYP_DOMAIN:
            if len(data) < idx + 1:
                raise ValueError("Truncated domain length")
            d_len = data[idx]
            idx += 1
            if len(data) < idx + d_len + 2:
                raise ValueError("Truncated domain")
            host = data[idx:idx + d_len].decode('utf-8')
            idx += d_len
            port = struct.unpack("!H", data[idx:idx + 2])[0]
            idx += 2
        elif atyp == ATYP_IPV6:
            if len(data) < idx + 18:
                raise ValueError("Truncated IPv6 address")
            host = socket.inet_ntop(socket.AF_INET6, data[idx:idx + 16])
            port = struct.unpack("!H", data[idx + 16:idx + 18])[0]
            idx += 18
        return stream_id, cmd, atyp, seq, host, port, data[idx:]


# ============================================================================
# Engine Base & Anti-OOM Controller
# ============================================================================
class LightconeEngineBase:
    def _setup_direct_socket(self, bind_host: str, bind_port: int) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.mem.udp_buf_size)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.mem.udp_buf_size)
        except Exception as e:
            logging.warning(
                f"[System] Could not scale UDP buffer to {self.mem.udp_buf_size // 1024}KB: {e}. "
                f"Check OS limits."
            )
        sock.setblocking(False)
        sock.bind((bind_host, bind_port))
        return sock

    def _direct_send(self, payload: bytes, addr: Tuple[str, int]):
        enc = self.sec.pack_and_encrypt(payload)

        if getattr(self, "fec_enabled", False):
            if hasattr(self, "fec_encoder") and self.fec_encoder:
                pkts = self.fec_encoder.input_packet(enc)
            else:
                if addr not in self.fec_encs:
                    self.fec_encs[addr] = FECGroupEncoder(self.fec_n, self.fec_m, self.mem)
                pkts = self.fec_encs[addr].input_packet(enc)
        else:
            pkts = [enc]

        # [FIX] Removed the dead `hasattr(self.sock, 'sendmmsg')` branch.
        # Python's stdlib socket object has no sendmmsg method, and the
        # tuple format used there was never valid for the real syscall
        # wrapper anyway. Plain sendto is what actually runs.
        for pkt in pkts:
            try:
                self.sock.sendto(pkt, addr)
            except BlockingIOError:
                pass
            except MemoryError:
                logging.error("[Defense] MemoryError during UDP send! Dropping packet.")
                gc.collect()
            except Exception as e:
                logging.debug(f"[UDP Send] Exception: {e}")

    async def _fec_sweep_loop(self):
        """
        [FIX] Dedicated background task for FEC group cleanup. Previously the
        cleanup was invoked from inside process_datagram whenever the group
        table hit a size threshold, making every incoming packet on a busy
        server do an O(n) scan of the group dict.
        """
        decoder = getattr(self, "fec_decoder", None)
        if decoder is None:
            return
        while True:
            await asyncio.sleep(FEC_SWEEP_INTERVAL)
            try:
                decoder.sweep_stale_groups()
            except Exception as e:
                logging.debug(f"[FEC Sweep] error: {e}")

    async def _fec_flush_loop(self):
        """
        [FIX] Periodic flush of partial FEC groups. Kept as a separate small
        task so the main ARQ sweep does not need to visit every FEC encoder
        on every tick.
        """
        while True:
            await asyncio.sleep(FEC_FLUSH_INTERVAL)
            if not getattr(self, "fec_enabled", False):
                continue
            now = time.time()
            try:
                if hasattr(self, "fec_encoder") and self.fec_encoder:
                    if self.fec_encoder.buffer and (now - self.fec_encoder.last_act > self.mem.fec_flush_interval):
                        if getattr(self, "s_ip", None):
                            target = (self.s_ip, self.s_port)
                            for p in self.fec_encoder._flush():
                                try:
                                    self.sock.sendto(p, target)
                                except Exception:
                                    pass
                elif hasattr(self, "fec_encs"):
                    for addr, enc in list(self.fec_encs.items()):
                        if enc.buffer and (now - enc.last_act > self.mem.fec_flush_interval):
                            for p in enc._flush():
                                try:
                                    self.sock.sendto(p, addr)
                                except Exception:
                                    pass
            except Exception as e:
                logging.debug(f"[FEC Flush] error: {e}")

    async def active_arq_sweep(self, stream_dict: dict):
        while True:
            await asyncio.sleep(ARQ_SWEEP_INTERVAL)
            now = time.time()

            # Evict idle streams proactively when we are close to the cap.
            if len(stream_dict) > self.mem.max_streams * 0.9:
                logging.warning(
                    f"[Memory Defense] High stream count ({len(stream_dict)}). "
                    f"Evicting idle connections."
                )
                sorted_streams = sorted(stream_dict.items(), key=lambda x: x[1].last_act)
                to_drop = int(len(stream_dict) * 0.1)
                for sid, ctx in sorted_streams[:to_drop]:
                    ctx.assembler.close()
                    stream_dict.pop(sid, None)

            for sid, ctx in list(stream_dict.items()):
                if now - ctx.last_act > self.mem.idle_timeout:
                    ctx.assembler.close()
                    stream_dict.pop(sid, None)
                    continue

                asm = ctx.assembler
                if asm.is_broken:
                    continue

                is_idle = (now - ctx.last_act > 1.0)
                if is_idle and not asm.buffer and asm.unacked_count == 0 and not ctx.cache:
                    continue

                if asm.buffer:
                    if min(asm.buffer.keys()) > asm.expected_seq:
                        scan_window = max(32, int(self.mem.max_window_packets * 0.05))
                        end_seq = min(max(asm.buffer.keys()) + 1, asm.expected_seq + scan_window)
                        for m_seq in range(asm.expected_seq, end_seq):
                            if m_seq not in asm.buffer:
                                if now - asm.last_nack_time.get(m_seq, 0) > self.mem.nack_cooldown_slow:
                                    asm.last_nack_time[m_seq] = now
                                    if asm.nack_callback:
                                        asm.nack_callback(m_seq)

                local_buf = 0
                if asm.writer and hasattr(asm.writer, 'transport'):
                    try:
                        local_buf = asm.writer.transport.get_write_buffer_size()
                    except Exception:
                        local_buf = 0

                if asm.unacked_count > 0 and local_buf < self.mem.tcp_buf_limit:
                    if (now - asm.last_ack_time > 0.05) or (asm.unacked_count >= ACK_BATCH_THRESHOLD):
                        if asm.ack_callback:
                            asm.ack_callback(asm.expected_seq)
                        asm.unacked_count = 0
                        asm.last_ack_time = now

                if ctx.cache and (now - ctx.last_ack_advance_time > 2.0):
                    ctx.last_ack_advance_time = now
                    if ctx.acked_seq in ctx.cache and getattr(ctx, 'resend_data_cb', None):
                        ctx.resend_data_cb(ctx.acked_seq, ctx.cache[ctx.acked_seq][0])


# ============================================================================
# Client Engine
# ============================================================================
class ClientEngine(LightconeEngineBase):
    def __init__(self, config: dict):
        self.config = config

        mem_mb = int(config.get("available_memory_mb", 512))
        latency_ms = int(config.get("expected_latency_ms", 100))
        self.mem = MemoryProfile(mem_mb, latency_ms)
        self.mem.apply_user_config(config.get("max_concurrent_streams"))
        self.mem.print_profile()

        self.sec = TunnelSecurity(config["psk"], self.mem)
        self.s_host, self.s_port = config["server_addr"].split(":")
        self.s_port = int(self.s_port)
        self.s_ip = None

        self.fec_n = int(config.get("fec_data_shards", 0))
        self.fec_m = int(config.get("fec_parity_shards", 0))
        self.fec_enabled = self.fec_n > 0 and self.fec_m > 0
        self.fec_encoder = FECGroupEncoder(self.fec_n, self.fec_m, self.mem) if self.fec_enabled else None
        self.fec_encs = {}
        self.fec_decoder = FECGroupDecoder(self.mem.fec_timeout, self.mem.fec_max_groups)

        self.streams: Dict[int, StreamCtx] = {}
        self.udp_sessions: Dict[int, Tuple[Tuple[str, int], asyncio.DatagramTransport, float]] = {}
        self.next_id = 1
        self.sock = None

    async def resolve_ddns_once(self):
        try:
            info = await asyncio.to_thread(socket.getaddrinfo, self.s_host, self.s_port)
            if info:
                valid_ips = [item[4][0] for item in info]
                if self.s_ip not in valid_ips:
                    self.s_ip = valid_ips[0]
                    logging.info(f"[DDNS] Target IP updated: {self.s_ip}")
        except Exception:
            pass

    async def resolve_ddns_loop(self):
        while True:
            await asyncio.sleep(60)
            await self.resolve_ddns_once()

    async def heartbeat(self):
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL_SEC)
            if self.s_ip and self.sock:
                self._direct_send(
                    MultiplexFrame.pack(0, CMD_HEARTBEAT, ATYP_IPV4, 0, "0.0.0.0", 0, b""),
                    (self.s_ip, self.s_port),
                )

    async def sweep(self):
        while True:
            await asyncio.sleep(10)
            now = time.time()
            for sid in [s for s, (_, _, act) in list(self.udp_sessions.items()) if now - act > self.mem.idle_timeout]:
                item = self.udp_sessions.pop(sid, None)
                if item:
                    item[1].close()

    def _read_from_os(self):
        try:
            processed = 0
            while True:
                try:
                    data, addr = self.sock.recvfrom(65536)
                    for dpkt in self.fec_decoder.process_datagram(addr, data, self.fec_enabled):
                        dec = self.sec.decrypt_and_unpack(dpkt)
                        if not dec:
                            continue
                        try:
                            sid, cmd, at, seq, rh, rp, pay = MultiplexFrame.unpack(dec)
                        except Exception:
                            continue

                        if cmd == CMD_TCP_DATA and sid in self.streams:
                            ctx = self.streams[sid]
                            ctx.last_act = time.time()
                            ctx.assembler.receive(seq, pay)

                        elif cmd == CMD_TCP_ACK and sid in self.streams:
                            ctx = self.streams[sid]
                            now = time.time()
                            if seq > ctx.acked_seq:
                                acked_count = seq - ctx.acked_seq
                                for ack_seq in range(ctx.acked_seq, seq):
                                    if ack_seq in ctx.cache:
                                        send_time = ctx.cache[ack_seq][1]
                                        # Karn's algorithm: skip RTT samples
                                        # for retransmitted packets.
                                        if send_time > 0:
                                            rtt = now - send_time
                                            if rtt > 0:
                                                ctx.rtt_estimate = (1 - ctx.rtt_alpha) * ctx.rtt_estimate + ctx.rtt_alpha * rtt
                                ctx.acked_seq = seq
                                ctx.last_ack_advance_time = now

                                if ctx.cwnd < ctx.ssthresh:
                                    ctx.cwnd += acked_count * 2
                                else:
                                    ctx.cwnd += acked_count
                                ctx.cwnd = min(ctx.cwnd, float(self.mem.max_window_packets))

                                keys_to_del = [k for k in ctx.cache.keys() if k < seq]
                                for k in keys_to_del:
                                    del ctx.cache[k]

                                ctx.window_event.set()

                        elif cmd == CMD_TCP_RESEND and sid in self.streams:
                            ctx = self.streams[sid]
                            ctx.last_act = time.time()
                            now = time.time()
                            if now - ctx.last_loss_time > 0.5:
                                ctx.ssthresh = max(int(ctx.cwnd * 0.8), 256)
                                ctx.cwnd = ctx.ssthresh
                                ctx.last_loss_time = now
                            if seq in ctx.cache:
                                payload, _ = ctx.cache[seq]
                                ctx.cache[seq] = (payload, 0)
                                self._direct_send(
                                    MultiplexFrame.pack(sid, CMD_TCP_DATA, at, seq, rh, rp, payload),
                                    (self.s_ip, self.s_port),
                                )

                        elif cmd == CMD_UDP_DATA and sid in self.udp_sessions:
                            ca, ut, _ = self.udp_sessions[sid]
                            self.udp_sessions[sid] = (ca, ut, time.time())
                            if at == ATYP_IPV4:
                                ab = socket.inet_aton(rh)
                            elif at == ATYP_DOMAIN:
                                hb = rh.encode('utf-8')
                                ab = struct.pack("!B", len(hb)) + hb
                            elif at == ATYP_IPV6:
                                ab = socket.inet_pton(socket.AF_INET6, rh)
                            else:
                                continue
                            ut.sendto(struct.pack("!HBB", 0, 0, at) + ab + struct.pack("!H", rp) + pay, ca)

                        elif cmd == CMD_HEARTBEAT:
                            pass

                        elif cmd == CMD_TCP_CLOSE:
                            ctx = self.streams.pop(sid, None)
                            if ctx:
                                ctx.assembler.close()

                    processed += 1
                    if processed >= 200:
                        loop = asyncio.get_running_loop()
                        loop.call_soon(self._read_from_os)
                        return
                except BlockingIOError:
                    break
                except ConnectionResetError:
                    pass
                except Exception as e:
                    logging.debug(f"[Client UDP] read error: {e}")
        except MemoryError:
            logging.error("[Defense] MemoryError during UDP receive burst! Forcing garbage collection.")
            gc.collect()

    async def handle_socks5(self, reader, writer):
        sid = None
        atyp = ATYP_IPV4
        host = ""
        port = 0
        u_trans = None
        try:
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

            if cmd == 0x01:
                if len(self.streams) >= self.mem.max_streams:
                    writer.close()
                    return
                writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                sid = self.next_id
                self.next_id += 1

                def on_nack(m_seq):
                    self._direct_send(
                        MultiplexFrame.pack(sid, CMD_TCP_RESEND, atyp, m_seq, host, port, b""),
                        (self.s_ip, self.s_port),
                    )

                def on_ack(ack_seq):
                    self._direct_send(
                        MultiplexFrame.pack(sid, CMD_TCP_ACK, atyp, ack_seq, host, port, b""),
                        (self.s_ip, self.s_port),
                    )

                def on_resend(m_seq, pay):
                    self._direct_send(
                        MultiplexFrame.pack(sid, CMD_TCP_DATA, atyp, m_seq, host, port, pay),
                        (self.s_ip, self.s_port),
                    )

                ctx = StreamCtx(StreamAssembler(self.mem, on_nack, on_ack), self.mem, resend_data_cb=on_resend)
                ctx.assembler.set_writer(writer)
                self.streams[sid] = ctx
                seq = 0
                pkt_cnt = 0

                while True:
                    try:
                        data = await reader.read(65536)
                        if not data:
                            break
                        ctx.last_act = time.time()

                        for i in range(0, len(data), MAX_PAYLOAD_SIZE):
                            chunk = data[i:i + MAX_PAYLOAD_SIZE]

                            while seq - ctx.acked_seq >= int(ctx.cwnd):
                                if ctx.assembler.is_broken or sid not in self.streams:
                                    break
                                ctx.window_event.clear()
                                try:
                                    await asyncio.wait_for(ctx.window_event.wait(), timeout=0.2)
                                except asyncio.TimeoutError:
                                    ctx.last_stall_probe = time.time()
                                    if ctx.acked_seq in ctx.cache:
                                        self._direct_send(
                                            MultiplexFrame.pack(sid, CMD_TCP_DATA, atyp, ctx.acked_seq, host, port, ctx.cache[ctx.acked_seq][0]),
                                            (self.s_ip, self.s_port),
                                        )

                            if ctx.assembler.is_broken or sid not in self.streams:
                                break

                            ctx.cache[seq] = (chunk, time.time())
                            self._direct_send(
                                MultiplexFrame.pack(sid, CMD_TCP_DATA, atyp, seq, host, port, chunk),
                                (self.s_ip, self.s_port),
                            )
                            seq += 1
                            pkt_cnt += 1
                            if pkt_cnt % 64 == 0:
                                await asyncio.sleep(0)
                    except MemoryError:
                        logging.error("[Defense] MemoryError during Client TCP Read! Dropping chunk.")
                        gc.collect()
                        await asyncio.sleep(0.1)

                # Half-close drain: give the ARQ cache a chance to flush.
                drain_start = time.time()
                while ctx.cache and not ctx.assembler.is_broken and (time.time() - drain_start < 5.0):
                    await asyncio.sleep(0.05)

            elif cmd == 0x03:
                if len(self.udp_sessions) >= self.mem.max_streams:
                    writer.close()
                    return
                sid = self.next_id
                self.next_id += 1

                class URelay(asyncio.DatagramProtocol):
                    def __init__(self, eng, sid):
                        self.eng = eng
                        self.sid = sid
                        self.trans = None

                    def connection_made(self, tr):
                        self.trans = tr

                    def datagram_received(self, dt, addr):
                        if len(dt) < 10:
                            return
                        _, _, u_at = struct.unpack("!HBB", dt[:4])
                        idx = 4
                        if u_at == ATYP_IPV4:
                            dh = socket.inet_ntoa(dt[idx:idx + 4])
                            dp = struct.unpack("!H", dt[idx + 4:idx + 6])[0]
                            idx += 6
                        elif u_at == ATYP_DOMAIN:
                            dl = dt[idx]
                            idx += 1
                            dh = dt[idx:idx + dl].decode('utf-8')
                            idx += dl
                            dp = struct.unpack("!H", dt[idx:idx + 2])[0]
                            idx += 2
                        elif u_at == ATYP_IPV6:
                            dh = socket.inet_ntop(socket.AF_INET6, dt[idx:idx + 16])
                            dp = struct.unpack("!H", dt[idx + 16:idx + 18])[0]
                            idx += 18
                        else:
                            return
                        self.eng.udp_sessions[self.sid] = (addr, self.trans, time.time())
                        self.eng._direct_send(
                            MultiplexFrame.pack(self.sid, CMD_UDP_DATA, u_at, 0, dh, dp, dt[idx:]),
                            (self.eng.s_ip, self.eng.s_port),
                        )

                loop = asyncio.get_running_loop()
                u_trans, _ = await loop.create_datagram_endpoint(lambda: URelay(self, sid), local_addr=("0.0.0.0", 0))
                writer.write(struct.pack("!BBBB4sH", 0x05, 0x00, 0x00, 0x01, socket.inet_aton("127.0.0.1"), u_trans.get_extra_info("sockname")[1]))
                await writer.drain()
                while await reader.read(1024):
                    pass

        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        except Exception as e:
            logging.debug(f"[Socks5] error: {e}")
        finally:
            writer.close()
            if u_trans:
                u_trans.close()
            if sid is not None:
                self.udp_sessions.pop(sid, None)
                ctx = self.streams.pop(sid, None)
                if ctx:
                    ctx.assembler.close()
                    try:
                        self._direct_send(
                            MultiplexFrame.pack(sid, CMD_TCP_CLOSE, atyp, 0, host, port, b""),
                            (self.s_ip, self.s_port),
                        )
                    except Exception:
                        pass

    async def handle_http_proxy(self, reader, writer):
        sid = None
        atyp = ATYP_DOMAIN
        host = ""
        port = 80
        try:
            line = await reader.readline()
            if not line:
                return
            parts = line.decode('utf-8', errors='ignore').split()
            if len(parts) < 2 or len(self.streams) >= self.mem.max_streams:
                writer.close()
                return

            method, url = parts[0], parts[1]
            sid = self.next_id
            self.next_id += 1

            if method == "CONNECT":
                host, port_str = url.rsplit(":", 1) if ":" in url else (url, "443")
                port = int(port_str) if port_str.isdigit() else 443
                while True:
                    if (await reader.readline()) in (b"\r\n", b"\n", b""):
                        break
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
                seq = 0
            else:
                parsed = urlparse(url)
                host, port = parsed.hostname or "", parsed.port or 80
                seq = 0
                self._direct_send(
                    MultiplexFrame.pack(sid, CMD_TCP_DATA, atyp, seq, host, port, line),
                    (self.s_ip, self.s_port),
                )
                seq += 1

            def on_nack(ms):
                self._direct_send(
                    MultiplexFrame.pack(sid, CMD_TCP_RESEND, atyp, ms, host, port, b""),
                    (self.s_ip, self.s_port),
                )

            def on_ack(ak):
                self._direct_send(
                    MultiplexFrame.pack(sid, CMD_TCP_ACK, atyp, ak, host, port, b""),
                    (self.s_ip, self.s_port),
                )

            def on_resend(ms, pay):
                self._direct_send(
                    MultiplexFrame.pack(sid, CMD_TCP_DATA, atyp, ms, host, port, pay),
                    (self.s_ip, self.s_port),
                )

            ctx = StreamCtx(StreamAssembler(self.mem, on_nack, on_ack), self.mem, resend_data_cb=on_resend)
            ctx.assembler.set_writer(writer)
            self.streams[sid] = ctx
            if method != "CONNECT":
                ctx.cache[0] = (line, time.time())

            while True:
                data = await reader.read(65536)
                if not data:
                    break
                ctx.last_act = time.time()

                for i in range(0, len(data), MAX_PAYLOAD_SIZE):
                    chunk = data[i:i + MAX_PAYLOAD_SIZE]

                    while seq - ctx.acked_seq >= int(ctx.cwnd):
                        if ctx.assembler.is_broken or sid not in self.streams:
                            break
                        ctx.window_event.clear()
                        try:
                            await asyncio.wait_for(ctx.window_event.wait(), timeout=0.2)
                        except asyncio.TimeoutError:
                            ctx.last_stall_probe = time.time()
                            if ctx.acked_seq in ctx.cache:
                                self._direct_send(
                                    MultiplexFrame.pack(sid, CMD_TCP_DATA, atyp, ctx.acked_seq, host, port, ctx.cache[ctx.acked_seq][0]),
                                    (self.s_ip, self.s_port),
                                )

                    if ctx.assembler.is_broken or sid not in self.streams:
                        break
                    ctx.cache[seq] = (chunk, time.time())
                    self._direct_send(
                        MultiplexFrame.pack(sid, CMD_TCP_DATA, atyp, seq, host, port, chunk),
                        (self.s_ip, self.s_port),
                    )
                    seq += 1

            drain_start = time.time()
            while ctx.cache and not ctx.assembler.is_broken and (time.time() - drain_start < 5.0):
                await asyncio.sleep(0.05)

        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        except Exception as e:
            logging.debug(f"[HTTP Proxy] error: {e}")
        finally:
            writer.close()
            ctx = self.streams.pop(sid, None)
            if ctx:
                ctx.assembler.close()
                try:
                    self._direct_send(
                        MultiplexFrame.pack(sid, CMD_TCP_CLOSE, atyp, 0, host, port, b""),
                        (self.s_ip, self.s_port),
                    )
                except Exception:
                    pass

    async def start(self):
        loop = asyncio.get_running_loop()
        await self.resolve_ddns_once()
        asyncio.create_task(self.resolve_ddns_loop())

        self.sock = self._setup_direct_socket("0.0.0.0", 0)
        loop.add_reader(self.sock.fileno(), self._read_from_os)

        # [FIX] FEC cleanup and flush are now separate tasks instead of being
        # piggybacked on the ARQ sweep or the receive hot path.
        asyncio.create_task(self._fec_sweep_loop())
        asyncio.create_task(self._fec_flush_loop())
        asyncio.create_task(self.sweep())
        asyncio.create_task(self.active_arq_sweep(self.streams))
        asyncio.create_task(self.heartbeat())

        s_port = int(self.config.get("socks_port", 1080))
        h_port = int(self.config.get("http_port", 8080))
        ss = await asyncio.start_server(self.handle_socks5, "0.0.0.0", s_port)
        hs = await asyncio.start_server(self.handle_http_proxy, "0.0.0.0", h_port)

        logging.info(f"[Client] SOCKS5: {s_port} | HTTP: {h_port} | Engine & Async FEC Active")
        try:
            await asyncio.gather(ss.serve_forever(), hs.serve_forever())
        finally:
            if self.sock:
                self.sock.close()


# ============================================================================
# Server Engine
# ============================================================================
class ServerEngine(LightconeEngineBase):
    def __init__(self, config: dict):
        self.config = config
        mem_mb = int(config.get("available_memory_mb", 512))
        latency_ms = int(config.get("expected_latency_ms", 100))
        self.mem = MemoryProfile(mem_mb, latency_ms)
        self.mem.apply_user_config(config.get("max_concurrent_streams"))
        self.mem.print_profile()

        self.sec = TunnelSecurity(config["psk"], self.mem)
        self.fec_n = int(config.get("fec_data_shards", 0))
        self.fec_m = int(config.get("fec_parity_shards", 0))
        self.fec_enabled = self.fec_n > 0 and self.fec_m > 0
        self.fec_encs = {}
        self.fec_decoder = FECGroupDecoder(self.mem.fec_timeout, self.mem.fec_max_groups)

        self.tcp_conns: Dict[int, StreamCtx] = {}
        self.udp_nat: Dict[int, object] = {}
        self.sock = None

    async def sweep(self):
        while True:
            await asyncio.sleep(10)
            now = time.time()
            for sid in list(self.udp_nat.keys()):
                val = self.udp_nat[sid]
                if isinstance(val, tuple) and now - val[1] > self.mem.idle_timeout:
                    item = self.udp_nat.pop(sid, None)
                    if item and isinstance(item, tuple):
                        item[0].close()

    def _read_from_os(self):
        try:
            processed = 0
            while True:
                try:
                    data, addr = self.sock.recvfrom(65536)
                    for dpkt in self.fec_decoder.process_datagram(addr, data, getattr(self, "fec_enabled", False)):
                        dec = self.sec.decrypt_and_unpack(dpkt)
                        if not dec:
                            continue
                        try:
                            sid, cmd, at, seq, rh, rp, pay = MultiplexFrame.unpack(dec)
                        except Exception:
                            continue

                        if cmd == CMD_TCP_DATA:
                            if sid not in self.tcp_conns:
                                if len(self.tcp_conns) >= self.mem.max_streams:
                                    continue

                                def on_nack(ms, a=addr, i=sid, ta=at, th=rh, tp=rp):
                                    self._direct_send(MultiplexFrame.pack(i, CMD_TCP_RESEND, ta, ms, th, tp, b""), a)

                                def on_ack(ak, a=addr, i=sid, ta=at, th=rh, tp=rp):
                                    self._direct_send(MultiplexFrame.pack(i, CMD_TCP_ACK, ta, ak, th, tp, b""), a)

                                def on_resend(ms, pay, a=addr, i=sid, ta=at, th=rh, tp=rp):
                                    self._direct_send(MultiplexFrame.pack(i, CMD_TCP_DATA, ta, ms, th, tp, pay), a)

                                ctx = StreamCtx(StreamAssembler(self.mem, on_nack, on_ack), self.mem, resend_data_cb=on_resend)
                                self.tcp_conns[sid] = ctx
                                asyncio.create_task(self._pipe(sid, at, rh, rp, addr))

                            ctx = self.tcp_conns.get(sid)
                            if ctx:
                                ctx.last_act = time.time()
                                ctx.assembler.receive(seq, pay)

                        elif cmd == CMD_TCP_ACK and sid in self.tcp_conns:
                            ctx = self.tcp_conns[sid]
                            now = time.time()
                            if seq > ctx.acked_seq:
                                acked_count = seq - ctx.acked_seq
                                for ack_seq in range(ctx.acked_seq, seq):
                                    if ack_seq in ctx.cache:
                                        send_time = ctx.cache[ack_seq][1]
                                        if send_time > 0:
                                            rtt = now - send_time
                                            if rtt > 0:
                                                ctx.rtt_estimate = (1 - ctx.rtt_alpha) * ctx.rtt_estimate + ctx.rtt_alpha * rtt
                                ctx.acked_seq = seq
                                ctx.last_ack_advance_time = now

                                if ctx.cwnd < ctx.ssthresh:
                                    ctx.cwnd += acked_count * 2
                                else:
                                    ctx.cwnd += acked_count
                                ctx.cwnd = min(ctx.cwnd, float(self.mem.max_window_packets))

                                keys_to_del = [k for k in ctx.cache.keys() if k < seq]
                                for k in keys_to_del:
                                    del ctx.cache[k]

                                ctx.window_event.set()

                        elif cmd == CMD_TCP_RESEND and sid in self.tcp_conns:
                            ctx = self.tcp_conns[sid]
                            ctx.last_act = time.time()
                            now = time.time()
                            if now - ctx.last_loss_time > 0.5:
                                ctx.ssthresh = max(int(ctx.cwnd * 0.8), 256)
                                ctx.cwnd = ctx.ssthresh
                                ctx.last_loss_time = now
                            if seq in ctx.cache:
                                payload, _ = ctx.cache[seq]
                                ctx.cache[seq] = (payload, 0)
                                self._direct_send(
                                    MultiplexFrame.pack(sid, CMD_TCP_DATA, at, seq, rh, rp, payload),
                                    addr,
                                )

                        elif cmd == CMD_UDP_DATA:
                            if sid not in self.udp_nat:
                                self.udp_nat[sid] = "creating"

                                async def create_udp(seng, s_id, t_ca, p_pay, p_rh, p_rp):
                                    try:
                                        loop = asyncio.get_running_loop()

                                        class FullConeUDPProtocol(asyncio.DatagramProtocol):
                                            def __init__(self, s, i, c):
                                                self.s = s
                                                self.i = i
                                                self.c = c

                                            def connection_made(self, tr):
                                                self.tr = tr

                                            def datagram_received(self, r_dt, r_addr):
                                                r_ip, r_port = r_addr[0], r_addr[1]
                                                r_at = ATYP_IPV6 if ":" in r_ip else ATYP_IPV4
                                                self.s._direct_send(
                                                    MultiplexFrame.pack(self.i, CMD_UDP_DATA, r_at, 0, r_ip, r_port, r_dt),
                                                    self.c,
                                                )

                                        u_tr, _ = await loop.create_datagram_endpoint(
                                            lambda: FullConeUDPProtocol(seng, s_id, t_ca),
                                            local_addr=("0.0.0.0", 0),
                                        )
                                        seng.udp_nat[s_id] = (u_tr, time.time())
                                        u_tr.sendto(p_pay, (p_rh, p_rp))
                                    except Exception:
                                        seng.udp_nat.pop(s_id, None)

                                asyncio.create_task(create_udp(self, sid, addr, pay, rh, rp))
                            elif isinstance(self.udp_nat.get(sid), tuple):
                                u_tr, _ = self.udp_nat[sid]
                                self.udp_nat[sid] = (u_tr, time.time())
                                u_tr.sendto(pay, (rh, rp))

                        elif cmd == CMD_HEARTBEAT:
                            self._direct_send(
                                MultiplexFrame.pack(0, CMD_HEARTBEAT, ATYP_IPV4, 0, "0.0.0.0", 0, b""),
                                addr,
                            )

                        elif cmd == CMD_TCP_CLOSE:
                            ctx = self.tcp_conns.pop(sid, None)
                            if ctx:
                                ctx.assembler.close()

                    processed += 1
                    if processed >= 200:
                        loop = asyncio.get_running_loop()
                        loop.call_soon(self._read_from_os)
                        return
                except BlockingIOError:
                    break
                except ConnectionResetError:
                    pass
                except Exception as e:
                    logging.debug(f"[Server UDP] read error: {e}")
        except MemoryError:
            logging.error("[Defense] MemoryError during Server UDP burst! Initiating GC.")
            gc.collect()

    async def _pipe(self, sid, at, h, p, ca):
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(h, p), timeout=CONNECT_TIMEOUT_SEC)
        except Exception:
            self.tcp_conns.pop(sid, None)
            self._direct_send(MultiplexFrame.pack(sid, CMD_TCP_CLOSE, at, 0, h, p, b""), ca)
            return

        ctx = self.tcp_conns.get(sid)
        if ctx:
            ctx.assembler.set_writer(writer)
        else:
            writer.close()
            return

        seq = 0
        pkt_cnt = 0
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                ctx.last_act = time.time()

                for i in range(0, len(data), MAX_PAYLOAD_SIZE):
                    chunk = data[i:i + MAX_PAYLOAD_SIZE]

                    while seq - ctx.acked_seq >= int(ctx.cwnd):
                        if ctx.assembler.is_broken or sid not in self.tcp_conns:
                            break
                        ctx.window_event.clear()
                        try:
                            await asyncio.wait_for(ctx.window_event.wait(), timeout=0.2)
                        except asyncio.TimeoutError:
                            ctx.last_stall_probe = time.time()
                            if ctx.acked_seq in ctx.cache:
                                self._direct_send(
                                    MultiplexFrame.pack(sid, CMD_TCP_DATA, at, ctx.acked_seq, h, p, ctx.cache[ctx.acked_seq][0]),
                                    ca,
                                )

                    if ctx.assembler.is_broken or sid not in self.tcp_conns:
                        break
                    ctx.cache[seq] = (chunk, time.time())
                    self._direct_send(MultiplexFrame.pack(sid, CMD_TCP_DATA, at, seq, h, p, chunk), ca)
                    seq += 1
                    pkt_cnt += 1
                    if pkt_cnt % 64 == 0:
                        await asyncio.sleep(0)

            drain_start = time.time()
            while ctx.cache and not ctx.assembler.is_broken and (time.time() - drain_start < 5.0):
                await asyncio.sleep(0.05)

        except MemoryError:
            logging.error("[Defense] MemoryError during Server TCP Read! Dropping chunk.")
            gc.collect()
            await asyncio.sleep(0.1)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        except Exception as e:
            logging.debug(f"[Server Pipe] error: {e}")
        finally:
            writer.close()
            ctx = self.tcp_conns.pop(sid, None)
            if ctx:
                ctx.assembler.close()
                self._direct_send(MultiplexFrame.pack(sid, CMD_TCP_CLOSE, at, 0, h, p, b""), ca)

    async def start(self):
        loop = asyncio.get_running_loop()
        h, p = self.config["server_addr"].split(":")
        p = int(p)

        self.sock = self._setup_direct_socket(h, p)
        loop.add_reader(self.sock.fileno(), self._read_from_os)

        # [FIX] Dedicated FEC cleanup / flush tasks.
        asyncio.create_task(self._fec_sweep_loop())
        asyncio.create_task(self._fec_flush_loop())
        asyncio.create_task(self.sweep())
        asyncio.create_task(self.active_arq_sweep(self.tcp_conns))

        logging.info(f"[Server] Online at {h}:{p} | Engine & Async FEC Active")
        try:
            await asyncio.Event().wait()
        finally:
            if self.sock:
                self.sock.close()


def apply_resource_limits(limit_mb: int):
    if sys.platform != "win32":
        try:
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            target = 65535 if hard == resource.RLIM_INFINITY else hard
            resource.setrlimit(resource.RLIMIT_NOFILE, (max(target, soft), target))

            # [FIX] RLIMIT_AS limits virtual address space, not resident
            # memory. Python plus common C extensions (numpy, zfec,
            # cryptography) mmap well beyond the "intended" memory budget
            # before any real traffic flows, so a tight limit here caused
            # spurious MemoryError. We use a 4x multiplier as a soft safety
            # net only; for real memory enforcement use cgroups (Docker)
            # or systemd's MemoryMax.
            if limit_mb > 0:
                limit_bytes = int(limit_mb * 1024 * 1024) * 4
                soft_mem, hard_mem = resource.getrlimit(resource.RLIMIT_AS)
                new_soft = limit_bytes
                if hard_mem == resource.RLIM_INFINITY:
                    new_hard = limit_bytes * 2
                else:
                    new_hard = max(hard_mem, limit_bytes * 2)
                if new_hard < new_soft:
                    new_hard = new_soft
                resource.setrlimit(resource.RLIMIT_AS, (new_soft, new_hard))
        except Exception as e:
            logging.debug(f"[System] Could not apply resource limits: {e}")


def reset_logging(config: dict):
    root_logger = logging.getLogger()
    for h in root_logger.handlers[:]:
        root_logger.removeHandler(h)
        h.close()
    logging.basicConfig(
        level=getattr(logging, config.get("log_level", "info").upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(message)s",
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("config")
    args = parser.parse_args()

    cfg_path = os.path.abspath(args.config)
    if not os.path.exists(cfg_path):
        sys.exit(1)

    with open(cfg_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    reset_logging(config)
    logging.info(f"[System] --------------------------------------------------")
    logging.info(f"[System] Loaded strict configuration from: {cfg_path}")

    try:
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        logging.info("[System] uvloop active")
    except ImportError:
        pass

    apply_resource_limits(int(config.get("available_memory_mb", 512)))
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    role = config.get("role", "client").lower()
    engine = ClientEngine(config) if role == "client" else ServerEngine(config)

    try:
        loop.run_until_complete(engine.start())
    except (KeyboardInterrupt, SystemExit):
        logging.info("[System] Received stop signal, shutting down elegantly...")
    finally:
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()


if __name__ == "__main__":
    main()
