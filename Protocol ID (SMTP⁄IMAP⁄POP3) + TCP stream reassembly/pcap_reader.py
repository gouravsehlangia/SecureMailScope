"""
backend.parser.pcap_reader
~~~~~~~~~~~~~~~~~~~~~~~~~~
Robust, dual-engine PCAP / PCAPNG packet reader.
- Engine 1: Pure-Python high-speed binary parser (zero external dependencies).
  Supports standard PCAP (microsecond & nanosecond, big & little endian)
  and PCAPNG (Enhanced Packet Blocks).
- Engine 2: Scapy reader adapter (uses Scapy if installed).

Both engines emit normalized `PacketRecord` dataclass objects.
"""

import struct
import socket
import os
from typing import Generator, Optional, Tuple, Dict, Any
from .models import PacketRecord

# Try importing Scapy
try:
    from scapy.all import PcapReader as ScapyPcapReader, IP, IPv6, TCP, Ether
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


class PcapReaderError(Exception):
    """Raised when parsing fails on corrupted or unsupported PCAP files."""
    pass


class PurePythonPcapReader:
    """
    Pure Python parser for PCAP and PCAPNG files.
    Requires no native C libraries, WinPcap, or Npcap.
    """

    PCAP_MAGIC_MICRO_BE = 0xa1b2c3d4
    PCAP_MAGIC_MICRO_LE = 0xd4c3b2a1
    PCAP_MAGIC_NANO_BE = 0xa1b23c4d
    PCAP_MAGIC_NANO_LE = 0x4d3cb2a1
    PCAPNG_MAGIC = 0x0a0d0d0a

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.is_pcapng = False
        self.endianness = "<"
        self.is_nanosecond = False
        self.link_type = 1  # 1 = LINKTYPE_ETHERNET, 113 = LINKTYPE_LINUX_SLL, 101 = LINKTYPE_RAW

    def read_packets(self) -> Generator[PacketRecord, None, None]:
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"PCAP file not found: {self.filepath}")

        with open(self.filepath, "rb") as f:
            magic_bytes = f.read(4)
            if len(magic_bytes) < 4:
                raise PcapReaderError("File too short to be a valid PCAP/PCAPNG capture.")

            magic = struct.unpack(">I", magic_bytes)[0]
            if magic == self.PCAPNG_MAGIC:
                self.is_pcapng = True
                f.seek(0)
                yield from self._read_pcapng(f)
            elif magic in (self.PCAP_MAGIC_MICRO_BE, self.PCAP_MAGIC_NANO_BE):
                self.endianness = ">"
                self.is_nanosecond = (magic == self.PCAP_MAGIC_NANO_BE)
                yield from self._read_classic_pcap(f)
            else:
                magic_le = struct.unpack("<I", magic_bytes)[0]
                if magic_le in (self.PCAP_MAGIC_MICRO_BE, self.PCAP_MAGIC_NANO_BE):
                    self.endianness = "<"
                    self.is_nanosecond = (magic_le == self.PCAP_MAGIC_NANO_BE)
                    yield from self._read_classic_pcap(f)
                else:
                    raise PcapReaderError(f"Unsupported PCAP magic number: 0x{magic:08x}")

    def _read_classic_pcap(self, f) -> Generator[PacketRecord, None, None]:
        # Header is 24 bytes: magic(4) + ver_major(2) + ver_minor(2) + thiszone(4) + sigfigs(4) + snaplen(4) + network(4)
        header_data = f.read(20)
        if len(header_data) < 20:
            raise PcapReaderError("Corrupt PCAP global header.")

        e = self.endianness
        _, _, _, _, _, network = struct.unpack(f"{e}HHIIII", header_data)
        self.link_type = network

        packet_index = 0
        while True:
            pkt_hdr = f.read(16)
            if not pkt_hdr or len(pkt_hdr) < 16:
                break

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{e}IIII", pkt_hdr)
            raw_data = f.read(incl_len)
            if len(raw_data) < incl_len:
                break

            timestamp = ts_sec + (ts_usec / 1e9 if self.is_nanosecond else ts_usec / 1e6)
            packet_index += 1

            parsed_pkt = self._parse_network_frame(raw_data, timestamp, packet_index, self.link_type)
            if parsed_pkt:
                yield parsed_pkt

    def _read_pcapng(self, f) -> Generator[PacketRecord, None, None]:
        packet_index = 0
        e = "<"
        ts_resolutions = [1e-6]  # default microseconds per interface

        while True:
            block_hdr = f.read(8)
            if not block_hdr or len(block_hdr) < 8:
                break

            block_type, block_len = struct.unpack(f"{e}II", block_hdr)
            if block_len < 12:
                break

            body_len = block_len - 12
            body_data = f.read(body_len)
            trailer = f.read(4)  # block_total_length repeat

            # Section Header Block
            if block_type == 0x0A0D0D0A:
                if len(body_data) >= 4:
                    bom = struct.unpack(">I", body_data[0:4])[0]
                    e = ">" if bom == 0x1A2B3C4D else "<"
            # Interface Description Block
            elif block_type == 0x00000001:
                # Link type is at offset 0
                if len(body_data) >= 4:
                    link_type = struct.unpack(f"{e}H", body_data[0:2])[0]
                    self.link_type = link_type
                    # Parse options for if_tsresol (code 9)
                    ts_res = 1e-6
                    opt_offset = 8
                    while opt_offset + 4 <= len(body_data):
                        code, opt_len = struct.unpack(f"{e}HH", body_data[opt_offset:opt_offset+4])
                        if code == 0:  # opt_endofopt
                            break
                        if code == 9 and opt_offset + 4 + opt_len <= len(body_data):
                            raw_val = body_data[opt_offset+4]
                            if raw_val & 0x80:
                                ts_res = 2 ** -(raw_val & 0x7F)
                            else:
                                ts_res = 10 ** -raw_val
                        padded_len = (opt_len + 3) & ~3
                        opt_offset += 4 + padded_len
                    ts_resolutions.append(ts_res)
            # Enhanced Packet Block
            elif block_type == 0x00000006:
                if len(body_data) >= 20:
                    if_id, ts_high, ts_low, cap_len, orig_len = struct.unpack(f"{e}IIIII", body_data[0:20])
                    raw_data = body_data[20:20 + cap_len]
                    ts_res = ts_resolutions[if_id] if if_id < len(ts_resolutions) else 1e-6
                    raw_ts = (ts_high << 32) | ts_low
                    timestamp = raw_ts * ts_res
                    packet_index += 1

                    parsed_pkt = self._parse_network_frame(raw_data, timestamp, packet_index, self.link_type)
                    if parsed_pkt:
                        yield parsed_pkt

    def _parse_network_frame(self, data: bytes, timestamp: float, index: int, link_type: int) -> Optional[PacketRecord]:
        ip_offset = 0

        # Ethernet: 14 bytes header
        if link_type == 1:
            if len(data) < 14:
                return None
            eth_type = struct.unpack(">H", data[12:14])[0]
            ip_offset = 14
            # Handle 802.1Q VLAN tag
            if eth_type == 0x8100:
                if len(data) < 18:
                    return None
                eth_type = struct.unpack(">H", data[16:18])[0]
                ip_offset = 18
            if eth_type == 0x0800:
                return self._parse_ipv4(data[ip_offset:], timestamp, index)
            elif eth_type == 0x86DD:
                return self._parse_ipv6(data[ip_offset:], timestamp, index)
            return None

        # Linux Cooked SLL: 16 bytes header
        elif link_type == 113:
            if len(data) < 16:
                return None
            proto = struct.unpack(">H", data[14:16])[0]
            if proto == 0x0800:
                return self._parse_ipv4(data[16:], timestamp, index)
            elif proto == 0x86DD:
                return self._parse_ipv6(data[16:], timestamp, index)
            return None

        # Raw IP (LINKTYPE_RAW / IPv4 / IPv6)
        elif link_type in (12, 101):
            if len(data) < 1:
                return None
            ver = (data[0] >> 4) & 0x0F
            if ver == 4:
                return self._parse_ipv4(data, timestamp, index)
            elif ver == 6:
                return self._parse_ipv6(data, timestamp, index)

        # Fallback heuristic: check if start of frame looks like IPv4
        if len(data) >= 20 and (data[0] >> 4) == 4:
            return self._parse_ipv4(data, timestamp, index)

        return None

    def _parse_ipv4(self, ip_data: bytes, timestamp: float, index: int) -> Optional[PacketRecord]:
        if len(ip_data) < 20:
            return None
        ver_ihl = ip_data[0]
        ihl = (ver_ihl & 0x0F) * 4
        if len(ip_data) < ihl:
            return None

        proto = ip_data[9]
        if proto != 6:  # TCP only
            return None

        src_ip = socket.inet_ntoa(ip_data[12:16])
        dst_ip = socket.inet_ntoa(ip_data[16:20])

        tcp_data = ip_data[ihl:]
        return self._parse_tcp(tcp_data, src_ip, dst_ip, timestamp, index, ip_version=4)

    def _parse_ipv6(self, ip_data: bytes, timestamp: float, index: int) -> Optional[PacketRecord]:
        if len(ip_data) < 40:
            return None
        next_hdr = ip_data[6]
        src_ip = socket.inet_ntop(socket.AF_INET6, ip_data[8:24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, ip_data[24:40])

        offset = 40
        # Parse extension headers until TCP
        while next_hdr in (0, 43, 60):  # Hop-by-hop, Routing, Destination options
            if len(ip_data) < offset + 2:
                return None
            next_hdr = ip_data[offset]
            hdr_ext_len = (ip_data[offset + 1] + 1) * 8
            offset += hdr_ext_len

        if next_hdr != 6:  # Not TCP
            return None

        tcp_data = ip_data[offset:]
        return self._parse_tcp(tcp_data, src_ip, dst_ip, timestamp, index, ip_version=6)

    def _parse_tcp(self, tcp_data: bytes, src_ip: str, dst_ip: str, timestamp: float, index: int, ip_version: int) -> Optional[PacketRecord]:
        if len(tcp_data) < 20:
            return None

        src_port, dst_port, seq, ack, offset_reserved, flags_byte = struct.unpack(">HHIIBB", tcp_data[0:14])
        data_offset = ((offset_reserved >> 4) & 0x0F) * 4
        if len(tcp_data) < data_offset:
            return None

        flags = {
            "fin": bool(flags_byte & 0x01),
            "syn": bool(flags_byte & 0x02),
            "rst": bool(flags_byte & 0x04),
            "psh": bool(flags_byte & 0x08),
            "ack": bool(flags_byte & 0x10),
            "urg": bool(flags_byte & 0x20),
        }

        payload = tcp_data[data_offset:]
        return PacketRecord(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            seq=seq,
            ack=ack,
            flags=flags,
            payload=payload,
            ip_proto="TCP",
            ip_version=ip_version,
            packet_index=index,
        )


def read_pcap(filepath: str, prefer_scapy: bool = True) -> Generator[PacketRecord, None, None]:
    """
    Unified generator yielding PacketRecord from PCAP/PCAPNG file.
    Attempts Scapy first if preferred and installed; seamlessly falls back
    to high-speed pure Python binary parser.
    """
    if prefer_scapy and HAS_SCAPY:
        try:
            with ScapyPcapReader(filepath) as reader:
                packet_index = 0
                for pkt in reader:
                    packet_index += 1
                    if not pkt.haslayer(TCP):
                        continue

                    # IP layer
                    if pkt.haslayer(IP):
                        ip_layer = pkt[IP]
                        src_ip = ip_layer.src
                        dst_ip = ip_layer.dst
                        ip_version = 4
                    elif pkt.haslayer(IPv6):
                        ip_layer = pkt[IPv6]
                        src_ip = ip_layer.src
                        dst_ip = ip_layer.dst
                        ip_version = 6
                    else:
                        continue

                    tcp = pkt[TCP]
                    flags_int = int(tcp.flags)
                    flags = {
                        "fin": bool(flags_int & 0x01),
                        "syn": bool(flags_int & 0x02),
                        "rst": bool(flags_int & 0x04),
                        "psh": bool(flags_int & 0x08),
                        "ack": bool(flags_int & 0x10),
                        "urg": bool(flags_int & 0x20),
                    }
                    payload = bytes(tcp.payload)
                    ts = float(pkt.time)

                    yield PacketRecord(
                        timestamp=ts,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=tcp.sport,
                        dst_port=tcp.dport,
                        seq=tcp.seq,
                        ack=tcp.ack,
                        flags=flags,
                        payload=payload,
                        ip_proto="TCP",
                        ip_version=ip_version,
                        packet_index=packet_index,
                    )
            return
        except Exception:
            # Fall back to pure python if scapy failed on this file
            pass

    # Pure Python binary reader
    reader = PurePythonPcapReader(filepath)
    yield from reader.read_packets()
