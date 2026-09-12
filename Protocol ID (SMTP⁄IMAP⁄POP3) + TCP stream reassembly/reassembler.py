"""
backend.parser.reassembler
~~~~~~~~~~~~~~~~~~~~~~~~~~
Advanced TCP stream reassembly engine.
- 5-tuple flow identification & canonical bidirectional stream keys.
- Client vs Server endpoint resolution (via SYN flags, well-known ports, or banner analysis).
- In-order byte stream reconstruction with sequence gap handling, duplicate suppression,
  and overlapping segment slicing.
- Interleaved chronological conversational event tracking.
"""

from typing import Dict, List, Tuple, Optional
from collections import defaultdict
from .models import PacketRecord, TcpStream, StreamEvent


STANDARD_EMAIL_SERVER_PORTS = {25, 465, 587, 2525, 110, 995, 143, 993}


class DirectionalReassembler:
    """
    Reassembles one half-duplex direction of a TCP connection.
    Handles out-of-order packets, duplicates, and overlapping segments.
    """

    def __init__(self, initial_seq: Optional[int] = None):
        self.initial_seq = initial_seq
        self.next_expected_seq = initial_seq
        # Buffer of pending segments: list of (seq, payload, timestamp)
        self.pending_segments: List[Tuple[int, bytes, float]] = []
        self.assembled_bytes = bytearray()
        self.retransmission_count = 0
        self.seen_seq_ranges: List[Tuple[int, int]] = []  # (start_seq, end_seq)

    def add_segment(self, seq: int, payload: bytes, timestamp: float) -> List[Tuple[bytes, int, float]]:
        """
        Ingests a TCP segment and returns newly assembled consecutive chunks:
        List of (chunk_payload, seq, timestamp).
        """
        if not payload:
            return []

        payload_len = len(payload)
        end_seq = (seq + payload_len) & 0xFFFFFFFF

        # Check for exact or full duplicate
        for s_start, s_end in self.seen_seq_ranges:
            if seq >= s_start and end_seq <= s_end:
                self.retransmission_count += 1
                return []

        self.seen_seq_ranges.append((seq, end_seq))

        # If we don't have initial sequence number, initialize it
        if self.next_expected_seq is None:
            self.initial_seq = seq
            self.next_expected_seq = seq

        # Insert into pending segments sorted by sequence number
        self.pending_segments.append((seq, payload, timestamp))
        self.pending_segments.sort(key=lambda x: x[0])

        new_chunks = []

        # Process pending segments that align or can advance stream
        advanced = True
        while advanced and self.pending_segments:
            advanced = False
            remaining = []
            for seg_seq, seg_payload, seg_ts in self.pending_segments:
                seg_len = len(seg_payload)
                seg_end = (seg_seq + seg_len) & 0xFFFFFFFF

                # Segment is completely behind what we already assembled
                if seg_end <= self.next_expected_seq:
                    continue

                # Segment is contiguous or overlaps current expected seq
                if seg_seq <= self.next_expected_seq <= seg_end:
                    offset = (self.next_expected_seq - seg_seq)
                    fresh_payload = seg_payload[offset:]
                    if fresh_payload:
                        self.assembled_bytes.extend(fresh_payload)
                        new_chunks.append((fresh_payload, self.next_expected_seq, seg_ts))
                        self.next_expected_seq = (self.next_expected_seq + len(fresh_payload)) & 0xFFFFFFFF
                        advanced = True
                else:
                    # Segment is ahead in sequence (out-of-order gap)
                    remaining.append((seg_seq, seg_payload, seg_ts))

            self.pending_segments = remaining

        # Gap fallback: if buffer grows with a persistent sequence gap (e.g. packet loss in capture),
        # force advancement to the lowest available buffered segment to avoid losing downstream data.
        if len(self.pending_segments) > 20:
            self.pending_segments.sort(key=lambda x: x[0])
            next_seg = self.pending_segments.pop(0)
            self.assembled_bytes.extend(next_seg[1])
            new_chunks.append((next_seg[1], next_seg[0], next_seg[2]))
            self.next_expected_seq = (next_seg[0] + len(next_seg[1])) & 0xFFFFFFFF

        return new_chunks

    def flush_remaining(self) -> List[Tuple[bytes, int, float]]:
        """Appends any remaining buffered out-of-order chunks."""
        flushed = []
        for seg_seq, seg_payload, seg_ts in sorted(self.pending_segments, key=lambda x: x[0]):
            self.assembled_bytes.extend(seg_payload)
            flushed.append((seg_payload, seg_seq, seg_ts))
        self.pending_segments.clear()
        return flushed


class StreamSessionTracker:
    """Tracks state and bidirectional assembly for a single 5-tuple TCP session."""

    def __init__(self, stream_id: str, ep1: Tuple[str, int], ep2: Tuple[str, int]):
        self.stream_id = stream_id
        self.ep1 = ep1  # (ip, port)
        self.ep2 = ep2  # (ip, port)

        self.client_ep: Optional[Tuple[str, int]] = None
        self.server_ep: Optional[Tuple[str, int]] = None

        self.client_reassembler = DirectionalReassembler()
        self.server_reassembler = DirectionalReassembler()

        self.events: List[StreamEvent] = []
        self.start_time: float = float("inf")
        self.end_time: float = 0.0
        self.packet_count = 0
        self.client_packet_count = 0
        self.server_packet_count = 0
        self.is_syn_seen = False
        self.is_fin_seen = False
        self.is_rst_seen = False

    def determine_endpoints(self, pkt: PacketRecord):
        """Resolves which endpoint is client and which is server."""
        if self.client_ep is not None:
            return

        # 1. Check SYN flag
        if pkt.flags.get("syn") and not pkt.flags.get("ack"):
            self.client_ep = (pkt.src_ip, pkt.src_port)
            self.server_ep = (pkt.dst_ip, pkt.dst_port)
            return

        # 2. Check standard server ports
        if pkt.dst_port in STANDARD_EMAIL_SERVER_PORTS:
            self.client_ep = (pkt.src_ip, pkt.src_port)
            self.server_ep = (pkt.dst_ip, pkt.dst_port)
            return
        elif pkt.src_port in STANDARD_EMAIL_SERVER_PORTS:
            self.server_ep = (pkt.src_ip, pkt.src_port)
            self.client_ep = (pkt.dst_ip, pkt.dst_port)
            return

        # 3. Default fallback: first packet sender is assumed to be client
        self.client_ep = (pkt.src_ip, pkt.src_port)
        self.server_ep = (pkt.dst_ip, pkt.dst_port)

    def process_packet(self, pkt: PacketRecord):
        self.packet_count += 1
        self.start_time = min(self.start_time, pkt.timestamp)
        self.end_time = max(self.end_time, pkt.timestamp)

        if pkt.flags.get("syn"):
            self.is_syn_seen = True
        if pkt.flags.get("fin"):
            self.is_fin_seen = True
        if pkt.flags.get("rst"):
            self.is_rst_seen = True

        self.determine_endpoints(pkt)

        # Check direction
        if (pkt.src_ip, pkt.src_port) == self.client_ep:
            self.client_packet_count += 1
            chunks = self.client_reassembler.add_segment(pkt.seq, pkt.payload, pkt.timestamp)
            for chunk_payload, seq, ts in chunks:
                self.events.append(StreamEvent(
                    timestamp=ts,
                    direction="client_to_server",
                    payload=chunk_payload,
                    seq=seq,
                ))
        else:
            self.server_packet_count += 1
            chunks = self.server_reassembler.add_segment(pkt.seq, pkt.payload, pkt.timestamp)
            for chunk_payload, seq, ts in chunks:
                self.events.append(StreamEvent(
                    timestamp=ts,
                    direction="server_to_client",
                    payload=chunk_payload,
                    seq=seq,
                ))

    def finalize(self) -> TcpStream:
        """Flushes remaining buffers and returns a finalized TcpStream."""
        rem_client = self.client_reassembler.flush_remaining()
        for chunk, seq, ts in rem_client:
            self.events.append(StreamEvent(
                timestamp=ts,
                direction="client_to_server",
                payload=chunk,
                seq=seq,
            ))

        rem_server = self.server_reassembler.flush_remaining()
        for chunk, seq, ts in rem_server:
            self.events.append(StreamEvent(
                timestamp=ts,
                direction="server_to_client",
                payload=chunk,
                seq=seq,
            ))

        # Sort all stream events by timestamp
        self.events.sort(key=lambda ev: ev.timestamp)

        c_ip, c_port = self.client_ep or self.ep1
        s_ip, s_port = self.server_ep or self.ep2

        retrans = (self.client_reassembler.retransmission_count +
                   self.server_reassembler.retransmission_count)

        return TcpStream(
            stream_id=self.stream_id,
            client_ip=c_ip,
            client_port=c_port,
            server_ip=s_ip,
            server_port=s_port,
            start_time=self.start_time if self.start_time != float("inf") else 0.0,
            end_time=self.end_time,
            client_payload=bytes(self.client_reassembler.assembled_bytes),
            server_payload=bytes(self.server_reassembler.assembled_bytes),
            events=self.events,
            packet_count=self.packet_count,
            client_packet_count=self.client_packet_count,
            server_packet_count=self.server_packet_count,
            retransmission_count=retrans,
            is_syn_seen=self.is_syn_seen,
            is_fin_seen=self.is_fin_seen,
            is_rst_seen=self.is_rst_seen,
        )


class TcpReassemblyEngine:
    """
    Coordinates multi-flow TCP reassembly across an entire capture.
    Maps packets to canonical streams, updates state, and yields finalized TcpStreams.
    """

    def __init__(self):
        self.streams: Dict[str, StreamSessionTracker] = {}

    def _canonical_stream_key(self, pkt: PacketRecord) -> Tuple[str, Tuple[str, int], Tuple[str, int]]:
        ep_a = (pkt.src_ip, pkt.src_port)
        ep_b = (pkt.dst_ip, pkt.dst_port)
        if ep_a <= ep_b:
            key = f"{ep_a[0]}:{ep_a[1]}-{ep_b[0]}:{ep_b[1]}"
            return key, ep_a, ep_b
        else:
            key = f"{ep_b[0]}:{ep_b[1]}-{ep_a[0]}:{ep_a[1]}"
            return key, ep_b, ep_a

    def process_packet(self, pkt: PacketRecord):
        key, ep1, ep2 = self._canonical_stream_key(pkt)
        if key not in self.streams:
            self.streams[key] = StreamSessionTracker(stream_id=key, ep1=ep1, ep2=ep2)
        self.streams[key].process_packet(pkt)

    def reassemble_all(self) -> List[TcpStream]:
        """Returns all completed, reassembled TCP streams."""
        results = []
        for tracker in self.streams.values():
            results.append(tracker.finalize())
        return results
