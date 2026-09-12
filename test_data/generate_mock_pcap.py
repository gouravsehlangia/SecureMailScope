#!/usr/bin/env python3
"""
SecureMailScope — Mock PCAP Generator
Builds a realistic synthetic .pcap file with 5 email-security test scenarios
for end-to-end testing of Stage 2 (TLS/Crypto analysis module).

Scenarios:
  1. IMAP/143  STARTTLS → TLS 1.2 ECDHE (PFS ✅)
  2. SMTP/587  STARTTLS → TLS 1.3       (encrypted cert, PFS ✅)
  3. POP3S/995 Implicit TLS → TLS 1.0 static RSA (NO PFS ❌)
  4. SMTP/25   STARTTLS offered but client never upgrades (downgrade ❌)
  5. IMAP/993  Truncated mid-ServerHello (malformed/error-handling test)

Outputs:
  test_data/mock_email_traffic.pcap
  test_data/mock_session.keylog  (NSS SSLKEYLOGFILE for scenario 2)
"""

import os
import struct
import sys

try:
    from scapy.all import (
        Ether, IP, TCP, Raw,
        wrpcap, Packet, NoPayload
    )
except ImportError:
    print("ERROR: scapy is not installed. Run: pip install scapy")
    sys.exit(1)

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))
PCAP_PATH  = os.path.join(OUTPUT_DIR, "mock_email_traffic.pcap")
KEYLOG_PATH = os.path.join(OUTPUT_DIR, "mock_session.keylog")

# ─────────────────────────────────────────────────────────────────────────────
# Binary TLS builder helpers (pure struct — no external crypto lib needed)
# ─────────────────────────────────────────────────────────────────────────────

def tls_record(content_type: int, version: int, payload: bytes) -> bytes:
    """Wraps payload in a 5-byte TLS record header."""
    return struct.pack("!BHH", content_type, version, len(payload)) + payload

def hs_msg(msg_type: int, body: bytes) -> bytes:
    """Wraps body in a 4-byte handshake header (type + 3-byte length)."""
    length_bytes = struct.pack("!I", len(body))[1:]   # 3-byte big-endian
    return bytes([msg_type]) + length_bytes + body

def make_random(seed: int = 0x42) -> bytes:
    """Returns 32 deterministic 'random' bytes (not crypto-secure; for pcap only)."""
    return bytes((seed + i) % 256 for i in range(32))

def make_extension(ext_type: int, data: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(data)) + data

def make_extensions_block(exts: list[bytes]) -> bytes:
    body = b"".join(exts)
    return struct.pack("!H", len(body)) + body

def make_sni_ext(hostname: str) -> bytes:
    name = hostname.encode()
    server_name = bytes([0x00]) + struct.pack("!H", len(name)) + name
    server_name_list = struct.pack("!H", len(server_name)) + server_name
    return make_extension(0x0000, server_name_list)

def make_supported_versions_client(*versions: int) -> bytes:
    """supported_versions extension for ClientHello (list of 2-byte codes)."""
    body = b"".join(struct.pack("!H", v) for v in versions)
    return make_extension(0x002B, bytes([len(body)]) + body)

def make_supported_versions_server(version: int) -> bytes:
    """supported_versions extension for ServerHello (single selected version)."""
    return make_extension(0x002B, struct.pack("!H", version))

def make_supported_groups_ext(*groups: int) -> bytes:
    body = b"".join(struct.pack("!H", g) for g in groups)
    return make_extension(0x000A, struct.pack("!H", len(body)) + body)

def make_key_share_client(group_id: int) -> bytes:
    """key_share extension for ClientHello with a fake 32-byte public key."""
    key_data = struct.pack("!H", group_id) + struct.pack("!H", 32) + b"\xab" * 32
    return make_extension(0x0033, struct.pack("!H", len(key_data)) + key_data)

def make_key_share_server(group_id: int) -> bytes:
    """key_share extension for ServerHello."""
    key_data = struct.pack("!H", group_id) + struct.pack("!H", 32) + b"\xcd" * 32
    return make_extension(0x0033, key_data)

def make_client_hello(
    client_version: int,
    random_seed: int,
    cipher_codes: list[int],
    extensions: bytes = b"",
    session_id: bytes = b""
) -> bytes:
    random = make_random(random_seed)
    sid_field = bytes([len(session_id)]) + session_id
    ciphers = b"".join(struct.pack("!H", c) for c in cipher_codes)
    cipher_field = struct.pack("!H", len(ciphers)) + ciphers
    compression = bytes([1, 0])  # 1 method: null
    body = struct.pack("!H", client_version) + random + sid_field + cipher_field + compression
    if extensions:
        body += extensions
    return hs_msg(0x01, body)

def make_server_hello(
    server_version: int,
    random_seed: int,
    cipher_code: int,
    extensions: bytes = b"",
    session_id: bytes = b""
) -> bytes:
    random = make_random(random_seed)
    sid_field = bytes([len(session_id)]) + session_id
    body = struct.pack("!H", server_version) + random + sid_field + struct.pack("!H", cipher_code) + bytes([0])
    if extensions:
        body += extensions
    return hs_msg(0x02, body)

def make_certificate_12(der_bytes: bytes) -> bytes:
    """TLS 1.2 Certificate handshake message."""
    cert_entry = struct.pack("!I", len(der_bytes))[1:] + der_bytes  # 3-byte length
    certs_list = struct.pack("!I", len(cert_entry))[1:] + cert_entry
    return hs_msg(0x0B, certs_list)

def make_server_key_exchange_ecdhe(curve_id: int = 0x0017) -> bytes:
    """ServerKeyExchange for named_curve ECDHE (TLS 1.2)."""
    # curve_type=named_curve(3) + 2-byte curve id + 1-byte pubkey len + pubkey
    pubkey = b"\x04" + b"\xbe" * 64   # uncompressed EC point (fake)
    body = bytes([0x03]) + struct.pack("!H", curve_id) + bytes([len(pubkey)]) + pubkey
    return hs_msg(0x0C, body)

def make_server_hello_done() -> bytes:
    return hs_msg(0x0E, b"")

def make_finished() -> bytes:
    return hs_msg(0x14, b"\xde\xad\xbe\xef" * 3)

FAKE_DER_CERT = (
    b"\x30\x82\x02\x40"   # SEQUENCE, length=576
    + b"\x30\x82\x01\x28"  # tbsCertificate SEQUENCE, length=296
    + b"\xa0\x03\x02\x01\x02"  # version: v3
    + b"\x02\x01\x01"          # serialNumber: 1
    + b"\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00"  # sha256WithRSAEncryption
    + b"\x30\x11\x31\x0f\x30\x0d\x06\x03\x55\x04\x03\x13\x06\x54\x65\x73\x74\x43\x41"  # CN=TestCA
    + b"\xaa" * 250  # Dummy remainder of cert fields
    + b"\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00"  # signature algorithm
    + b"\x03\x42\x00" + b"\xff" * 65  # signature value
)


# ─────────────────────────────────────────────────────────────────────────────
# TCP Stream Builder  (SYN → SYN/ACK → ACK → data → FIN)
# ─────────────────────────────────────────────────────────────────────────────

def tcp_stream(
    src_ip: str, dst_ip: str,
    sport: int, dport: int,
    client_payloads: list[bytes],
    server_payloads: list[bytes],
    sport_base_seq: int = 1000,
    dport_base_seq: int = 2000
) -> list[Packet]:
    """
    Produces a realistic TCP exchange:
      SYN / SYN-ACK / ACK / [interleaved data] / FIN-ACK / FIN-ACK
    client_payloads and server_payloads are interleaved in order.
    """
    pkts = []

    c_seq = sport_base_seq
    s_seq = dport_base_seq

    def pkt(src, dst, sp, dp, flags, seq, ack, payload=b""):
        p = (
            Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") /
            IP(src=src, dst=dst, ttl=64) /
            TCP(sport=sp, dport=dp, flags=flags, seq=seq, ack=ack) /
            (Raw(load=payload) if payload else NoPayload())
        )
        return p

    # 3-way handshake
    pkts.append(pkt(src_ip, dst_ip, sport, dport, "S",  c_seq,     0))
    c_seq += 1
    pkts.append(pkt(dst_ip, src_ip, dport, sport, "SA", s_seq,     c_seq))
    s_seq += 1
    pkts.append(pkt(src_ip, dst_ip, sport, dport, "A",  c_seq,     s_seq))

    # Interleave server banner first (email protocols always send banner first)
    all_exchanges = []
    max_len = max(len(client_payloads), len(server_payloads))
    for i in range(max_len):
        if i < len(server_payloads):
            all_exchanges.append(("server", server_payloads[i]))
        if i < len(client_payloads):
            all_exchanges.append(("client", client_payloads[i]))

    for side, data in all_exchanges:
        if not data:
            continue
        if side == "client":
            pkts.append(pkt(src_ip, dst_ip, sport, dport, "PA", c_seq, s_seq, data))
            c_seq += len(data)
            pkts.append(pkt(dst_ip, src_ip, dport, sport, "A",  s_seq, c_seq))
        else:
            pkts.append(pkt(dst_ip, src_ip, dport, sport, "PA", s_seq, c_seq, data))
            s_seq += len(data)
            pkts.append(pkt(src_ip, dst_ip, sport, dport, "A",  c_seq, s_seq))

    # FIN-ACK both sides
    pkts.append(pkt(src_ip, dst_ip, sport, dport, "FA", c_seq, s_seq))
    c_seq += 1
    pkts.append(pkt(dst_ip, src_ip, dport, sport, "A",  s_seq, c_seq))
    pkts.append(pkt(dst_ip, src_ip, dport, sport, "FA", s_seq, c_seq))
    s_seq += 1
    pkts.append(pkt(src_ip, dst_ip, sport, dport, "A",  c_seq, s_seq))

    return pkts


# ─────────────────────────────────────────────────────────────────────────────
# SCENARIO BUILDERS
# ─────────────────────────────────────────────────────────────────────────────

def scenario_1_imap_starttls_tls12() -> list[Packet]:
    """
    Scenario 1: IMAP/143 STARTTLS upgrade → TLS 1.2, ECDHE-RSA-AES128-GCM-SHA256 (PFS)
    Cipher: 0xC02F = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    """
    # IMAP banner + CAPABILITY + STARTTLS exchange (plaintext)
    banner  = b"* OK [CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN] mail.example.com ready\r\n"
    cap_req = b"A001 CAPABILITY\r\n"
    cap_rsp = b"* CAPABILITY IMAP4rev1 STARTTLS\r\nA001 OK CAPABILITY completed\r\n"
    stls_c  = b"A002 STARTTLS\r\n"
    stls_s  = b"A002 OK Begin TLS negotiation now\r\n"

    # TLS 1.2 ClientHello (cipher: ECDHE-RSA-AES128-GCM-SHA256 0xC02F + fallbacks)
    ch_exts = make_extensions_block([
        make_sni_ext("mail.example.com"),
        make_supported_groups_ext(0x0017, 0x0018),   # P-256, P-384
        make_supported_versions_client(0x0303),        # TLS 1.2
    ])
    ch = make_client_hello(
        client_version=0x0303,
        random_seed=0xAA,
        cipher_codes=[0xC02F, 0xC030, 0x002F],
        extensions=ch_exts
    )

    # TLS 1.2 ServerHello → cipher 0xC02F, NO supported_versions ext (plain TLS 1.2)
    sh_exts = make_extensions_block([
        make_supported_groups_ext(0x0017),
    ])
    sh = make_server_hello(
        server_version=0x0303,
        random_seed=0xBB,
        cipher_code=0xC02F,
        extensions=sh_exts
    )
    cert   = make_certificate_12(FAKE_DER_CERT)
    ske    = make_server_key_exchange_ecdhe(curve_id=0x0017)  # P-256
    shd    = make_server_hello_done()

    # Pack into TLS records (server sends SH + Cert + SKE + SHD coalesced)
    tls_ch = tls_record(0x16, 0x0303, ch)
    tls_server_hs = tls_record(0x16, 0x0303, sh + cert + ske + shd)

    # Client Finished (Change Cipher Spec + Finished placeholder)
    ccs    = tls_record(0x14, 0x0303, bytes([1]))
    fin_c  = tls_record(0x16, 0x0303, make_finished())

    # Server CCS + Finished
    ccs_s  = tls_record(0x14, 0x0303, bytes([1]))
    fin_s  = tls_record(0x16, 0x0303, make_finished())

    # Application Data (encrypted email payload — opaque bytes)
    app    = tls_record(0x17, 0x0303, b"\xee" * 48)

    # Assemble: plaintext STARTTLS then TLS wire bytes  
    server_data = [banner, cap_rsp, stls_s, tls_server_hs, ccs_s + fin_s, app]
    client_data = [cap_req, stls_c, tls_ch, ccs + fin_c]

    return tcp_stream(
        "192.168.1.10", "10.0.0.1",
        sport=49152, dport=143,
        client_payloads=client_data,
        server_payloads=server_data,
        sport_base_seq=11000, dport_base_seq=21000
    )


def scenario_2_smtp_starttls_tls13() -> tuple[list[Packet], str]:
    """
    Scenario 2: SMTP/587 STARTTLS → TLS 1.3, TLS_AES_256_GCM_SHA384 (0x1302)
    Also generates SSLKEYLOGFILE content for this session.
    """
    # SMTP plaintext preamble
    ehlo_banner = b"220 smtp.example.com ESMTP Postfix\r\n"
    ehlo_c      = b"EHLO client.example.com\r\n"
    ehlo_rsp    = b"250-smtp.example.com\r\n250-STARTTLS\r\n250 PIPELINING\r\n"
    stls_c      = b"STARTTLS\r\n"
    stls_rsp    = b"220 2.0.0 Ready to start TLS\r\n"

    # TLS 1.3 ClientHello — client_version=0x0303 (legacy), supported_versions ext=TLS 1.3
    # client_random seed=0xCC — we'll use this in the keylog
    client_random = make_random(0xCC)
    ch_exts = make_extensions_block([
        make_sni_ext("smtp.example.com"),
        make_supported_versions_client(0x0304, 0x0303),    # TLS 1.3 preferred
        make_supported_groups_ext(0x001D, 0x0017),          # x25519, P-256
        make_key_share_client(0x001D),                      # x25519 key share
    ])
    # Build ClientHello body manually to use exact client_random
    sid_field = bytes([0])  # no session id
    ciphers_bytes = struct.pack("!H", 0x1302) + struct.pack("!H", 0x1301)  # AES-256-GCM-SHA384, AES-128-GCM-SHA256
    cipher_field  = struct.pack("!H", len(ciphers_bytes)) + ciphers_bytes
    compression   = bytes([1, 0])
    ch_body = struct.pack("!H", 0x0303) + client_random + sid_field + cipher_field + compression + ch_exts
    ch = hs_msg(0x01, ch_body)

    # TLS 1.3 ServerHello — version=0x0303 in field, but supported_versions ext=TLS 1.3 (0x0304)
    sh_exts = make_extensions_block([
        make_supported_versions_server(0x0304),   # selected TLS 1.3
        make_key_share_server(0x001D),             # x25519
    ])
    sh = make_server_hello(
        server_version=0x0303,
        random_seed=0xDD,
        cipher_code=0x1302,    # TLS_AES_256_GCM_SHA384
        extensions=sh_exts
    )

    # TLS 1.3: after ServerHello, handshake is encrypted → Application Data records
    # We simulate encrypted Certificate + Finished as opaque 0x17 records
    encrypted_hs_s = tls_record(0x17, 0x0303, b"\xfc" * 256)    # encrypted Certificate
    encrypted_fin_s = tls_record(0x17, 0x0303, b"\xfd" * 48)    # encrypted Finished
    encrypted_fin_c = tls_record(0x17, 0x0303, b"\xfe" * 48)    # encrypted client Finished

    tls_ch = tls_record(0x16, 0x0303, ch)
    tls_sh = tls_record(0x16, 0x0303, sh)

    # Application data (encrypted email)
    app    = tls_record(0x17, 0x0303, b"\x00" * 64)

    server_data = [ehlo_banner, ehlo_rsp, stls_rsp, tls_sh, encrypted_hs_s + encrypted_fin_s, app]
    client_data = [ehlo_c, stls_c, tls_ch, encrypted_fin_c]

    pkts = tcp_stream(
        "192.168.1.20", "10.0.0.2",
        sport=49153, dport=587,
        client_payloads=client_data,
        server_payloads=server_data,
        sport_base_seq=12000, dport_base_seq=22000
    )

    # SSLKEYLOGFILE for this session
    # Format: CLIENT_RANDOM <hex_client_random> <hex_secret>
    # CLIENT_HANDSHAKE_TRAFFIC_SECRET is needed for TLS 1.3 decryption
    client_random_hex = client_random.hex()
    # Fake but correctly formatted 48-byte secret (SHA-384 output size for TLS_AES_256_GCM_SHA384)
    fake_secret = ("ab" * 24)
    keylog = (
        f"# NSS Key Log — SecureMailScope mock session (Scenario 2: SMTP/587 TLS 1.3)\n"
        f"CLIENT_HANDSHAKE_TRAFFIC_SECRET {client_random_hex} {fake_secret}\n"
        f"SERVER_HANDSHAKE_TRAFFIC_SECRET {client_random_hex} {'cd' * 24}\n"
        f"CLIENT_TRAFFIC_SECRET_0 {client_random_hex} {'ef' * 24}\n"
        f"SERVER_TRAFFIC_SECRET_0 {client_random_hex} {'01' * 24}\n"
    )
    return pkts, keylog


def scenario_3_pop3s_tls10_weak() -> list[Packet]:
    """
    Scenario 3: POP3S/995 implicit TLS → TLS 1.0, TLS_RSA_WITH_RC4_128_MD5 (0x0004)
    No PFS. Weak cipher. Tests deprecated-version + weak-cipher detection.
    """
    # POP3 banner (after TLS is already established in implicit mode)
    # So no plaintext preamble — pure TLS from byte 1

    # TLS 1.0 ClientHello
    ch = make_client_hello(
        client_version=0x0301,   # TLS 1.0
        random_seed=0x10,
        cipher_codes=[0x0004, 0x0005],   # RC4-128-MD5, RC4-128-SHA
        extensions=b""
    )
    sh = make_server_hello(
        server_version=0x0301,   # TLS 1.0
        random_seed=0x11,
        cipher_code=0x0004,      # TLS_RSA_WITH_RC4_128_MD5
        extensions=b""
    )
    cert = make_certificate_12(FAKE_DER_CERT)
    shd  = make_server_hello_done()

    tls_ch = tls_record(0x16, 0x0301, ch)
    tls_server_hs = tls_record(0x16, 0x0301, sh + cert + shd)

    ccs_s  = tls_record(0x14, 0x0301, bytes([1]))
    fin_s  = tls_record(0x16, 0x0301, make_finished())
    ccs_c  = tls_record(0x14, 0x0301, bytes([1]))
    fin_c  = tls_record(0x16, 0x0301, make_finished())

    # POP3 response within TLS (encrypted, but we show opaque App Data)
    app_s  = tls_record(0x17, 0x0301, b"+OK Dovecot ready.\r\n".ljust(48, b"\x00"))

    server_data = [tls_server_hs, ccs_s + fin_s, app_s]
    client_data = [tls_ch, ccs_c + fin_c]

    return tcp_stream(
        "192.168.1.30", "10.0.0.3",
        sport=49154, dport=995,
        client_payloads=client_data,
        server_payloads=server_data,
        sport_base_seq=13000, dport_base_seq=23000
    )


def scenario_4_smtp_starttls_not_upgraded() -> list[Packet]:
    """
    Scenario 4: SMTP/25 — server offers STARTTLS but client proceeds in cleartext.
    Simulates a downgrade / STARTTLS stripping attack.
    """
    banner  = b"220 smtp.victim.org ESMTP\r\n"
    ehlo_c  = b"EHLO attacker.mitm.net\r\n"
    ehlo_rsp= b"250-smtp.victim.org\r\n250-STARTTLS\r\n250 PIPELINING\r\n"

    # Client skips STARTTLS and goes straight to AUTH
    auth_c  = b"AUTH LOGIN\r\n"
    auth_s  = b"334 VXNlcm5hbWU6\r\n"
    user_c  = b"dXNlckBleGFtcGxlLmNvbQ==\r\n"   # base64(user@example.com)
    pass_s  = b"334 UGFzc3dvcmQ6\r\n"
    pass_c  = b"cGFzc3dvcmQ=\r\n"                # base64(password)
    ok_s    = b"235 2.7.0 Authentication successful\r\n"
    mail_c  = b"MAIL FROM:<attacker@mitm.net>\r\n"

    server_data = [banner, ehlo_rsp, auth_s, pass_s, ok_s]
    client_data = [ehlo_c, auth_c, user_c, pass_c, mail_c]

    return tcp_stream(
        "192.168.1.40", "10.0.0.4",
        sport=49155, dport=25,
        client_payloads=client_data,
        server_payloads=server_data,
        sport_base_seq=14000, dport_base_seq=24000
    )


def scenario_5_truncated_server_hello() -> list[Packet]:
    """
    Scenario 5: IMAP/993 implicit TLS — ServerHello is cut off mid-message (malformed).
    Tests that Stage 2 handles truncated handshakes without crashing.
    """
    ch = make_client_hello(
        client_version=0x0303,
        random_seed=0x50,
        cipher_codes=[0xC02F, 0xC030],
        extensions=b""
    )
    tls_ch = tls_record(0x16, 0x0303, ch)

    # ServerHello cut off after 20 bytes (mid-random field)
    sh_full = make_server_hello(
        server_version=0x0303, random_seed=0x51, cipher_code=0xC02F, extensions=b""
    )
    sh_truncated = sh_full[:20]   # deliberate truncation
    tls_sh_truncated = tls_record(0x16, 0x0303, sh_truncated)

    server_data = [tls_sh_truncated]
    client_data = [tls_ch]

    return tcp_stream(
        "192.168.1.50", "10.0.0.5",
        sport=49156, dport=993,
        client_payloads=client_data,
        server_payloads=server_data,
        sport_base_seq=15000, dport_base_seq=25000
    )


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    all_pkts = []

    print("[1/5] Building Scenario 1: IMAP STARTTLS → TLS 1.2 ECDHE...")
    all_pkts.extend(scenario_1_imap_starttls_tls12())

    print("[2/5] Building Scenario 2: SMTP STARTTLS → TLS 1.3 (+ keylog)...")
    pkts2, keylog_content = scenario_2_smtp_starttls_tls13()
    all_pkts.extend(pkts2)
    with open(KEYLOG_PATH, "w") as f:
        f.write(keylog_content)
    print(f"      SSLKEYLOGFILE written → {KEYLOG_PATH}")

    print("[3/5] Building Scenario 3: POP3S implicit TLS 1.0 + RC4/MD5 (weak)...")
    all_pkts.extend(scenario_3_pop3s_tls10_weak())

    print("[4/5] Building Scenario 4: SMTP STARTTLS offered but not used (downgrade)...")
    all_pkts.extend(scenario_4_smtp_starttls_not_upgraded())

    print("[5/5] Building Scenario 5: IMAP/993 truncated ServerHello (malformed)...")
    all_pkts.extend(scenario_5_truncated_server_hello())

    wrpcap(PCAP_PATH, all_pkts)
    print(f"\n✅ pcap written → {PCAP_PATH}  ({len(all_pkts)} packets total)")
    print(f"✅ keylog written → {KEYLOG_PATH}")


if __name__ == "__main__":
    main()
