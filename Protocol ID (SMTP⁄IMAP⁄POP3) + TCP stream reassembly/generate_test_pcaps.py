"""
tests.generate_test_pcaps
~~~~~~~~~~~~~~~~~~~~~~~~~
Generates realistic, synthetic PCAP files for testing and SIH demonstrations.
Scenarios:
1. smtp_starttls_valid.pcap: Proper SMTP with STARTTLS and TLS 1.2 handshake.
2. smtp_stripping_attack.pcap: MITM STARTTLS stripping with exposed cleartext credentials.
3. imap_starttls.pcap: IMAP session on port 143 with STARTTLS upgrade.
4. pop3_stls.pcap: POP3 session on port 110 with STLS upgrade.
"""

import os
import struct
from scapy.all import Ether, IP, TCP, wrpcap


def make_tls_client_hello() -> bytes:
    """Constructs a minimal realistic TLS 1.2 ClientHello byte record."""
    record_header = b"\x16\x03\x01"  # Handshake, TLS 1.0 record layer compatibility
    handshake_type = b"\x01"          # ClientHello
    client_version = b"\x03\x03"      # TLS 1.2
    random_bytes = b"\xaa" * 32
    session_id = b"\x00"              # No session ID
    cipher_suites = (
        b"\x00\x08"                   # Cipher suite length = 8 bytes
        b"\xc0\x2f"                   # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        b"\xc0\x30"                   # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        b"\x00\x9c"                   # TLS_RSA_WITH_AES_128_GCM_SHA256
        b"\x00\x35"                   # TLS_RSA_WITH_AES_256_CBC_SHA
    )
    compression = b"\x01\x00"         # 1 compression method: null
    extensions = (
        b"\x00\x12"                   # Extension length = 18 bytes
        b"\x00\x00\x00\x0e\x00\x0c\x00\x00\x09mail.test\x00"  # SNI extension
    )

    handshake_body = client_version + random_bytes + session_id + cipher_suites + compression + extensions
    handshake_len = struct.pack(">I", len(handshake_body))[1:]  # 3 bytes
    handshake_msg = handshake_type + handshake_len + handshake_body

    record_len = struct.pack(">H", len(handshake_msg))
    return record_header + record_len + handshake_msg


def make_tls_server_hello() -> bytes:
    """Constructs a minimal realistic TLS 1.2 ServerHello byte record."""
    record_header = b"\x16\x03\x03"  # Handshake, TLS 1.2
    handshake_type = b"\x02"          # ServerHello
    server_version = b"\x03\x03"      # TLS 1.2
    random_bytes = b"\xbb" * 32
    session_id = b"\x00"
    selected_cipher = b"\xc0\x2f"     # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    compression = b"\x00"

    handshake_body = server_version + random_bytes + session_id + selected_cipher + compression
    handshake_len = struct.pack(">I", len(handshake_body))[1:]
    handshake_msg = handshake_type + handshake_len + handshake_body

    record_len = struct.pack(">H", len(handshake_msg))
    return record_header + record_len + handshake_msg


def generate_pcap_files(output_dir: str):
    os.makedirs(output_dir, exist_ok=True)

    # -------------------------------------------------------------
    # 1. SMTP with Valid STARTTLS
    # -------------------------------------------------------------
    c_ip, s_ip = "192.168.1.50", "198.51.100.25"
    c_port, s_port = 49152, 25
    c_seq, s_seq = 1000, 5000
    ts = 1700000000.0
    packets = []

    def add_packet(src, dst, sport, dport, seq, ack, flags, payload=b""):
        nonlocal ts
        ts += 0.05
        pkt = (
            Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") /
            IP(src=src, dst=dst) /
            TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags)
        )
        if payload:
            pkt = pkt / payload
        pkt.time = ts
        packets.append(pkt)

    # Handshake
    add_packet(c_ip, s_ip, c_port, s_port, c_seq, 0, "S")
    c_seq += 1
    add_packet(s_ip, c_ip, s_port, c_port, s_seq, c_seq, "SA")
    s_seq += 1
    add_packet(c_ip, s_ip, c_port, s_port, c_seq, s_seq, "A")

    # Server Banner
    srv_banner = b"220 mail.securebank.in ESMTP Postfix (Ubuntu)\r\n"
    add_packet(s_ip, c_ip, s_port, c_port, s_seq, c_seq, "PA", srv_banner)
    s_seq += len(srv_banner)

    # Client EHLO
    c_ehlo = b"EHLO mailclient.local\r\n"
    add_packet(c_ip, s_ip, c_port, s_port, c_seq, s_seq, "PA", c_ehlo)
    c_seq += len(c_ehlo)

    # Server EHLO Response with STARTTLS
    s_ehlo_resp = b"250-mail.securebank.in\r\n250-PIPELINING\r\n250-STARTTLS\r\n250-8BITMIME\r\n250 HELP\r\n"
    add_packet(s_ip, c_ip, s_port, c_port, s_seq, c_seq, "PA", s_ehlo_resp)
    s_seq += len(s_ehlo_resp)

    # Client STARTTLS
    c_stls = b"STARTTLS\r\n"
    add_packet(c_ip, s_ip, c_port, s_port, c_seq, s_seq, "PA", c_stls)
    c_seq += len(c_stls)

    # Server Ready to start TLS
    s_stls_ok = b"220 2.0.0 Ready to start TLS\r\n"
    add_packet(s_ip, c_ip, s_port, c_port, s_seq, c_seq, "PA", s_stls_ok)
    s_seq += len(s_stls_ok)

    # Client TLS ClientHello
    c_chello = make_tls_client_hello()
    add_packet(c_ip, s_ip, c_port, s_port, c_seq, s_seq, "PA", c_chello)
    c_seq += len(c_chello)

    # Server TLS ServerHello
    s_shello = make_tls_server_hello()
    add_packet(s_ip, c_ip, s_port, c_port, s_seq, c_seq, "PA", s_shello)
    s_seq += len(s_shello)

    wrpcap(os.path.join(output_dir, "smtp_starttls_valid.pcap"), packets)

    # -------------------------------------------------------------
    # 2. SMTP STARTTLS Stripping Attack & Cleartext Credentials Leak
    # -------------------------------------------------------------
    packets = []
    c_ip, s_ip = "192.168.1.75", "198.51.100.25"
    c_port, s_port = 49200, 25
    c_seq, s_seq = 2000, 7000

    # Handshake
    add_packet(c_ip, s_ip, c_port, s_port, c_seq, 0, "S")
    c_seq += 1
    add_packet(s_ip, c_ip, s_port, c_port, s_seq, c_seq, "SA")
    s_seq += 1
    add_packet(c_ip, s_ip, c_port, s_port, c_seq, s_seq, "A")

    # Banner
    srv_banner = b"220 mail.targetcorp.com ESMTP Exim 4.94\r\n"
    add_packet(s_ip, c_ip, s_port, c_port, s_seq, c_seq, "PA", srv_banner)
    s_seq += len(srv_banner)

    # Client EHLO
    c_ehlo = b"EHLO laptop.local\r\n"
    add_packet(c_ip, s_ip, c_port, s_port, c_seq, s_seq, "PA", c_ehlo)
    c_seq += len(c_ehlo)

    # Server advertises STARTTLS, but MITM stripped it or client ignores it!
    # Server advertised STARTTLS
    s_ehlo_resp = b"250-mail.targetcorp.com\r\n250-STARTTLS\r\n250-AUTH LOGIN PLAIN\r\n250 HELP\r\n"
    add_packet(s_ip, c_ip, s_port, c_port, s_seq, c_seq, "PA", s_ehlo_resp)
    s_seq += len(s_ehlo_resp)

    # Client performs AUTH LOGIN directly without STARTTLS!
    c_auth = b"AUTH LOGIN\r\n"
    add_packet(c_ip, s_ip, c_port, s_port, c_seq, s_seq, "PA", c_auth)
    c_seq += len(c_auth)

    s_prompt_u = b"334 VXNlcm5hbWU6\r\n"
    add_packet(s_ip, c_ip, s_port, c_port, s_seq, c_seq, "PA", s_prompt_u)
    s_seq += len(s_prompt_u)

    # Send username base64: admin@targetcorp.com
    c_user = b"YWRtaW5AdGFyZ2V0Y29ycC5jb20=\r\n"
    add_packet(c_ip, s_ip, c_port, s_port, c_seq, s_seq, "PA", c_user)
    c_seq += len(c_user)

    s_prompt_p = b"334 UGFzc3dvcmQ6\r\n"
    add_packet(s_ip, c_ip, s_port, c_port, s_seq, c_seq, "PA", s_prompt_p)
    s_seq += len(s_prompt_p)

    # Send password base64: SuperSecretHackathonPassword!
    c_pass = b"U3VwZXJTZWNyZXRIYWNrYXRob25QYXNzd29yZCE=\r\n"
    add_packet(c_ip, s_ip, c_port, s_port, c_seq, s_seq, "PA", c_pass)
    c_seq += len(c_pass)

    s_ok = b"235 2.7.0 Authentication successful\r\n"
    add_packet(s_ip, c_ip, s_port, c_port, s_seq, c_seq, "PA", s_ok)
    s_seq += len(s_ok)

    wrpcap(os.path.join(output_dir, "smtp_stripping_attack.pcap"), packets)

    # -------------------------------------------------------------
    # 3. IMAP Session with STARTTLS
    # -------------------------------------------------------------
    packets = []
    c_ip, s_ip = "192.168.1.80", "198.51.100.30"
    c_port, s_port = 51200, 143
    c_seq, s_seq = 3000, 9000

    add_packet(c_ip, s_ip, c_port, s_port, c_seq, 0, "S")
    c_seq += 1
    add_packet(s_ip, c_ip, s_port, c_port, s_seq, c_seq, "SA")
    s_seq += 1
    add_packet(c_ip, s_ip, c_port, s_port, c_seq, s_seq, "A")

    s_banner = b"* OK [CAPABILITY IMAP4rev1 STARTTLS IDLE] Dovecot ready.\r\n"
    add_packet(s_ip, c_ip, s_port, c_port, s_seq, c_seq, "PA", s_banner)
    s_seq += len(s_banner)

    c_cmd = b"A001 STARTTLS\r\n"
    add_packet(c_ip, s_ip, c_port, s_port, c_seq, s_seq, "PA", c_cmd)
    c_seq += len(c_cmd)

    s_resp = b"A001 OK Begin TLS negotiation now\r\n"
    add_packet(s_ip, c_ip, s_port, c_port, s_seq, c_seq, "PA", s_resp)
    s_seq += len(s_resp)

    c_chello = make_tls_client_hello()
    add_packet(c_ip, s_ip, c_port, s_port, c_seq, s_seq, "PA", c_chello)
    c_seq += len(c_chello)

    wrpcap(os.path.join(output_dir, "imap_starttls.pcap"), packets)

    # -------------------------------------------------------------
    # 4. POP3 Session with STLS
    # -------------------------------------------------------------
    packets = []
    c_ip, s_ip = "192.168.1.95", "198.51.100.40"
    c_port, s_port = 52300, 110
    c_seq, s_seq = 4000, 11000

    add_packet(c_ip, s_ip, c_port, s_port, c_seq, 0, "S")
    c_seq += 1
    add_packet(s_ip, c_ip, s_port, c_port, s_seq, c_seq, "SA")
    s_seq += 1
    add_packet(c_ip, s_ip, c_port, s_port, c_seq, s_seq, "A")

    s_banner = b"+OK POP3 server ready <1896.697170952@mail.example.org>\r\n"
    add_packet(s_ip, c_ip, s_port, c_port, s_seq, c_seq, "PA", s_banner)
    s_seq += len(s_banner)

    c_capa = b"CAPA\r\n"
    add_packet(c_ip, s_ip, c_port, s_port, c_seq, s_seq, "PA", c_capa)
    c_seq += len(c_capa)

    s_capa_resp = b"+OK Capability list follows\r\nSTLS\r\nUSER\r\nIMPLEMENTATION Dovecot\r\n.\r\n"
    add_packet(s_ip, c_ip, s_port, c_port, s_seq, c_seq, "PA", s_capa_resp)
    s_seq += len(s_capa_resp)

    c_stls = b"STLS\r\n"
    add_packet(c_ip, s_ip, c_port, s_port, c_seq, s_seq, "PA", c_stls)
    c_seq += len(c_stls)

    s_stls_ok = b"+OK Begin TLS negotiation\r\n"
    add_packet(s_ip, c_ip, s_port, c_port, s_seq, c_seq, "PA", s_stls_ok)
    s_seq += len(s_stls_ok)

    c_chello = make_tls_client_hello()
    add_packet(c_ip, s_ip, c_port, s_port, c_seq, s_seq, "PA", c_chello)
    c_seq += len(c_chello)

    wrpcap(os.path.join(output_dir, "pop3_stls.pcap"), packets)
    print(f"[+] Successfully generated 4 test PCAP scenarios in {output_dir}")


if __name__ == "__main__":
    generate_pcap_files("sample_pcaps")
