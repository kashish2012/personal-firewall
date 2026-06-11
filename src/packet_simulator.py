"""
packet_simulator.py
-------------------
Simulates realistic network packets for demo/testing without root privileges.
Skill Learned → Protocol Analysis (you see exactly what real packets look like)
"""

import struct
import socket
import random
import time
from datetime import datetime


# ── Well-known services (port → name) ────────────────────────────────────────
PORT_NAMES = {
    22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}

# ── Scenario library ──────────────────────────────────────────────────────────
SCENARIOS = [
    # (label, src_ip, dst_ip, proto_num, src_port, dst_port, description)
    ("Normal HTTPS",     "192.168.1.10",  "93.184.216.34",  6,  54321, 443,  "Regular web browsing"),
    ("Normal DNS",       "192.168.1.10",  "8.8.8.8",        17, 50000, 53,   "DNS lookup to Google"),
    ("SSH from LAN",     "192.168.1.5",   "192.168.1.1",    6,  45678, 22,   "Local SSH session"),
    ("Blocked Telnet",   "10.0.0.99",     "192.168.1.10",   6,  60001, 23,   "Insecure Telnet attempt"),
    ("Port Scan SYN",    "45.33.32.156",  "192.168.1.10",   6,  12345, 80,   "Nmap-style SYN probe"),
    ("Blocked RDP",      "185.220.101.5", "192.168.1.10",   6,  55555, 3389, "Remote Desktop brute-force"),
    ("ICMP Ping",        "192.168.1.1",   "192.168.1.10",   1,  0,     0,    "Router ping check"),
    ("MySQL Access",     "10.0.0.5",      "10.0.0.10",      6,  33456, 3306, "Database connection"),
    ("HTTP Request",     "192.168.1.20",  "172.217.14.46",  6,  57890, 80,   "Plain HTTP (unencrypted)"),
    ("SMB Internal",     "192.168.1.15",  "192.168.1.50",   6,  49152, 445,  "File share access"),
    ("Suspicious UDP",   "203.0.113.42",  "192.168.1.10",   17, 31337, 4444, "Unknown high-port UDP"),
    ("SMTP Outbound",    "192.168.1.10",  "74.125.24.27",   6,  54000, 25,   "Email sending"),
]


def _checksum(data: bytes) -> int:
    """Simple one's complement checksum."""
    s = 0
    for i in range(0, len(data) - 1, 2):
        s += (data[i] << 8) + data[i + 1]
    if len(data) % 2:
        s += data[-1] << 8
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def build_ip_packet(src_ip: str, dst_ip: str, proto: int,
                    src_port: int = 0, dst_port: int = 0,
                    flags: int = 0x02) -> bytes:
    """
    Craft a raw IPv4 packet with TCP/UDP/ICMP payload.
    This teaches exactly how the IP header is structured byte-by-byte.
    """
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)

    # ── Transport layer ──
    if proto == 6:  # TCP
        # src_port, dst_port, seq, ack_seq, data_offset+reserved, flags, window, checksum, urgent
        tcp = struct.pack("!HHLLBBHHH",
                          src_port, dst_port, random.randint(0, 2**32),
                          0, (5 << 4), flags, 65535, 0, 0)
        payload = tcp
    elif proto == 17:  # UDP
        # src_port, dst_port, length, checksum
        udp = struct.pack("!HHHH", src_port, dst_port, 8, 0)
        payload = udp
    else:  # ICMP or other
        # type=8 (echo request), code=0, checksum, id, seq
        icmp = struct.pack("!BBHHH", 8, 0, 0, random.randint(1, 65535), 1)
        payload = icmp

    # ── IP header ──
    total_len = 20 + len(payload)
    # ver+ihl, dscp, total_len, id, frag_offset, ttl, proto, checksum, src, dst
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
                         0x45, 0, total_len,
                         random.randint(0, 65535), 0,
                         64, proto, 0, src, dst)
    csum = _checksum(ip_hdr)
    ip_hdr = ip_hdr[:10] + struct.pack("!H", csum) + ip_hdr[12:]
    return ip_hdr + payload


class PacketSimulator:
    """
    Generates a stream of realistic packets for testing the firewall engine
    without needing root or a real network interface.
    """

    def __init__(self, engine):
        self.engine = engine
        self.packet_count = 0

    def run_scenario(self, scenario_index: int = None) -> dict:
        """Run one scenario (random if index not given). Returns result."""
        if scenario_index is None:
            scenario_index = random.randint(0, len(SCENARIOS) - 1)
        label, src, dst, proto, sport, dport, desc = SCENARIOS[scenario_index]
        raw = build_ip_packet(src, dst, proto, sport, dport)
        result = self.engine.process_packet(raw, direction="IN")
        result["scenario_label"] = label
        result["scenario_desc"] = desc
        self.packet_count += 1
        return result

    def run_all_scenarios(self, delay: float = 0.3) -> list:
        """Run every scenario once with a short delay between them."""
        results = []
        for i in range(len(SCENARIOS)):
            r = self.run_scenario(i)
            results.append(r)
            time.sleep(delay)
        return results

    def run_port_scan_simulation(self, target_ip: str = "192.168.1.10",
                                 attacker_ip: str = "45.33.32.156") -> list:
        """
        Simulate a port scan: rapid SYN packets to many ports.
        Skill: Recognise attack patterns.
        """
        results = []
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                        3306, 3389, 5432, 6379, 8080, 8443]
        for port in common_ports:
            raw = build_ip_packet(attacker_ip, target_ip, 6,
                                  random.randint(40000, 60000), port, flags=0x02)
            r = self.engine.process_packet(raw, direction="IN")
            r["scenario_label"] = f"Port Scan → :{port}"
            results.append(r)
            time.sleep(0.05)
        return results

    def run_ddos_simulation(self, target_ip: str = "192.168.1.10",
                            count: int = 20) -> list:
        """Simulate a simple UDP flood from random IPs."""
        results = []
        for _ in range(count):
            src = f"{random.randint(1,254)}.{random.randint(0,254)}." \
                  f"{random.randint(0,254)}.{random.randint(1,254)}"
            raw = build_ip_packet(src, target_ip, 17,
                                  random.randint(1024, 65535), 80)
            r = self.engine.process_packet(raw, direction="IN")
            r["scenario_label"] = "DDoS UDP flood"
            results.append(r)
        return results
