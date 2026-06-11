"""
firewall_engine.py
------------------
Core firewall engine: packet capture, rule matching, logging.
Skill Learned → Packet Filtering + Protocol Analysis
"""

import socket
import struct
import threading
import time
import json
import logging
import os
import sys
from datetime import datetime
from collections import defaultdict

# ── Logging setup ────────────────────────────────────────────────────────────
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/firewall.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("PersonalFirewall")


# ── Protocol map ─────────────────────────────────────────────────────────────
PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6"}


# ── Packet Parser ─────────────────────────────────────────────────────────────
class PacketParser:
    """
    Skill: Protocol Analysis
    Parses raw IP packets and extracts header fields.
    """

    @staticmethod
    def parse_ip_header(raw_data: bytes) -> dict:
        """Parse IPv4 header (first 20 bytes)."""
        if len(raw_data) < 20:
            return {}
        iph = struct.unpack("!BBHHHBBH4s4s", raw_data[:20])
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = (version_ihl & 0xF) * 4  # header length in bytes
        ttl = iph[5]
        protocol = iph[6]
        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])
        return {
            "version": version,
            "ihl": ihl,
            "ttl": ttl,
            "protocol": protocol,
            "protocol_name": PROTOCOLS.get(protocol, f"UNKNOWN({protocol})"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "raw_size": len(raw_data),
        }

    @staticmethod
    def parse_tcp_header(raw_data: bytes, offset: int) -> dict:
        """Parse TCP header."""
        if len(raw_data) < offset + 14:
            return {}
        tcph = struct.unpack("!HHLLBBHHH", raw_data[offset : offset + 20])
        flags = tcph[5]
        return {
            "src_port": tcph[0],
            "dst_port": tcph[1],
            "seq": tcph[2],
            "ack": tcph[3],
            "flag_syn": bool(flags & 0x02),
            "flag_ack": bool(flags & 0x10),
            "flag_fin": bool(flags & 0x01),
            "flag_rst": bool(flags & 0x04),
        }

    @staticmethod
    def parse_udp_header(raw_data: bytes, offset: int) -> dict:
        """Parse UDP header."""
        if len(raw_data) < offset + 8:
            return {}
        udph = struct.unpack("!HHHH", raw_data[offset : offset + 8])
        return {"src_port": udph[0], "dst_port": udph[1], "length": udph[2]}

    @classmethod
    def parse(cls, raw_data: bytes) -> dict:
        """Full packet parse: IP + transport layer."""
        pkt = cls.parse_ip_header(raw_data)
        if not pkt:
            return {}
        offset = pkt.get("ihl", 20)
        proto = pkt.get("protocol")
        if proto == 6:
            tcp = cls.parse_tcp_header(raw_data, offset)
            pkt.update(tcp)
        elif proto == 17:
            udp = cls.parse_udp_header(raw_data, offset)
            pkt.update(udp)
        pkt["timestamp"] = datetime.now().isoformat()
        return pkt


# ── Rule Engine ───────────────────────────────────────────────────────────────
class RuleEngine:
    """
    Skill: Packet Filtering
    Matches packets against allow/block rules with priority ordering.
    """

    def __init__(self, rules_path: str = "config/rules.json"):
        self.rules = []
        self.rules_path = rules_path
        self._load_rules()

    def _load_rules(self):
        if os.path.exists(self.rules_path):
            with open(self.rules_path) as f:
                data = json.load(f)
                self.rules = data.get("rules", [])
            logger.info(f"Loaded {len(self.rules)} firewall rules.")
        else:
            logger.warning("No rules file found — allowing all traffic.")

    def reload(self):
        """Hot-reload rules without restarting."""
        self._load_rules()

    def match(self, pkt: dict) -> tuple[str, str]:
        """
        Returns (action, rule_name).
        Action is 'ALLOW' or 'BLOCK'.
        Rules are evaluated in priority order (lower number = higher priority).
        """
        sorted_rules = sorted(self.rules, key=lambda r: r.get("priority", 99))
        for rule in sorted_rules:
            if self._matches(pkt, rule):
                return rule.get("action", "ALLOW").upper(), rule.get("name", "unnamed")
        return "ALLOW", "default-allow"

    def _matches(self, pkt: dict, rule: dict) -> bool:
        """Check if a packet matches a single rule."""
        checks = {
            "src_ip": lambda v: pkt.get("src_ip") == v,
            "dst_ip": lambda v: pkt.get("dst_ip") == v,
            "protocol": lambda v: pkt.get("protocol_name", "").upper() == v.upper(),
            "dst_port": lambda v: pkt.get("dst_port") == int(v),
            "src_port": lambda v: pkt.get("src_port") == int(v),
        }
        for field, checker in checks.items():
            if field in rule:
                try:
                    if not checker(rule[field]):
                        return False
                except Exception:
                    return False
        return True


# ── Statistics Tracker ────────────────────────────────────────────────────────
class StatsTracker:
    """
    Skill: Network Security Monitoring
    Tracks packet counts, blocked counts, top talkers.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.total = 0
        self.blocked = 0
        self.allowed = 0
        self.by_protocol: dict = defaultdict(int)
        self.by_src_ip: dict = defaultdict(int)
        self.by_dst_port: dict = defaultdict(int)
        self.start_time = time.time()

    def record(self, pkt: dict, action: str):
        with self.lock:
            self.total += 1
            proto = pkt.get("protocol_name", "UNKNOWN")
            src = pkt.get("src_ip", "?")
            dport = pkt.get("dst_port")
            self.by_protocol[proto] += 1
            self.by_src_ip[src] += 1
            if dport:
                self.by_dst_port[dport] += 1
            if action == "BLOCK":
                self.blocked += 1
            else:
                self.allowed += 1

    def summary(self) -> dict:
        uptime = round(time.time() - self.start_time, 1)
        top_ips = sorted(self.by_src_ip.items(), key=lambda x: x[1], reverse=True)[:5]
        top_ports = sorted(self.by_dst_port.items(), key=lambda x: x[1], reverse=True)[:5]
        return {
            "uptime_seconds": uptime,
            "total_packets": self.total,
            "allowed": self.allowed,
            "blocked": self.blocked,
            "by_protocol": dict(self.by_protocol),
            "top_src_ips": top_ips,
            "top_dst_ports": top_ports,
        }


# ── Firewall Core ─────────────────────────────────────────────────────────────
class FirewallEngine:
    """
    Main engine: ties together capture, parsing, rule matching, and logging.
    Skill: Network Security (full pipeline)
    """

    def __init__(self, config_path: str = "config/firewall_config.json"):
        self.config = self._load_config(config_path)
        self.rule_engine = RuleEngine(self.config.get("rules_path", "config/rules.json"))
        self.stats = StatsTracker()
        self.running = False
        self._packet_log = []

    def _load_config(self, path: str) -> dict:
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
        return {}

    def process_packet(self, raw_data: bytes, direction: str = "IN") -> dict:
        """Parse + match + log a single raw packet. Returns result dict."""
        pkt = PacketParser.parse(raw_data)
        if not pkt:
            return {}
        action, rule_name = self.rule_engine.match(pkt)
        self.stats.record(pkt, action)
        result = {**pkt, "action": action, "rule": rule_name, "direction": direction}
        self._log_packet(result)
        return result

    def _log_packet(self, result: dict):
        proto = result.get("protocol_name", "?")
        src = result.get("src_ip", "?")
        dst = result.get("dst_ip", "?")
        sport = result.get("src_port", "")
        dport = result.get("dst_port", "")
        action = result.get("action", "?")
        rule = result.get("rule", "?")
        port_info = f":{sport}→:{dport}" if sport or dport else ""
        msg = f"[{action}] {proto} {src}{port_info} → {dst} (rule: {rule})"
        if action == "BLOCK":
            logger.warning(msg)
        else:
            logger.info(msg)
        self._packet_log.append(result)

    def start_live_capture(self, iface: str = None):
        """
        Start raw socket capture (requires root/admin).
        Skill: Network Security + Protocol Analysis in action.
        """
        logger.info("Starting live packet capture (requires root/sudo)...")
        self.running = True
        try:
            # AF_PACKET = Linux raw socket
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
            if iface:
                s.bind((iface, 0))
            logger.info(f"Listening on {'all interfaces' if not iface else iface}...")
            while self.running:
                raw, _ = s.recvfrom(65535)
                # Ethernet header is 14 bytes; skip to IP
                self.process_packet(raw[14:], direction="IN")
        except PermissionError:
            logger.error("Root privileges required for live capture. Run with sudo.")
        except OSError as e:
            logger.error(f"Socket error: {e}")
        finally:
            self.running = False

    def stop(self):
        self.running = False
        logger.info("Firewall engine stopped.")

    def get_stats(self) -> dict:
        return self.stats.summary()
