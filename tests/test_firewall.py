"""
test_firewall.py
----------------
Unit tests for firewall components.
Skill: Writing security-aware test cases.

Run with:  python -m pytest tests/ -v
       or: python tests/test_firewall.py
"""

import sys
import os
import struct
import socket
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from firewall_engine import PacketParser, RuleEngine, StatsTracker, FirewallEngine
from packet_simulator import PacketSimulator, build_ip_packet


# ── Helpers ────────────────────────────────────────────────────────────────────
def make_tcp_packet(src_ip: str, dst_ip: str,
                    src_port: int, dst_port: int) -> bytes:
    return build_ip_packet(src_ip, dst_ip, 6, src_port, dst_port)


def make_udp_packet(src_ip: str, dst_ip: str,
                    src_port: int, dst_port: int) -> bytes:
    return build_ip_packet(src_ip, dst_ip, 17, src_port, dst_port)


def make_icmp_packet(src_ip: str, dst_ip: str) -> bytes:
    return build_ip_packet(src_ip, dst_ip, 1)


# ── Test: PacketParser ────────────────────────────────────────────────────────
class TestPacketParser(unittest.TestCase):

    def test_parse_tcp_packet(self):
        raw = make_tcp_packet("192.168.1.1", "10.0.0.1", 54321, 80)
        pkt = PacketParser.parse(raw)
        self.assertEqual(pkt["src_ip"], "192.168.1.1")
        self.assertEqual(pkt["dst_ip"], "10.0.0.1")
        self.assertEqual(pkt["protocol_name"], "TCP")
        self.assertEqual(pkt["dst_port"], 80)
        self.assertEqual(pkt["src_port"], 54321)

    def test_parse_udp_packet(self):
        raw = make_udp_packet("172.16.0.5", "8.8.8.8", 50001, 53)
        pkt = PacketParser.parse(raw)
        self.assertEqual(pkt["protocol_name"], "UDP")
        self.assertEqual(pkt["dst_port"], 53)

    def test_parse_icmp_packet(self):
        raw = make_icmp_packet("192.168.1.1", "192.168.1.10")
        pkt = PacketParser.parse(raw)
        self.assertEqual(pkt["protocol_name"], "ICMP")

    def test_empty_data_returns_empty(self):
        pkt = PacketParser.parse(b"")
        self.assertEqual(pkt, {})

    def test_short_data_returns_empty(self):
        pkt = PacketParser.parse(b"\x00" * 10)
        self.assertEqual(pkt, {})


# ── Test: RuleEngine ──────────────────────────────────────────────────────────
class TestRuleEngine(unittest.TestCase):

    def _engine_with(self, rules: list) -> RuleEngine:
        """Create a rule engine with inline rules (no file needed)."""
        re = RuleEngine.__new__(RuleEngine)
        re.rules = rules
        re.rules_path = ""
        return re

    def test_block_by_port(self):
        re = self._engine_with([
            {"name": "block-telnet", "priority": 1,
             "action": "BLOCK", "protocol": "TCP", "dst_port": 23}
        ])
        pkt = {"protocol_name": "TCP", "dst_port": 23, "src_ip": "1.2.3.4"}
        action, rule = re.match(pkt)
        self.assertEqual(action, "BLOCK")
        self.assertEqual(rule, "block-telnet")

    def test_allow_by_default(self):
        re = self._engine_with([])
        pkt = {"protocol_name": "TCP", "dst_port": 443}
        action, rule = re.match(pkt)
        self.assertEqual(action, "ALLOW")
        self.assertEqual(rule, "default-allow")

    def test_priority_order(self):
        """Lower priority number wins."""
        re = self._engine_with([
            {"name": "low-prio-allow", "priority": 10, "action": "ALLOW",
             "dst_port": 80},
            {"name": "high-prio-block", "priority": 1,  "action": "BLOCK",
             "dst_port": 80},
        ])
        pkt = {"dst_port": 80}
        action, rule = re.match(pkt)
        self.assertEqual(action, "BLOCK")
        self.assertEqual(rule, "high-prio-block")

    def test_block_by_ip(self):
        re = self._engine_with([
            {"name": "ban-ip", "priority": 1, "action": "BLOCK",
             "src_ip": "45.33.32.156"}
        ])
        pkt = {"src_ip": "45.33.32.156", "dst_port": 80}
        action, _ = re.match(pkt)
        self.assertEqual(action, "BLOCK")

    def test_allow_different_ip(self):
        re = self._engine_with([
            {"name": "ban-ip", "priority": 1, "action": "BLOCK",
             "src_ip": "45.33.32.156"}
        ])
        pkt = {"src_ip": "192.168.1.1", "dst_port": 80}
        action, _ = re.match(pkt)
        self.assertEqual(action, "ALLOW")


# ── Test: StatsTracker ────────────────────────────────────────────────────────
class TestStatsTracker(unittest.TestCase):

    def test_counts(self):
        st = StatsTracker()
        st.record({"src_ip": "1.1.1.1", "protocol_name": "TCP", "dst_port": 80}, "ALLOW")
        st.record({"src_ip": "2.2.2.2", "protocol_name": "UDP", "dst_port": 53}, "BLOCK")
        self.assertEqual(st.total, 2)
        self.assertEqual(st.allowed, 1)
        self.assertEqual(st.blocked, 1)

    def test_protocol_breakdown(self):
        st = StatsTracker()
        for _ in range(3):
            st.record({"src_ip": "x", "protocol_name": "TCP"}, "ALLOW")
        st.record({"src_ip": "x", "protocol_name": "UDP"}, "ALLOW")
        self.assertEqual(st.by_protocol["TCP"], 3)
        self.assertEqual(st.by_protocol["UDP"], 1)


# ── Test: Full pipeline via simulator ─────────────────────────────────────────
class TestSimulatorPipeline(unittest.TestCase):

    def setUp(self):
        self.engine = FirewallEngine(config_path="config/firewall_config.json")
        self.sim = PacketSimulator(self.engine)

    def test_all_scenarios_produce_result(self):
        from packet_simulator import SCENARIOS
        for i in range(len(SCENARIOS)):
            result = self.sim.run_scenario(i)
            self.assertIn("action", result, f"Scenario {i} missing action")
            self.assertIn(result["action"], ("ALLOW", "BLOCK"))

    def test_telnet_is_blocked(self):
        """Scenario index 3 = Blocked Telnet."""
        result = self.sim.run_scenario(3)
        self.assertEqual(result.get("action"), "BLOCK")

    def test_https_is_allowed(self):
        """Scenario index 0 = Normal HTTPS."""
        result = self.sim.run_scenario(0)
        self.assertEqual(result.get("action"), "ALLOW")

    def test_port_scan_generates_packets(self):
        results = self.sim.run_port_scan_simulation()
        self.assertGreater(len(results), 0)

    def test_ddos_simulation(self):
        results = self.sim.run_ddos_simulation(count=10)
        self.assertEqual(len(results), 10)


if __name__ == "__main__":
    unittest.main(verbosity=2)
