"""
dashboard.py
------------
Real-time terminal dashboard for the Personal Firewall.
Skill Learned → Network Security Monitoring + Visualization
"""

import time
import os
import sys
import json
import threading
from datetime import datetime

# Try rich for a better UI, fall back to plain text
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.columns import Columns
    from rich.text import Text
    from rich.live import Live
    from rich.layout import Layout
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

sys.path.insert(0, os.path.dirname(__file__))
from firewall_engine import FirewallEngine
from packet_simulator import PacketSimulator


# ── Color helpers (plain fallback) ────────────────────────────────────────────
ACTION_COLOR = {"ALLOW": "green", "BLOCK": "red"}
ICON = {"ALLOW": "✅", "BLOCK": "🚫"}


def clear():
    os.system("cls" if os.name == "nt" else "clear")


# ── Plain-text dashboard ──────────────────────────────────────────────────────
class PlainDashboard:
    def __init__(self, engine: FirewallEngine, simulator: PacketSimulator):
        self.engine = engine
        self.sim = simulator
        self.recent: list = []
        self.MAX_RECENT = 15

    def _add(self, result: dict):
        self.recent.insert(0, result)
        self.recent = self.recent[:self.MAX_RECENT]

    def render(self):
        clear()
        stats = self.engine.get_stats()
        now = datetime.now().strftime("%H:%M:%S")
        print("=" * 72)
        print(f"  🔥 PERSONAL FIREWALL — {now}   |   Uptime: {stats['uptime_seconds']}s")
        print("=" * 72)
        print(f"  Total: {stats['total_packets']}   "
              f"Allowed: {stats['allowed']}   "
              f"Blocked: {stats['blocked']}")
        print(f"  Protocols: {stats['by_protocol']}")
        print("-" * 72)
        print(f"  {'ACTION':<8} {'PROTO':<7} {'SRC IP':<18} {'DST PORT':<10} {'RULE'}")
        print("-" * 72)
        for r in self.recent:
            act = r.get("action", "?")
            proto = r.get("protocol_name", "?")
            src = r.get("src_ip", "?")
            dport = r.get("dst_port", "-")
            rule = r.get("rule", "?")
            icon = ICON.get(act, " ")
            print(f"  {icon} {act:<6} {proto:<7} {src:<18} {str(dport):<10} {rule}")
        print("=" * 72)

    def run(self, packet_delay: float = 0.4, total_rounds: int = 3):
        """Run all scenarios N times and print dashboard after each packet."""
        for _ in range(total_rounds):
            results = self.sim.run_all_scenarios(delay=0)
            for r in results:
                self._add(r)
                self.render()
                time.sleep(packet_delay)

        # Port scan demo
        print("\n  [!] Simulating port scan attack...")
        scan_results = self.sim.run_port_scan_simulation()
        for r in scan_results:
            self._add(r)
            self.render()
            time.sleep(0.15)

        # DDoS demo
        print("\n  [!] Simulating DDoS flood...")
        ddos_results = self.sim.run_ddos_simulation(count=15)
        for r in ddos_results:
            self._add(r)
            self.render()
            time.sleep(0.08)

        print("\n  ✅ Simulation complete. Check logs/firewall.log for full record.")
        self._save_report()

    def _save_report(self):
        stats = self.engine.get_stats()
        report_path = "logs/report.json"
        with open(report_path, "w") as f:
            json.dump(stats, f, indent=2)
        print(f"  📄 Stats report saved → {report_path}")


# ── Rich dashboard (if available) ─────────────────────────────────────────────
class RichDashboard:
    def __init__(self, engine: FirewallEngine, simulator: PacketSimulator):
        self.engine = engine
        self.sim = simulator
        self.console = Console()
        self.recent: list = []
        self.MAX_RECENT = 20

    def _add(self, result: dict):
        self.recent.insert(0, result)
        self.recent = self.recent[:self.MAX_RECENT]

    def _build_table(self) -> Table:
        table = Table(box=box.SIMPLE_HEAVY, show_header=True,
                      header_style="bold cyan", expand=True)
        table.add_column("Action", width=9)
        table.add_column("Proto", width=7)
        table.add_column("Src IP", width=18)
        table.add_column("→ Port", width=8)
        table.add_column("Dst IP", width=18)
        table.add_column("Rule / Scenario", width=28)
        table.add_column("Time", width=10)

        for r in self.recent:
            act = r.get("action", "?")
            color = ACTION_COLOR.get(act, "white")
            icon = ICON.get(act, " ")
            ts = r.get("timestamp", "")[-8:] if r.get("timestamp") else ""
            table.add_row(
                Text(f"{icon} {act}", style=f"bold {color}"),
                r.get("protocol_name", "?"),
                r.get("src_ip", "?"),
                str(r.get("dst_port", "-")),
                r.get("dst_ip", "?"),
                r.get("scenario_label", r.get("rule", "?")),
                ts,
            )
        return table

    def _build_stats_panel(self) -> Panel:
        stats = self.engine.get_stats()
        top_ips = ", ".join(f"{ip}({c})" for ip, c in stats["top_src_ips"])
        top_ports = ", ".join(f":{p}({c})" for p, c in stats["top_dst_ports"])
        body = (
            f"[bold]Uptime:[/] {stats['uptime_seconds']}s   "
            f"[bold]Total:[/] {stats['total_packets']}   "
            f"[green bold]Allowed:[/] {stats['allowed']}   "
            f"[red bold]Blocked:[/] {stats['blocked']}\n"
            f"[bold]Protocols:[/] {stats['by_protocol']}\n"
            f"[bold]Top IPs:[/] {top_ips or 'none yet'}\n"
            f"[bold]Top Ports:[/] {top_ports or 'none yet'}"
        )
        return Panel(body, title="📊 Live Statistics", border_style="cyan")

    def render_static(self):
        self.console.print(self._build_stats_panel())
        self.console.print(self._build_table())

    def run(self, packet_delay: float = 0.35, total_rounds: int = 3):
        self.console.print(Panel(
            "[bold cyan]🔥 Personal Firewall — Simulation Mode[/]\n"
            "Packets are being synthesised to demonstrate rule matching.\n"
            "Run with [bold]sudo python main.py --live[/] for real traffic capture.",
            border_style="bright_blue"
        ))
        time.sleep(1)

        for round_num in range(1, total_rounds + 1):
            self.console.rule(f"[cyan]Round {round_num}/{total_rounds} — Standard Traffic[/]")
            results = self.sim.run_all_scenarios(delay=0)
            for r in results:
                self._add(r)
                self.render_static()
                time.sleep(packet_delay)

        self.console.rule("[red]⚠ Port Scan Attack Simulation[/]")
        time.sleep(0.5)
        for r in self.sim.run_port_scan_simulation():
            self._add(r)
            self.render_static()
            time.sleep(0.12)

        self.console.rule("[red]⚠ UDP Flood / DDoS Simulation[/]")
        time.sleep(0.5)
        for r in self.sim.run_ddos_simulation(count=15):
            self._add(r)
            self.render_static()
            time.sleep(0.08)

        stats = self.engine.get_stats()
        report_path = "logs/report.json"
        with open(report_path, "w") as f:
            json.dump(stats, f, indent=2)

        self.console.print(Panel(
            f"[green]✅ Simulation complete![/]\n"
            f"Packets processed: [bold]{stats['total_packets']}[/]\n"
            f"Blocked: [red bold]{stats['blocked']}[/]   "
            f"Allowed: [green bold]{stats['allowed']}[/]\n"
            f"Full log → [bold]logs/firewall.log[/]\n"
            f"Stats JSON → [bold]{report_path}[/]",
            border_style="green",
            title="Session Summary"
        ))


def get_dashboard(engine, simulator):
    if HAS_RICH:
        return RichDashboard(engine, simulator)
    return PlainDashboard(engine, simulator)
