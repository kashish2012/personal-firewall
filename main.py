"""
main.py
-------
Entry point for the Personal Firewall project.
Usage:
    python main.py                  # Simulation mode (no root needed)
    sudo python main.py --live      # Live capture mode (Linux, root required)
    python main.py --scan           # Simulate port scan only
    python main.py --ddos           # Simulate DDoS only
    python main.py --stats          # Print stats from last run
"""

import argparse
import sys
import os
import json

# Add src/ to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from firewall_engine import FirewallEngine, logger
from packet_simulator import PacketSimulator
from dashboard import get_dashboard


def print_banner():
    banner = r"""
  ╔══════════════════════════════════════════════════════╗
  ║       🔥  PERSONAL FIREWALL — Cybersecurity Tool     ║
  ║          Packet Filter | Monitor | Analyse           ║
  ╚══════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    parser = argparse.ArgumentParser(
        description="Personal Firewall — Cybersecurity Internship Project"
    )
    parser.add_argument("--live",  action="store_true",
                        help="Start live packet capture (requires root/sudo on Linux)")
    parser.add_argument("--iface", type=str, default=None,
                        help="Network interface to capture on (e.g. eth0, wlan0)")
    parser.add_argument("--scan",  action="store_true",
                        help="Run port-scan simulation only")
    parser.add_argument("--ddos",  action="store_true",
                        help="Run DDoS simulation only")
    parser.add_argument("--stats", action="store_true",
                        help="Print saved stats from last session")
    parser.add_argument("--rounds", type=int, default=2,
                        help="How many scenario rounds to run (default: 2)")
    args = parser.parse_args()

    print_banner()

    # ── Print saved stats ──────────────────────────────────────────────────
    if args.stats:
        path = "logs/report.json"
        if os.path.exists(path):
            with open(path) as f:
                data = json.load(f)
            print(json.dumps(data, indent=2))
        else:
            print("No report found. Run a simulation first.")
        return

    # ── Initialise engine ──────────────────────────────────────────────────
    engine = FirewallEngine(config_path="config/firewall_config.json")
    simulator = PacketSimulator(engine)
    dashboard = get_dashboard(engine, simulator)

    # ── Live capture mode ──────────────────────────────────────────────────
    if args.live:
        print("[*] Starting LIVE capture mode. Press Ctrl+C to stop.\n")
        try:
            engine.start_live_capture(iface=args.iface)
        except KeyboardInterrupt:
            engine.stop()
            print("\n[*] Capture stopped.")
            s = engine.get_stats()
            print(f"    Total: {s['total_packets']}  Blocked: {s['blocked']}")
        return

    # ── Targeted simulations ───────────────────────────────────────────────
    if args.scan:
        print("[*] Running port-scan simulation...\n")
        results = simulator.run_port_scan_simulation()
        for r in results:
            act = r.get("action")
            icon = "🚫" if act == "BLOCK" else "✅"
            print(f"  {icon} [{act}] {r.get('src_ip')} → :{r.get('dst_port')} "
                  f"({r.get('scenario_label', '')})")
        s = engine.get_stats()
        print(f"\n  Packets: {s['total_packets']}  Blocked: {s['blocked']}")
        return

    if args.ddos:
        print("[*] Running DDoS simulation...\n")
        results = simulator.run_ddos_simulation(count=30)
        blocked = sum(1 for r in results if r.get("action") == "BLOCK")
        print(f"  Flooded {len(results)} packets. Blocked: {blocked}")
        s = engine.get_stats()
        print(f"  Total: {s['total_packets']}  Blocked: {s['blocked']}")
        return

    # ── Default: full simulation dashboard ────────────────────────────────
    print("[*] Running SIMULATION mode (no root required)\n")
    dashboard.run(packet_delay=0.3, total_rounds=args.rounds)


if __name__ == "__main__":
    main()
