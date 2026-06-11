# 🎓 Skills Learned — Personal Firewall Project

## Skill 1: Protocol Analysis
**Where:** `src/packet_simulator.py` → `build_ip_packet()` and `src/firewall_engine.py` → `PacketParser`

You learn the binary layout of network protocols:
- IPv4 header: version, IHL, TTL, protocol number, source/dest IP
- TCP header: source port, dest port, sequence numbers, flags (SYN, ACK, FIN, RST)
- UDP header: ports, length, checksum
- How Python's `struct.pack/unpack` works with `!` (big-endian / network byte order)

**Real-world connection:** Wireshark, tcpdump, and Scapy all do this same parsing internally.

---

## Skill 2: Packet Filtering
**Where:** `src/firewall_engine.py` → `RuleEngine`

You learn:
- How rule-based filtering works (match fields → take action)
- Priority ordering (first matching rule wins — same as iptables)
- How `iptables` commands like `-A INPUT -p tcp --dport 23 -j DROP` map to code
- Default-allow vs default-deny policies

**Real-world connection:** AWS Security Groups, iptables, Windows Firewall, Palo Alto — all use this same model.

---

## Skill 3: Network Security
**Where:** `src/packet_simulator.py` → attack simulations, `main.py` → `--scan` and `--ddos` flags

You learn to recognise:
- **Port scans** — Many SYN packets to sequential ports from one IP
- **DDoS floods** — High-volume packets from many source IPs
- **Brute-force indicators** — Repeated connection attempts to port 3389 (RDP), 22 (SSH)
- **Insecure protocol usage** — Telnet (port 23), unencrypted HTTP (port 80)
- **Suspicious IPs** — How threat intelligence blocklists work

---

## Most Important Concepts (Ranked)

| Rank | Concept | Why It Matters |
|------|---------|----------------|
| ⭐⭐⭐ | Rule engine with priority | Core of every real firewall product |
| ⭐⭐⭐ | IP/TCP/UDP header structure | Foundation for all network security tools |
| ⭐⭐ | Raw socket capture | How IDS/IPS tools work (Snort, Suricata) |
| ⭐⭐ | Attack pattern recognition | Essential for SOC analyst roles |
| ⭐ | Statistics and monitoring | Needed for SIEM integration |

---

## What to Highlight in Your Internship Report

1. You implemented a **stateful rule engine** with priority ordering — the same model used in enterprise firewalls.
2. You **crafted raw network packets** from scratch using `struct`, giving you deep protocol knowledge.
3. You built a **simulated threat environment** that demonstrates port scans and DDoS without needing a real attacker.
4. You wrote **unit tests** for security-critical code — a professional software engineering practice.
