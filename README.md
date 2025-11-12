## ARP Spoofer (Windows-Friendly)

Python tooling for ARP cache poisoning and on-path packet interception using Scapy and Npcap.

### Requirements
- Windows 10/11 (Npcap in "WinPcap Compatible Mode") or compatible environment with Scapy.
- Administrator privileges to modify ARP tables and enable IPv4 forwarding.
- Python 3.9+ with `scapy` installed (`pip install scapy`).
- Make sure you have install Npcap [comes packed with Wireshark and Nmap].

### Key Features
- Continuous ARP cache poisoning of gateway and target hosts.
- Active man-in-the-middle bridge: logs packets from target and gateway, forwards traffic in real time.
- Optional host discovery (`--scan`) to list reachable LAN devices (passive ARP table + active ARP ping).
- Automatic checksum recalculation on forwarded IP/TCP/UDP/ICMP packets.

### Usage

Run the CLI with PowerShell/CMD from the project root:

```powershell
python arpspoof.py --scan
```

This scans the local subnet (derived from the chosen interface or supplied `--scan-cidr`), prints a table of discovered hosts, and prompts for a target selection. The script keeps poisoning and forwarding until interrupted with `Ctrl+C`.

#### Manual Target Selection

```powershell
python arpspoof.py 192.168.1.25 --interface Ethernet0 --gatewayip 192.168.1.1 --interval 1
```

Provide `TARGET_IP` directly (plus optional gateway/target MAC addresses if you already know them). The script infers missing MACs via ARP table or Scapy lookups.

#### Host Discovery Options

- `--scan`: enable interactive discovery/selection.
- `--scan-cidr 192.168.10.0/24`: override the auto-detected network range.
- `--scan-timeout 4`: wait longer for ARP responses during active probing.
  - Discovery output hides multicast and other non-unicast entries; if nothing is listed, try expanding the CIDR or ensure the target has recently sent traffic.

#### Additional Flags

- `--interface NAME`: specific NIC to use (required if auto-detection fails).
- `--attackermac`, `--targetmac`, `--gatewaymac`: override MAC detection.
- `--disassociate`: randomize attacker MAC before poisoning.
- `--ipforward`: request IPv4 forwarding toggle (administrator rights required).
- `--stealth`: enable stealth mode with legitimate vendor MAC prefixes, adaptive rate limiting, and slower poisoning patterns to evade detection.
- `--jitter PERCENT`: add random timing jitter (0.0-1.0, e.g., 0.2 = ±20%) to avoid predictable patterns.
- `--min-interval TIME`: minimum interval between ARP packets to prevent flooding alerts.

#### Stealth Features

The `--stealth` flag implements several evasion techniques:

- **Legitimate Vendor MAC Prefixes**: Uses real OUI (Organizationally Unique Identifier) prefixes from common vendors (Intel, Apple, Cisco, etc.) instead of random or your real MAC, preventing vendor-based identification.
- **Adaptive Rate Limiting**: Starts with a faster initial burst, then gradually slows down to mimic natural ARP behavior.
- **ARP Deduplication**: Tracks and avoids sending identical ARP replies in quick succession, reducing duplicate ARP detection triggers.
- **Timing Jitter**: When combined with `--jitter`, adds randomness to packet timing to avoid predictable patterns that monitoring systems flag.

**Example stealth usage:**
```powershell
python arpspoof.py --scan --stealth --jitter 0.3 --interval 2
```

### Supported Interfaces
- Any network interface exposed to Npcap on Windows (for example: physical adapters like Ethernet or Wi‑Fi, virtual adapters from VPN software or hypervisors, and loopback/testing adapters such as the Microsoft KM‑TEST Loopback).
- Loopback and virtual adapters are ignored by discovery scans.

### Safety Notes
- Use on networks you own or have explicit permission to test.
- ARP spoofing can disrupt connectivity; stop the script to release the spoofed entries.

