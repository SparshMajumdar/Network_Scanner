import os
from utils import scan_ports, check_security, detect_arp_spoof

USE_MOCK = os.getenv("ENV") == "production"

def scan(ip_range):
    if USE_MOCK:
        return [
            {'ip': '192.168.1.2', 'mac': 'AA:BB:CC:DD:EE:01'},
            {'ip': '192.168.1.3', 'mac': 'AA:BB:CC:DD:EE:02'},
            {'ip': '192.168.1.4', 'mac': 'AA:BB:CC:DD:EE:03'}
        ]

    from scapy.all import ARP, Ether, srp
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=False)[0]
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices
