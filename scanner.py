import os
import random
from utils import scan_ports, check_security, detect_arp_spoof

USE_MOCK = os.getenv("ENV") == "production"

# Generate a random MAC address
def generate_mac():
    return "AA:BB:{:02X}:{:02X}:{:02X}:{:02X}".format(
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
    )

# Generate fake devices based on IP range
def generate_mock_devices(ip_range, count=5):
    base_ip = ip_range.split('.')[0:3]  # Get the first three octets
    devices = []
    used_ips = set()

    while len(devices) < count:
        last_octet = random.randint(2, 254)
        ip = ".".join(base_ip + [str(last_octet)])

        if ip in used_ips:
            continue  # avoid duplicates

        used_ips.add(ip)
        devices.append({
            'ip': ip,
            'mac': generate_mac()
        })

    return devices

def scan(ip_range):
    if USE_MOCK:
        return generate_mock_devices(ip_range)

    # Real scan
    from scapy.all import ARP, Ether, srp
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=False)[0]
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices
