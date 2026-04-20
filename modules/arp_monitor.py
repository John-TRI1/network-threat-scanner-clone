from scapy.all import ARP
import time
from core.alert import log_alert

arp_cache = {}
alerted = set()

def check_arp(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        real_mac = packet[ARP].hwsrc
        source_ip = packet[ARP].psrc

        if source_ip in arp_cache:
            if arp_cache[source_ip] != real_mac:
                if source_ip not in alerted:
                        alerted.add(source_ip)  # remember this ip so we do not spam the same arp alert
                        log_alert('ARP_SPOOF', source_ip, dst_ip=packet[ARP].pdst, port="ARP")
        else:
            arp_cache[source_ip] = real_mac
