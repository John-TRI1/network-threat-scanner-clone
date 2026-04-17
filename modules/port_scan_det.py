from scapy.all import TCP, IP
from collections import defaultdict
import time
from core.alert import log_alert

THRESHOLD = 50
TIME_WINDOW = 30

attempts = defaultdict(set)
first_seen = {}  # Changed from set() to dict()
alerted = set()  # Added missing alerted set

def check_port_scan(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP) and (packet[TCP].flags & 0x02):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport
        now = time.time()

        # Initialize or reset the time window for this IP
        if src_ip not in first_seen or (now - first_seen[src_ip] > TIME_WINDOW):
            first_seen[src_ip] = now
            attempts[src_ip].clear()
            # Optional: remove from alerted if you want to detect it again after reset
            if src_ip in alerted: alerted.remove(src_ip)

        # add port to this IP's set
        attempts[src_ip].add(dst_port)

        # check if threshold exceeded
        if len(attempts[src_ip]) >= THRESHOLD and src_ip not in alerted:
            alerted.add(src_ip)
            # Passing extra details to match your new alert.py
            log_alert('PORT_SCAN', src_ip, dst_ip=packet[IP].dst, port=dst_port)
