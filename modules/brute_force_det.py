from scapy.all import TCP, IP
from collections import defaultdict
import time
from core.alert import log_alert

THRESHOLD = 150
TIME_WINDOW = 10
AUTH_PORTS = {22, 21, 23, 3389, 80, 443}

trackers = {
    'SYN': defaultdict(list),
    'RST': defaultdict(list)
}

def analyze_packet(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        flags = packet[TCP].flags
        dst_port = packet[TCP].dport
        now = time.time()

        # 1. Detect SYN Flooding (Incoming to Auth Ports)
        if (flags & 0x02) and dst_port in AUTH_PORTS:
            trackers['SYN'][src_ip] = [t for t in trackers['SYN'][src_ip] if now - t < TIME_WINDOW]
            trackers['SYN'][src_ip].append(now)
            
            if len(trackers['SYN'][src_ip]) >= THRESHOLD:
                log_alert('SYN_FLOOD', src_ip, dst_ip=dst_ip, port=dst_port)

        # 2. Detect RST Flooding (Attacker sending RSTs)
        # We only flag if the attacker is the one INITIATING the RSTs
        elif (flags & 0x04): 
            trackers['RST'][src_ip] = [t for t in trackers['RST'][src_ip] if now - t < TIME_WINDOW]
            trackers['RST'][src_ip].append(now)

            if len(trackers['RST'][src_ip]) >= THRESHOLD:
                # If they are hitting AUTH_PORTS specifically, it's a brute force symptom
                if dst_port in AUTH_PORTS:
                    log_alert('RST_FLOOD', src_ip, dst_ip=dst_ip, port=dst_port)