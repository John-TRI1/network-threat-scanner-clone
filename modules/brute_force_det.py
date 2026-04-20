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

alerted = {
    'SYN': set(),
    'RST': set()
}  # keep track of who already got flagged in this burst

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

            if len(trackers['SYN'][src_ip]) == 1 and src_ip in alerted['SYN']:
                alerted['SYN'].remove(src_ip)  # clear the old flag when a new burst starts

            if len(trackers['SYN'][src_ip]) >= THRESHOLD and src_ip not in alerted['SYN']:
                alerted['SYN'].add(src_ip)  # mark this ip so we only log the flood once
                log_alert('SYN_FLOOD', src_ip, dst_ip=dst_ip, port=dst_port)

        # 2. Detect RST Flooding (Attacker sending RSTs)
        # We only flag if the attacker is the one INITIATING the RSTs
        elif (flags & 0x04): 
            trackers['RST'][src_ip] = [t for t in trackers['RST'][src_ip] if now - t < TIME_WINDOW]
            trackers['RST'][src_ip].append(now)

            if len(trackers['RST'][src_ip]) == 1 and src_ip in alerted['RST']:
                alerted['RST'].remove(src_ip)  # clear the old flag when a new burst starts

            if len(trackers['RST'][src_ip]) >= THRESHOLD and src_ip not in alerted['RST']:
                # If they are hitting AUTH_PORTS specifically, it's a brute force symptom
                if dst_port in AUTH_PORTS:
                    alerted['RST'].add(src_ip)  # mark this ip so we only log the flood once
                    log_alert('RST_FLOOD', src_ip, dst_ip=dst_ip, port=dst_port)
