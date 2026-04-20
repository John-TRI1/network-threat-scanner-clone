#Runs scanner
from scapy.all import sniff, ARP, TCP, IP
from core import layered_scan
from core.alert import load_persistence
from modules.arp_monitor import check_arp
from modules.port_scan_det import check_port_scan
from modules.brute_force_det import analyze_packet
from modules.sniffer import process_packet

if __name__ == '__main__':
    # 1. Run your scanner
    layered_scan.run_scan()

    # 2. Run your sniffer
    print("\n[*] Scan finished. Starting live threat monitor...")
    sniff(filter="arp or tcp", prn=process_packet, store=0)

