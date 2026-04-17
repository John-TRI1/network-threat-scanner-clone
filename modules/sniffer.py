from scapy.all import sniff, ARP, TCP, IP
from modules.arp_monitor import check_arp
from modules.port_scan_det import check_port_scan
from modules.brute_force_det import analyze_packet

#Gets all known hosts from the .txt file

known_hosts = open('data/known_hosts.txt', 'r').read().splitlines()

#capturing packets (specifically arp and tcp)
def process_packet(packet):
    if packet.haslayer(ARP):
        check_arp(packet)
    if packet.haslayer(TCP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        check_port_scan(packet)
        analyze_packet(packet)
if __name__ == '__main__':
    print(f"[*] Monitoring traffic for {len(known_hosts)} hosts...")
