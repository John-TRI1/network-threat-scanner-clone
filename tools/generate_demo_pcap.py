import argparse
import time

from scapy.all import ARP, Ether, IP, TCP, wrpcap


def build_demo_packets(attacker_ip: str, victim_ip: str) -> list:
    pkts: list = []
    now = time.time()
    eth = Ether(src="aa:aa:aa:aa:aa:aa", dst="ff:ff:ff:ff:ff:ff")

    # 1) ARP spoof signal: same psrc with different hwsrc values (ARP reply/op=2).
    arp1 = Ether(src="aa:aa:aa:aa:aa:aa", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, psrc=attacker_ip, pdst=victim_ip, hwsrc="aa:aa:aa:aa:aa:aa"
    )
    arp2 = Ether(src="bb:bb:bb:bb:bb:bb", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, psrc=attacker_ip, pdst=victim_ip, hwsrc="bb:bb:bb:bb:bb:bb"
    )
    arp1.time = now
    arp2.time = now + 0.5
    pkts.extend([arp1, arp2])

    # 2) Port scan: SYNs to many distinct destination ports within TIME_WINDOW.
    t = now + 1.0
    for i, dport in enumerate(range(1, 70)):  # > 50 distinct ports
        syn = eth / IP(src=attacker_ip, dst=victim_ip) / TCP(
            sport=40000 + i, dport=dport, flags="S"
        )
        syn.time = t + (i * 0.01)
        pkts.append(syn)

    # 3) SYN flood: many SYNs to an "auth port" (e.g., 22) within 10s.
    t2 = t + 2.0
    for i in range(160):  # > 150 threshold
        syn_flood = eth / IP(src=attacker_ip, dst=victim_ip) / TCP(
            sport=50000 + i, dport=22, flags="S"
        )
        syn_flood.time = t2 + (i * 0.01)
        pkts.append(syn_flood)

    # 4) RST flood: many RSTs within 10s (to auth port to match current logic).
    t3 = t2 + 2.0
    for i in range(160):
        rst_flood = eth / IP(src=attacker_ip, dst=victim_ip) / TCP(
            sport=60000 + i, dport=22, flags="R"
        )
        rst_flood.time = t3 + (i * 0.01)
        pkts.append(rst_flood)

    return pkts


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a demo PCAP that triggers all detectors.")
    parser.add_argument("--attacker-ip", default="10.9.0.66", help="Source IP used in the demo traffic")
    parser.add_argument("--victim-ip", default="10.9.0.10", help="Destination IP used in the demo traffic")
    parser.add_argument("--out", default="data/demo_attacks.pcap", help="Output PCAP path")
    args = parser.parse_args()

    pkts = build_demo_packets(args.attacker_ip, args.victim_ip)
    wrpcap(args.out, pkts)
    print(f"[*] Wrote {len(pkts)} packets to {args.out}")


if __name__ == "__main__":
    main()

