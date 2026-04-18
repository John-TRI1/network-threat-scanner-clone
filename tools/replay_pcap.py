import argparse
import os
import sys
import time

from scapy.utils import PcapReader

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from core.alert import load_persistence
from modules.sniffer import process_packet


def replay_pcap(path: str, pps: float | None, realtime: bool) -> None:
    """
    Replays packets from a PCAP through the same detection pipeline used by live sniffing.
    This lets you test detections without requiring root / raw sniffing permissions.
    """
    last_ts: float | None = None
    delay_per_packet = (1.0 / pps) if (pps and pps > 0) else None

    with PcapReader(path) as reader:
        for pkt in reader:
            if realtime:
                ts = float(getattr(pkt, "time", 0.0) or 0.0)
                if last_ts is not None and ts > 0:
                    time.sleep(max(0.0, ts - last_ts))
                if ts > 0:
                    last_ts = ts
            elif delay_per_packet is not None:
                time.sleep(delay_per_packet)

            process_packet(pkt)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Replay a PCAP file through the network-threat-scanner detectors (no live sniffing)."
    )
    parser.add_argument("pcap", help="Path to a .pcap or .pcapng file")
    parser.add_argument(
        "--pps",
        type=float,
        default=None,
        help="Packets per second replay rate (ignored if --realtime is set)",
    )
    parser.add_argument(
        "--realtime",
        action="store_true",
        help="Replay according to packet timestamps (may be slow)",
    )
    parser.add_argument(
        "--load-persistence",
        action="store_true",
        help="Resume threat scores from threat_log.txt before replaying",
    )
    args = parser.parse_args()

    if args.load_persistence:
        load_persistence()

    print(f"[*] Replaying PCAP: {args.pcap}")
    replay_pcap(args.pcap, pps=args.pps, realtime=args.realtime)
    print("[*] Replay finished.")


if __name__ == "__main__":
    main()

