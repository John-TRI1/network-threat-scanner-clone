from scapy.all import ARP, Ether, IP, TCP, send, sendp, get_if_addr, conf
import time

# target device we want to send normal traffic to
TARGET_IP = input('Enter the target IP address for baseline traffic: ')
# keeping this simple but high enough to be noticed
ARP_COUNT = 10
SYN_COUNT = 60
START_PORT = 80
DELAY = 0.1
METRICS_FILE = 'data/metrics_log.txt'  # this is where the baseline summary gets saved

def arp_baseline(source_ip, target_ip, iface):
    # send a couple arp requests like normal network traffic
    print(f'\n[*] Sending {ARP_COUNT} ARP baseline packets')

    for _ in range(ARP_COUNT):
        packet = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=target_ip, psrc=source_ip, op=1)
        sendp(packet, iface=iface, verbose=0)
        time.sleep(DELAY)


def syn_baseline(source_ip, target_ip):
    # send a few tcp syn packets to act like light traffic
    print(f'\n[*] Sending {SYN_COUNT} TCP-SYN baseline packets')

    for offset in range(SYN_COUNT):
        packet = IP(src=source_ip, dst=target_ip) / TCP(
            sport=40000 + offset,
            dport=START_PORT + offset,
            flags='S'
        )
        send(packet, verbose=0)
        time.sleep(DELAY)


def run_baseline():
    start_time = time.time()  # save the time before we send anything
    # this marks where this test starts in the log file
    with open(METRICS_FILE, 'a') as file:  # open the summary log file
        file.write(f'\n===== TEST START =====\n')  # mark where this test starts

    # grab the default network interface and local ip
    iface = conf.iface
    source_ip = get_if_addr(iface)

    print(f'[*] Interface: {iface}')
    print(f'[*] Source IP: {source_ip}')
    print(f'[*] Target IP: {TARGET_IP}')

    arp_baseline(source_ip, TARGET_IP, iface)
    syn_baseline(source_ip, TARGET_IP)

    end_time = time.time()  # grab the time again when the script finishes
    run_time = end_time - start_time  # this gives the full run time
    total_packets = ARP_COUNT + SYN_COUNT  # total packets we planned to send

    if run_time > 0:  # make sure we do not divide by zero
        packets_per_second = total_packets / run_time  # quick packets per second number
    else:
        packets_per_second = 0  # fallback if something weird happens with the timer

    # this writes the baseline info in one clean line
    with open(METRICS_FILE, 'a') as file:  # open the summary log file again to save this run
        file.write(f'BASELINE | Target: {TARGET_IP} | Packets: {total_packets} | ARP: {ARP_COUNT} | SYN: {SYN_COUNT} | TIME: {run_time:.2f}s | PPS: {packets_per_second:.2f}\n')  # save the baseline results in one line
        file.write(f'===== TEST END =====\n\n')  # mark where this test ends

    print('[*] Baseline traffic complete.')


if __name__ == '__main__':
    run_baseline()
