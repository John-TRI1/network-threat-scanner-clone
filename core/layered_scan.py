from scapy.all import ARP, Ether, srp, IP, ICMP, sr, TCP, sr1
import ipaddress
import sys
from ping3 import ping
from multiprocessing.pool import ThreadPool as Pool

#layer 1: ICMP PING SWEEP
#Create ICMP packet and send it to the network and see which devices respond

def ping_sweep(ip): 
	response = ping(ip, timeout=1, size=56)
	if response is not None and response is not False: 
		print(f'{ip} IS ALIVE, FOUND VIA ICMP (RTT:{response:.4f}s)')
		return ip
	else:
		pass

#layer 2: ARP-SCAN

def arp_scan(ip):
	arp = ARP(pdst=ip)
	ether = Ether(dst='ff:ff:ff:ff:ff:ff') 
	packet = ether/arp
	result = srp(packet, timeout=1, verbose=0)[0]

	for sent, received in result:
		print(f'{received.psrc} IS ALIVE, FOUND VIA ARP')
		return received.psrc
	return None


def run_scan():
	target_ip = input(f'Enter the IP address you want to scan (ie: 192.168.1.0/24): ') 
	ip_list = [str(ip) for ip in ipaddress.ip_network(target_ip, strict=False).hosts()]
	
	with Pool() as pool:
		results = pool.map(ping_sweep,  ip_list)
	alive = [ip for ip in results if ip is not None]
	print(f'\n{len(alive)} IP FOUND VIA ICMP')
	
	remaining = [ip for ip in ip_list if ip not in alive]
	with Pool() as pool: 
		arp_results = pool.map(arp_scan, remaining)
	arp_alive = [ip for ip in arp_results if ip is not None]
	print(f'\n{len(arp_alive)} IP FOUND VIA ARP-SCAN')
	
	all_alive = sorted(set(alive) | set(arp_alive))
	print(f'\n{len(all_alive)} TOTAL UNIQUE HOST FOUND')
	
	with open("known_hosts.txt", "w") as file:
		for ip in all_alive:
			file.write(ip + "\n")

def user_scan(userIP):
	target_ip = userIP
	ip_list = [str(ip) for ip in ipaddress.ip_network(target_ip, strict=False).hosts()]
	
	with Pool() as pool:
		results = pool.map(ping_sweep,  ip_list)
	alive = [ip for ip in results if ip is not None]
	remaining = [ip for ip in ip_list if ip not in alive]

	with Pool() as pool: 
		arp_results = pool.map(arp_scan, remaining)
	arp_alive = [ip for ip in arp_results if ip is not None]

	all_alive = sorted(set(alive) | set(arp_alive))
	
	return {
		"alive" : alive,
		"arp_alive" : arp_alive,
		"all_hosts" : all_alive
	}

if __name__ == '__main__':
    run_scan()