from scapy.all import ARP, Ether, srp
import socket
from manuf import manuf

target_ip = '144.167.112.5/24' #target ip 

arp = ARP(pdst=target_ip) #create arp packet
ether = Ether(dst='ff:ff:ff:ff:ff:ff') #create ether broadcast packet, mac address indicates broadcasting
packet = ether/arp #stack them 

result = srp(packet, timeout=3)[0] #send and recveive packet at layer 2, set a timeout so script does not get stuck

#list of client that will be filled in the loop below
clients=[]

for sent, received in result: 
    ip = received.psrc
    mac = received.hwsrc
    
    p = manuf.MacParser() #create manuf parser object
    vendor = p.get_manuf(mac) #get the vendor of the device using the mac address
    hostname = socket.getfqdn(ip) #get the hostname of the device using the ip address

    clients.append({'ip': ip, 'mac': mac, 'hostname': hostname, 'vendor': vendor})
    
#print clients
print(f'Available devices on the network')
print(f'IP' + ' '*18+'mac' + ' '*18 + 'hostname' + ' '*18 + 'vendor')

for client in clients:
    print("{:16}  {}".format(client['ip'], client['mac'], client['hostname']))