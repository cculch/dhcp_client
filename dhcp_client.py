from scapy.all import *
import time

def randomMAC():
    mac = [ 0xDE, 0xAD, random.randint(0x00, 0x29) , random.randint(0x00, 0x7f), random.randint(0x00, 0xff), random.randint(0x00, 0x29),]
    return ':'.join(map(lambda x: '%02x' % x, mac))

src_mac =   '00:01:02:03:04:07'
interface = 'enx503eaabb51e7'
#interface = 'ens33'

print('src_mac = ' + src_mac)

# Send Discover
ethernet=   Ether(dst='ff:ff:ff:ff:ff:ff',src=src_mac)
ip      =   IP(src ='0.0.0.0',dst='255.255.255.255')
udp     =   UDP(sport=68,dport=67)
bootp   =   BOOTP(chaddr = mac2str(src_mac),xid =  0x01020304,flags= 0x0)
dhcp    =   DHCP(options=[('message-type','discover'),'end'])
packet  =   ethernet / ip / udp / bootp / dhcp

sendp(packet, iface = interface, verbose = 0)

# Receive Offer
received_offer = sniff(iface = interface, filter = 'port 68 and port 67', stop_filter=lambda pkt: BOOTP in pkt and pkt[BOOTP].op == 2 and pkt[DHCP].options[0][1] == 2, timeout=5)
#bootp_reply = received_offer[0]['BOOTP']

server_mac = received_offer[0]['Ether'].src
server_ip = received_offer[0]['IP'].src
offered_ip = received_offer[0]['BOOTP'].yiaddr

# Send Request
ethernet=   Ether(dst='ff:ff:ff:ff:ff:ff',src=src_mac)
ip      =   IP(src ='0.0.0.0',dst='255.255.255.255')
udp     =   UDP(sport=68,dport=67)
bootp   =   BOOTP(chaddr = mac2str(src_mac),xid =  0x01020304,flags= 0x0)
dhcp    =   DHCP(options=[('message-type','request'),('client_id', src_mac),('requested_addr', offered_ip),('server_id', server_ip),('hostname', 'shawn_test'),'end'])
packet  =   ethernet / ip / udp / bootp / dhcp

sendp(packet, iface = interface, verbose = 0)

# Receive Ack
received_ack = sniff(iface = interface, filter="port 68 and port 67", stop_filter=lambda pkt: BOOTP in pkt and pkt[BOOTP].op == 2 and pkt[DHCP].options[0][1] == 5, timeout=5)

print('DHCP finished!')

print('Start sleeping')
time.sleep(5)
print('End sleeping')


# Release
#ethernet=   Ether(dst=server_mac,src=src_mac)
ip      =   IP(src=offered_ip, dst=server_ip)
udp     =   UDP(sport=68,dport=67)
bootp   =   BOOTP(ciaddr=offered_ip, chaddr = mac2str(src_mac),xid =  0x01020305)
dhcp    =   DHCP(options=[('message-type','release'),('client_id',chr(1),mac2str(src_mac)),('server_id', server_ip),'end'])
packet  =   ethernet / ip / udp / bootp / dhcp

sendp(packet, iface = interface, verbose = 0)

print('IP released!')



