from scapy.all import *

src_mac =   '00:01:02:03:04:0c'
interface = 'ens33'

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
bootp_reply = received_offer[0]['BOOTP']

print('ser_mac = ' + received_offer[0]['Ether'].src)
print('ser_ip = ' + bootp_reply.siaddr)
print('offered_ip = ' + bootp_reply.yiaddr)

# Send Request
ethernet=   Ether(dst='ff:ff:ff:ff:ff:ff',src=src_mac)
ip      =   IP(src ='0.0.0.0',dst='255.255.255.255')
udp     =   UDP(sport=68,dport=67)
bootp   =   BOOTP(chaddr = mac2str(src_mac),xid =  0x01020304,flags= 0x0)
dhcp    =   DHCP(options=[('message-type','request'),('client_id', src_mac),('requested_addr', bootp_reply.yiaddr),('server_id', bootp_reply.siaddr),'end'])
packet  =   ethernet / ip / udp / bootp / dhcp

sendp(packet, iface = interface, verbose = 0)

# Receive Ack
received_ack = sniff(iface = interface, filter="port 68 and port 67", stop_filter=lambda pkt: BOOTP in pkt and pkt[BOOTP].op == 2 and pkt[DHCP].options[0][1] == 5, timeout=5)

print('DHCP finished!')







