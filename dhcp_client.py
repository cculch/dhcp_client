from scapy.all import *
import time

my_src_mac =   '00:01:02:03:04:07'
my_interface = 'enx503eaabb51e7'
#interface = 'ens33'
my_trans_id = 0x01020304

def randomMAC():
    mac = [ 0xDE, 0xAD, random.randint(0x00, 0x29) , random.randint(0x00, 0x7f), random.randint(0x00, 0xff), random.randint(0x00, 0x29),]
    return ':'.join(map(lambda x: '%02x' % x, mac))

# Send Discover
def send_discover(src_mac, trans_id, interface):
    ethernet=   Ether(dst='ff:ff:ff:ff:ff:ff',src=src_mac)
    ip      =   IP(src ='0.0.0.0',dst='255.255.255.255')
    udp     =   UDP(sport=68,dport=67)
    bootp   =   BOOTP(chaddr = mac2str(src_mac),xid = trans_id,flags= 0x0)
    dhcp    =   DHCP(options=[('message-type','discover'),'end'])
    packet  =   ethernet / ip / udp / bootp / dhcp

    sendp(packet, iface = interface, verbose = 0)

# Receive Offer
def receive_offer(interface):
    received_offer = sniff(iface = interface, filter = 'port 68 and port 67', stop_filter=lambda pkt: BOOTP in pkt and pkt[BOOTP].op == 2 and pkt[DHCP].options[0][1] == 2, timeout=5)
    return received_offer


# Send Request
def send_request(src_mac, trans_id, offered_ip, server_ip, hostname, interface):
    ethernet=   Ether(dst='ff:ff:ff:ff:ff:ff',src=src_mac)
    ip      =   IP(src ='0.0.0.0',dst='255.255.255.255')
    udp     =   UDP(sport=68,dport=67)
    bootp   =   BOOTP(chaddr = mac2str(src_mac),xid = trans_id, flags= 0x0)
    dhcp    =   DHCP(options=[('message-type','request'),('client_id', src_mac),('requested_addr', offered_ip),('server_id', server_ip),('hostname', hostname),'end'])
    packet  =   ethernet / ip / udp / bootp / dhcp

    sendp(packet, iface = interface, verbose = 0)

# Receive Ack
def receive_ack(interface):
    received_ack = sniff(iface = interface, filter="port 68 and port 67", stop_filter=lambda pkt: BOOTP in pkt and pkt[BOOTP].op == 2 and pkt[DHCP].options[0][1] == 5, timeout=5)

    print('DHCP finished!')



# Release
def release_ip(src_mac, offered_ip, server_ip, trans_id, interface):
    ethernet=   Ether(dst='ff:ff:ff:ff:ff:ff',src=src_mac)
    ip      =   IP(src=offered_ip, dst=server_ip)
    udp     =   UDP(sport=68,dport=67)
    bootp   =   BOOTP(ciaddr=offered_ip, chaddr = mac2str(src_mac),xid = trans_id)
    dhcp    =   DHCP(options=[('message-type','release'),('client_id',chr(1),mac2str(src_mac)),('server_id', server_ip),'end'])
    packet  =   ethernet / ip / udp / bootp / dhcp

    sendp(packet, iface = interface, verbose = 0)

    print('IP released!')



send_discover(my_src_mac, my_trans_id, my_interface)

offer = receive_offer(my_interface)

#server_mac = received_offer[0]['Ether'].src
#server_ip = received_offer[0]['IP'].src
#offered_ip = received_offer[0]['BOOTP'].yiaddr
send_request(my_src_mac, my_trans_id, offer[0]['BOOTP'].yiaddr, offer[0]['IP'].src , 'test_hostname', my_interface)

receive_ack(my_interface)

print('Start sleeping')
time.sleep(5)
print('End sleeping')

release_ip(my_src_mac, offer[0]['BOOTP'].yiaddr, offer[0]['IP'].src, my_trans_id, my_interface )
