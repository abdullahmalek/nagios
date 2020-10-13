# import dpkt 
# from scapy.all import wrpcap, Ether, IP, UDP



# def sniffer():
    
#     with open("foo.pcap", "rb") as f:
#         pcap = dpkt.pcap.Reader(f)
#         for ts, buf in pcap:
#             l2 = dpkt.ethernet.Ethernet(buf)
#             print("Ethernet (L2) frame:", repr(l2))

#             if l2.type not in (dpkt.ethernet.ETH_TYPE_IP, dpkt.ethernet.ETH_TYPE_IP6):
#                 print("Not an IP packet")
#                 continue
#             l3 = l2.data
#             print("IP packet:", repr(l3))

#             if l3.p not in (dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP):
#                 print("Not TCP or UDP")
#                 continue

#             l4 = l3.data
#             print("Layer 4:", repr(l4))

#             if l4.dport in (53, 5353) or l4.sport in (53, 5353):
#                 dns = l4.data
#                 if not isinstance(dns, dpkt.dns.DNS):
#                     dns = dpkt.dns.DNS(dns)
#                 print("DNS packet:", repr(dns))




import dpkt
from dpkt.ip import IP
from dpkt.ethernet import Ethernet
from dpkt.arp import ARP
from scapy.all import wrpcap, Ether, IP, UDP


import struct
import socket
import ipaddress

# def ip2int(addr):                                                               
#     return struct.unpack("!I", socket.inet_aton(addr))[0]

def sniffer():
    packet = Ether() / IP(dst="1.2.3.4") / UDP(dport=123)
    wrpcap('foo.pcap', [packet])
    f = open('foo.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)

    sniffed = ""
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            print('Non IP Packet type not supported')
            continue

        ip = eth.data
        do_not_fragment = bool(dpkt.ip.IP_DF)
        more_fragments = bool(dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK
        sniffed = 'IP: '+str(ipaddress.ip_address(ip.src)) + ' -> '+str(ipaddress.ip_address(ip.dst)) + '   len='+str(ip.len) + '   ttl='+str(ip.ttl) + '   DF='+str(do_not_fragment)\
             +  '   MF='+str(more_fragments) + '   offset='+str(fragment_offset)
        return sniffed


if __name__ == '__main__':
    arr = sniffer()
    print(arr)
