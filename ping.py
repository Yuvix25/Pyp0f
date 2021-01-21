from scapy.all import *

def packet_callback(packet:Packet):
    packet.show()

s = sr(IP(dst='111.221.29.254')/TCP(dport=443, flags='S'))
sniff(filter="tcp",prn=packet_callback, count=5)
#print(s[0][TCP])