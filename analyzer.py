# import necessary packages
import socket
from scapy.all import *

# create socket for packet sniffing
s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.htons(0x0800))

# receive packets and store in a list
packet_list = s.recv(65565)

# loop through the packet list
for packet in packet_list:
    
    # analyze each packet
    # check if packet is an IP packet
    if packet.haslayer(IP):
        # extract source IP
        ip_src=packet[IP].src
        # extract destination IP
        ip_dst=packet[IP].dst
        
        # print source and destination IP
        print ("Source IP: " + ip_src + " Destination IP: " + ip_dst)
