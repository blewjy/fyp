#!/usr/bin/env python

import argparse
import sys
import socket
import random
import struct

from scapy.all import bind_layers
from scapy.all import sendp, send, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import Ether, IP, UDP, TCP
from scapy.all import IntField, FieldListField, FieldLenField, ShortField, PacketListField
from scapy.layers.inet import _IPOption_HDR

from time import sleep

TYPE_IPV4 = 0x800
TYPE_RECIRC = 0x1111
TYPE_PAUSE = 0x1212
TYPE_RESUME = 0x1313

bind_layers(Ether, IP, type=TYPE_RECIRC)
bind_layers(Ether, IP, type=TYPE_PAUSE)
bind_layers(Ether, IP, type=TYPE_RESUME)

num_pkts_sent = 0

def get_if():
    ifs = get_if_list()
    iface = None
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface


def main():

    if len(sys.argv)<5:
        print 'pass 4 arguments: <destination> "<message>" <type> <no. of packets>'
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    if sys.argv[3] == "normal":
        ether_type = TYPE_IPV4
    elif sys.argv[3] == "recirc":
        ether_type = TYPE_RECIRC
    elif sys.argv[3] == "pause":
        ether_type = TYPE_PAUSE
    elif sys.argv[3] == "resume":
        ether_type = TYPE_RESUME
        
    pkt =       Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff", type=ether_type) 
    pkt = pkt / IP(dst=addr) 
    pkt = pkt / UDP(dport=4321, sport=1234) 
    pkt = pkt / sys.argv[2]

    pkt.show2()
    
    try:
      for i in range(int(sys.argv[4])):
        sendp(pkt, iface=iface)
        global num_pkts_sent
        num_pkts_sent += 1
        print "sent %d packets in total" % num_pkts_sent
        sleep(0.1)
    except KeyboardInterrupt:
        raise

if __name__ == '__main__':
    main()
