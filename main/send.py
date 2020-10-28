#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import time 

from scapy.all import bind_layers
from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import Ether, IP, UDP, TCP
from scapy.all import IntField, FieldListField, FieldLenField, ShortField, PacketListField
from scapy.layers.inet import _IPOption_HDR

TYPE_IPV4 = 0x800
TYPE_RECIRC = 0x1111
TYPE_PAUSE = 0x1212
TYPE_RESUME = 0x1313

bind_layers(Ether, IP, type=TYPE_RECIRC)
bind_layers(Ether, IP, type=TYPE_PAUSE)
bind_layers(Ether, IP, type=TYPE_RESUME)

num_pkts_sent = 0
num_normal_pkts_recv = 0
num_recirc_pkts_recv = 0
num_other_pkts_recv = 0

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

class SwitchTrace(Packet):
    fields_desc = [IntField("swid", 0), IntField("buffercount", 0)]

    def extract_padding(self, p):
        return "", p

class IPOption_SWTRACE(IPOption):
    name = "SWTRACE"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B", length_of="swtraces", adjust=lambda pkt,l:l*2+4),
                    ShortField("count", 0),
                    PacketListField("swtraces", [], SwitchTrace, count_from=lambda pkt:(pkt.count*1))
                ]

def main():

    if len(sys.argv)<4:
        print 'pass 3 arguments: <destination> <packet type> <num packets>'
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    if sys.argv[2] == "normal" or sys.argv[2] == "trace":
        ether_type = TYPE_IPV4
    elif sys.argv[2] == "pause":
        ether_type = TYPE_PAUSE
    elif sys.argv[2] == "resume":
        ether_type = TYPE_RESUME
     
    pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff", type=ether_type) 

    if sys.argv[2] == "trace":
        pkt = pkt / IP(dst=addr, options = IPOption_SWTRACE(count=0,swtraces=[])) 
    else:
        pkt = pkt / IP(dst=addr) 
        pkt = pkt / UDP(dport=4321, sport=1234) 

    # pkt.show2()
    i = 0
    while i < int(sys.argv[3]):
        sendp(pkt, iface=iface, verbose=False)
        global num_pkts_sent
        num_pkts_sent += 1
        print "Packets sent: %d" % num_pkts_sent
        i += 1
        time.sleep(0.2)
    

if __name__ == '__main__':
    main()
