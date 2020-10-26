#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from time import sleep

from scapy.all import bind_layers
from scapy.all import sniff, sendp, send, get_if_list, get_if_hwaddr
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

packets_sent = 0

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

class SwitchTrace(Packet):
    fields_desc = [IntField("swid", 0),
                  IntField("qdepth", 0)]
    def extract_padding(self, p):
                return "", p

class IPOption_SWTRACE(IPOption):
    name = "SWTRACE"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swtraces",
                                  adjust=lambda pkt,l:l*2+4),
                    ShortField("count", 0),
                    PacketListField("swtraces",
                                   [],
                                   SwitchTrace,
                                   count_from=lambda pkt:(pkt.count*1)) ]

def main():

    # We'll accept 3 args:
    #   argv[1]: destination IP
    #   argv[2]: message string
    #   argv[3]: 0 for normal, 1 for RECIRC, 2 for PAUSE, 3 for RESUME
    #   argv[4]: number of packets to send
    if len(sys.argv)<5:
        print 'pass 4 arguments: <destination> "<message>" <etherType> <num_packets>'
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    print "sending on interface %s to %s" % (iface, str(addr))

    if sys.argv[3] == "1":
        pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff", type=TYPE_RECIRC)
    elif sys.argv[3] == "2":
        pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff", type=TYPE_PAUSE)
    elif sys.argv[3] == "3":
        pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff", type=TYPE_RESUME)
    else:
        pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff", type=TYPE_IPV4)

    pkt = pkt / IP(dst=addr) 
    pkt = pkt / UDP(dport=4321, sport=1234) 
    pkt = pkt / sys.argv[2]
        
    pkt.show2()

    try:
      print
      for i in range(int(sys.argv[4])):
        sendp(pkt, iface=iface, verbose=False)
        global packets_sent
        packets_sent += 1  
        sys.stdout.write("\rpackets sent: {0}".format(packets_sent))
        sys.stdout.flush()
        sleep(0.5)
    except KeyboardInterrupt:
        raise
    finally:
        print


if __name__ == '__main__':
    main()