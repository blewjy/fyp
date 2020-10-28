#!/usr/bin/env python

import threading
import time
import argparse
import sys
import socket
import random
import struct

from scapy.all import bind_layers
from scapy.all import sniff, sendp, send, hexdump, get_if_list, get_if_hwaddr
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

paused = False

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

def print_state():
   global num_pkts_sent, num_normal_pkts_recv, num_other_pkts_recv
   print "pkts_sent: {0}\tnormal_recv: {1}\tother_recv: {2}".format(num_pkts_sent, num_normal_pkts_recv, num_other_pkts_recv)


class Sender(threading.Thread):

    def __init__(self, dest_ip, pkt_type, num_pkts):
        threading.Thread.__init__(self)
        self.dest_ip = dest_ip
        self.pkt_type = pkt_type
        self.num_pkts = num_pkts

    def run(self):
        addr = socket.gethostbyname(self.dest_ip)
        iface = get_if()

        if self.pkt_type == "normal" or self.pkt_type == "trace":
            ether_type = TYPE_IPV4
        elif self.pkt_type == "pause":
            ether_type = TYPE_PAUSE
        elif self.pkt_type == "resume":
            ether_type = TYPE_RESUME
         
        pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff", type=ether_type) 

        if self.pkt_type == "trace":
            pkt = pkt / IP(dst=addr, options = IPOption_SWTRACE(count=0,swtraces=[])) 
        else:
            pkt = pkt / IP(dst=addr) 
            pkt = pkt / UDP(dport=4321, sport=1234) 

        # pkt.show2()
        i = 0
        while i < int(self.num_pkts):
            global paused
            if not paused:
                sendp(pkt, iface=iface, verbose=False)
                global num_pkts_sent
                num_pkts_sent += 1
                i += 1
                print_state()
                time.sleep(0.5)
            else:
                print "Sending is paused"
                time.sleep(5)

    
class Receiver(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        iface = get_if()
        print "sniffing on %s" % iface
        sys.stdout.flush()
        sniff(iface = iface, prn = lambda x: self.handle_pkt(x, iface))

    def handle_pkt(self, pkt, iface):
        global paused
        if Ether in pkt:
            if pkt[Ether].src != get_if_hwaddr(iface):
                if pkt[Ether].type == TYPE_IPV4:
                    global num_normal_pkts_recv
                    num_normal_pkts_recv += 1
                elif pkt[Ether].type == TYPE_PAUSE:
                    print "Pause packet received!"
                    paused = True
                elif pkt[Ether].type == TYPE_RESUME:
                    print "Resume packet received!"
                    paused = False
                else:
                    global num_other_pkts_recv
                    num_other_pkts_recv += 1
                    pkt.show2()
                print_state()
        

def main():
    if len(sys.argv)<4:
        print 'pass 3 arguments: <destination> <type> <no. of packets>'
        exit(1)

    sender = Sender(sys.argv[1], sys.argv[2], sys.argv[3])
    sender.daemon = True
    sender.start()

    receiver = Receiver()
    receiver.daemon = True
    receiver.start()

    try:
        while True:
            time.sleep(100) # main thread needs to stay alive...
    except KeyboardInterrupt:
        raise
    finally:
        print "Exiting Main Thread"


if __name__ == '__main__':
   main()