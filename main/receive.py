#!/usr/bin/env python
import sys
import struct
import os

from scapy.all import bind_layers
from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import PacketListField, ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import Ether, IP, TCP, UDP, Raw
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
total_buffered_pkts = 0

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
    print "pkts_sent: {0}\tnormal_recv: {1}\tother_recv: {2}\ttotal_buffered: {3}".format(num_pkts_sent, num_normal_pkts_recv, num_other_pkts_recv, total_buffered_pkts)
 

def handle_pkt(pkt, iface):
    global paused
    if Ether in pkt:
        if pkt[Ether].src != get_if_hwaddr(iface):
            if pkt[Ether].type == TYPE_IPV4:
                global num_normal_pkts_recv
                num_normal_pkts_recv += 1
                if IP in pkt and len(pkt[IP].options) > 0:
                    global total_buffered_pkts
                    total_buffered_pkts
                    for trace in pkt[IP].options[0].swtraces:
                        total_buffered_pkts += trace.buffercount
            elif pkt[Ether].type == TYPE_PAUSE:
                print "Pause packet received!"
                paused = True
            elif pkt[Ether].type == TYPE_RESUME:
                print "Resume packet received!"
                paused = False
            else:
                global num_other_pkts_recv
                num_other_pkts_recv += 1
            # pkt.show2()
            print_state()

def main():
    iface = get_if()
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface, prn = lambda x: handle_pkt(x, iface))

if __name__ == '__main__':
    main()
