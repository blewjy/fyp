#!/usr/bin/env python
import sys
import struct

from scapy.all import bind_layers
from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, get_if_addr
from scapy.all import Packet, IPOption
from scapy.all import PacketListField, ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import Ether, IP, UDP, Raw, TCP
from scapy.layers.inet import _IPOption_HDR

TYPE_IPV4 = 0x800
TYPE_RECIRC = 0x1111
TYPE_PAUSE = 0x1212
TYPE_RESUME = 0x1313

bind_layers(Ether, IP, type=TYPE_RECIRC)
bind_layers(Ether, IP, type=TYPE_PAUSE)
bind_layers(Ether, IP, type=TYPE_RESUME)

num_normal_pkts = 0
num_recirc_pkts = 0
num_other_pkts = 0

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
    fields_desc = [ IntField("swid", 0),
                  IntField("qdepth", 0),
                  IntField("numrecirc", 0)]
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

def handle_pkt(pkt, iface):
    if Ether in pkt:
        if pkt[Ether].src != get_if_hwaddr(iface):
            if pkt[Ether].type == TYPE_IPV4:
                global num_normal_pkts
                num_normal_pkts += 1
            elif pkt[Ether].type == TYPE_RECIRC:
                global num_recirc_pkts
                num_recirc_pkts += 1
            elif pkt[Ether].type == TYPE_PAUSE:
                print "pause packet received!"
            elif pkt[Ether].type == TYPE_RESUME:
                print "resume packet received!"
            else:
                global num_other_pkts
                num_other_pkts += 1
                pkt.show2()
            print "normal: {0}\trecirc: {1}\tother:{2}".format(num_normal_pkts, num_recirc_pkts, num_other_pkts)
        

            if IP in pkt and len(pkt[IP].options) > 0:
                for trace in pkt[IP].options[0].swtraces:
                    print trace.swid, trace.qdepth, trace.numrecirc
            # pkt.show2()
            sys.stdout.flush()

def main():
    iface = 'eth0'
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface, prn = lambda x: handle_pkt(x, iface))

if __name__ == '__main__':
    main()
