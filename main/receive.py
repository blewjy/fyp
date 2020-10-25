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

TYPE_PAUSE = 0x1212
bind_layers(Ether, IP, type=TYPE_PAUSE)

packets_sniffed = 0
regular_packets_received = 0
custom_packets_received = 0

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

class SwitchTrace(Packet):
    fields_desc = [ IntField("swid", 0),
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

def handle_pkt(pkt, iface):
    global packets_sniffed
    packets_sniffed += 1
    if get_if_hwaddr(iface) == pkt[Ether].dst:
        if IP in pkt and len(pkt[IP].options) > 0:
            global custom_packets_received
            custom_packets_received += 1
            max_qdepth = 0
            for trace in pkt[IP].options[0].swtraces:
                if trace.qdepth > max_qdepth:
                    max_qdepth = trace.qdepth
            pkt.show2()
            sys.stdout.flush()
            print max_qdepth
        else:
            global regular_packets_received
            regular_packets_received += 1
    
    # print custom_packets_received, regular_packets_received
    sys.stdout.write("custom packets: {0}\tregular packets: {1}\r".format(custom_packets_received, regular_packets_received))
    sys.stdout.flush()

    # if UDP in pkt and pkt[UDP].dport == 4321:
        # print "got a packet"
        # pkt.show2()
        # sys.stdout.flush()


def main():
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    print "my interface mac addr: %s" % get_if_hwaddr(iface)
    print
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x, iface))

if __name__ == '__main__':
    main()
