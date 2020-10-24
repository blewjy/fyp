/*
Plan: 
- We want to implement the PFC PAUSE frame sending mechanism in the data-plane, and we want to see that it works
- i.e. we want to see that when the buffer reaches a certain threshold, PAUSE frame is sent, and packets stop coming into the switch.
- Then, when the buffer clears, we want the RESUME frame to be sent, and packets continue to come in.

- So we have two types of packets, differentiated with a custom header. Similar to the MRI example.
- Those packets with custom headers are "our" packets, which we will pause.
- Packets without custom headers will be packets from a separate iperf flow. These will help to increase our queue length.

- Start with the simple h1--s1--s2--h2 topology.
- If we start sending "our" packets from h1 to h2, we should see "our" packets arriving at h2.
- Now, we want to see what parameters for our iperf flow will there be substantial queue length increase. Then we see where it stabilizes.
- At any of the switches, if it encounters that threshold, PAUSE frame will be sent backwards.
- Each switch has a flag at each port to check if its paused. If it is, all "our" packets (with the custom headers) will be dropped. This simulates the "pause".
- If the flow is paused, means that h2 will stop receiving "our" packets 
  - a cool way to visualize this maybe with rate? like count how many packets per second the receiver is receiving.
  - we can send maybe 10 packets per second
  - receiver should receive about 10 packets per second if no interruption
  - once paused, it should go down to 0 packets per second
  - then back up to 10 packets per second when resume
- Because we only have 2 switches, only s1 will receive the pause frame from s2, and only s1 will drop "our" packets.
- Once the switch sees that the queue has cleared, and if the switch itself is not paused, then RESUME frame will be sent.
  - gotta experiment what should be the definition of "queue has cleared"
  - probably when our custom packet comes in and the switch sees like 5 consecutive packets with 0 deq_qdepth, then consider clear
- Then the upstream switch will continue forwarding the packets.
- And we should see "our" packets arriving at h2.

- If we can replicate this behaviour with the simple topology, then we try to go for the CBD topology which will cause the deadlock
- We consider that the deadlock is detected if after we relax the iperf sending, we still do not see "our" packets arriving at the receiving hosts.
- This is because the RESUME frame cannot be sent out by the switches, as they themselves are paused. 




*/



/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_PAUSE = 0x1212; // defining another EtherType for our PAUSE frames (packets)
const bit<16> TYPE_IPV4 = 0x800;

const bit<5>  IPV4_OPTION_SWTRACE = 31;

#define MAX_HOPS 9

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> switchID_t;
typedef bit<32> qdepth_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header ipv4_option_t {
    bit<1> copyFlag;
    bit<2> optClass;
    bit<5> option;
    bit<8> optionLength;
}

header swtrace_count_t {
    bit<16> count;
}

header swtrace_t {
    switchID_t  swid;
    qdepth_t    qdepth;
}

struct ingress_metadata_t {
    bit<16>  count;
}

struct parser_metadata_t {
    bit<16>  remaining;
}

struct metadata {
    ingress_metadata_t ingress_metadata;
    parser_metadata_t parser_metadata;
}

struct headers {
    ethernet_t          ethernet;
    ipv4_t              ipv4;
    ipv4_option_t       ipv4_option;
    swtrace_count_t     swtrace_count;
    swtrace_t[MAX_HOPS] swtraces;
}

error { IPHeaderTooShort }

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        verify(hdr.ipv4.ihl >= 5, error.IPHeaderTooShort);
        transition select(hdr.ipv4.ihl) {
            5             : accept;
            default       : parse_ipv4_option;
        }    
    }

    state parse_ipv4_option {
        packet.extract(hdr.ipv4_option);
        transition select(hdr.ipv4_option.option) {
            IPV4_OPTION_SWTRACE: parse_swtrace_count;
            default: accept;
        }
    }

    state parse_swtrace_count {
        packet.extract(hdr.swtrace_count);
        meta.parser_metadata.remaining = hdr.swtrace_count.count;
        transition select(meta.parser_metadata.remaining) {
            0: accept;
            default: parse_swtrace;
        }
    }

    state parse_swtrace {
        packet.extract(hdr.swtraces.next);
        meta.parser_metadata.remaining = meta.parser_metadata.remaining  - 1;
        transition select(meta.parser_metadata.remaining) {
            0: accept;
            default: parse_swtrace;
        }
    }   


}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        // Regular ipv4 forward
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

        // We make all packets mutlicasted to all ports
        // Packets that we don't want to multicast handled at egress
        // TODO: Eventually, this will be for duplicating the packet to create a PAUSE frame.
        //       So this should be set if the queue is long. 
        //       How to check if queue is long? TBD. 
        //       Maybe we can have a counter how many packets passed the ingress, or sth like that.
        standard_metadata.mcast_grp = 1;
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    
    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action mark_as_pause() {
        hdr.ethernet.etherType = TYPE_PAUSE;
    }
    
    table check_pkt_dest {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            mark_as_pause;
            drop;
        }
        default_action = drop();
    }

    action add_swtrace(switchID_t swid) { 
        hdr.swtrace_count.count = hdr.swtrace_count.count + 1;
        hdr.swtraces.push_front(1);

        hdr.swtraces[0].setValid();
        hdr.swtraces[0].swid = swid;
        hdr.swtraces[0].qdepth = (qdepth_t)standard_metadata.deq_qdepth;

        hdr.ipv4.ihl = hdr.ipv4.ihl + 2;
        hdr.ipv4_option.optionLength = hdr.ipv4_option.optionLength + 8; 
	    hdr.ipv4.totalLen = hdr.ipv4.totalLen + 8;
    }

    table swtrace {
        actions = { 
	        add_swtrace; 
	        NoAction; 
        }
        default_action = NoAction();      
    }
    

    apply {

        if (hdr.swtrace_count.isValid()) {
            swtrace.apply();
        }

        // NOTE: Does not support sending packet to yourself, i.e. h1 send packet to h1 will not work, behaviour undefined!
        if (hdr.ipv4.isValid() && standard_metadata.egress_port == standard_metadata.ingress_port) {
            check_pkt_dest.apply();
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv4_option);
        packet.emit(hdr.swtrace_count);
        packet.emit(hdr.swtraces);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
