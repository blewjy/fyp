/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4   = 0x800;
const bit<16> TYPE_PAUSE  = 0x1212; // defining another EtherType for our PAUSE frames
const bit<16> TYPE_RESUME = 0x1313; // defining another EtherType for our RESUME frames

const bit<5>  IPV4_OPTION_SWTRACE = 31;

#define MAX_HOPS  9
#define MAX_PORTS 4

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> switchID_t;
typedef bit<32> bufferCount_t;

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
    switchID_t    swid;
    bufferCount_t buffercount;
}

struct ingress_metadata_t {
    bit<16> count;
}

struct parser_metadata_t {
    bit<16> remaining;
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

        if (hdr.swtrace_count.isValid()) {
            // Check if this packet's ingress port should be paused
            bit<1> ingress_port_should_pause;
            port_should_pause_states.read(ingress_port_should_pause, (bit<32>)standard_metadata.ingress_port - 1);
            if (ingress_port_should_pause == (bit<1>)1) {
                // If this ingress port should be paused, then we set this packet as a multicast packet, so that it will duplicate at the egress
                // Then, we need to check at egress that all multicast packets are dropped, except 2:
                // - The original packet going towards the original destination out of the original egress_spec should not be dropped
                // - The duplicated multicast packet going out of the same port it came in from should not be dropped, AND it should be marked as a pause packet.
                // - The rest of the packets should be dropped.
                standard_metadata.mcast_grp = 1;
            }

            // Check if this packet's egress port has been paused
            bit<1> egress_spec_has_been_paused;
            port_has_been_paused_states.read(egress_spec_has_been_paused, (bit<32>)standard_metadata.egress_spec - 1);
            if (egress_spec_has_been_paused == (bit<1>)1) {
                drop();
            }
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
            standard_metadata.egress_port: exact;
        }
        actions = {
            NoAction;
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

        // TEMP
        bit<1> temp_bool;
        port_should_pause_states.read(temp_bool, (bit<32>)standard_metadata.ingress_port - 1);

        // If queue length exceed a certain threshold, we mark this port as to be paused
        bit<1> mark = (bit<1>)0;
        if (temp_bool == (bit<1>)1 || (qdepth_t)standard_metadata.deq_qdepth > (qdepth_t)10) {
            mark = (bit<1>)1;
        }
        port_should_pause_states.write((bit<32>)standard_metadata.ingress_port - 1, mark);

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

        if (hdr.ipv4.isValid()) {
            if (standard_metadata.egress_port != standard_metadata.ingress_port) {
                // If its a valid ipv4 packet and its not going back out the same port it came in, we want to check if the egress_port tallies with destIP
                check_pkt_dest.apply();
            } else {
                // Otherwise, it is going out the same port it came in, this must be a pause packet.
                mark_as_pause();
            }
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
