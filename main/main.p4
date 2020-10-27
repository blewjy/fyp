/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_RECIRC = 4;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE  = 2;

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_RECIRC = 0x1111; // defining another EtherType for our RECIRCULATED packets
const bit<16> TYPE_PAUSE = 0x1212; // defining another EtherType for our PAUSE packets
const bit<16> TYPE_RESUME = 0x1313; // defining another EtherType for our RESUME packets
const bit<16> TYPE_DROP = 0x1414; // defining another EtherType for packets to be dropped (for convenience)

#define IS_E2E_CLONE(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE)
const bit<32> E2E_CLONE_SESSION_ID = 11;

#define IS_RECIRCULATED(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_RECIRC)

#define MAX_PORTS 4

const bit<16> PAUSE_THRESHOLD = 10;
const bit<16> RESUME_THRESHOLD = 4;


register<bit<1>>(MAX_PORTS) egress_port_paused_state;
register<bit<1>>(MAX_PORTS) has_paused_upstream_port_state;

register<bit<16>>(1) num_recirc_packets;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> switchID_t;

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

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
}

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
            TYPE_RECIRC: parse_ipv4;
            TYPE_PAUSE: parse_ipv4;
            TYPE_RESUME: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
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
        standard_metadata.egress_spec = port;
        if (!IS_RECIRCULATED(standard_metadata)){
            hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
            hdr.ethernet.dstAddr = dstAddr;
            hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        }
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
        
        if (hdr.ethernet.isValid()){
            if (hdr.ethernet.etherType == TYPE_PAUSE) {
                // If this is a PAUSE frame, we pause the egress for this port
                egress_port_paused_state.write((bit<32>)standard_metadata.ingress_port - 1, (bit<1>)1);

                num_recirc_packets.write(0, (bit<16>)0);
                hdr.ethernet.etherType = TYPE_DROP;
                drop();
            } else if (hdr.ethernet.etherType == TYPE_RESUME) {
                // If this is a RESUME frame, we unpause the egress for this port
                egress_port_paused_state.write((bit<32>)standard_metadata.ingress_port - 1, (bit<1>)0);
                hdr.ethernet.etherType = TYPE_DROP;
                drop();
            }
        }

        if (IS_RECIRCULATED(standard_metadata)) {
            hdr.ethernet.etherType = TYPE_RECIRC;
            // We need to set back the mcast_grp so that the packet doesn't keep multicasting everytime it recirculates.
            standard_metadata.mcast_grp = 0; 
        }

        // NOTE: For now, let's put this check in ingress
        //       If we want to also detect actual long queue in the egress buffer, we can also move this check to egress.
        bit<16> num_recirculating;
        num_recirc_packets.read(num_recirculating, 0);

        // For every new packet (non-recirc, TYPE_IPV4 only), if buffer capacity already past threshold, we should send a pause packet to the flow's upstream.
        // It's ok to send multiple pause packets towards the same port, as there might be multiple flows through that port.
        // With this logic, each flow will only receive 1 pause packet.
        // NOTE: Actually... Each port should only need to receive 1 pause packet, no matter which flow.
        //       Because we are implementing the pause in a per port basis, not per flow, not per priority.
        //       But this implementation is still ok for simple topo like what we are doing now.
        if (hdr.ethernet.isValid() && hdr.ethernet.etherType == TYPE_IPV4 && num_recirculating > PAUSE_THRESHOLD) {
            standard_metadata.mcast_grp = 1;
        }

        // However, when we want to resume, we cannot use new incoming packets to trigger the resume, because there might not be any new incoming packets (all incoming flows may have been paused)
        // Resume needs to be triggered with currently recirculating packets
        // We check for resume condition in egress and force some packets to recirc.
        // Those forced recirc packets are caught here and multicasted as resume frames.
        if (hdr.ethernet.isValid() && hdr.ethernet.etherType == TYPE_RECIRC && (bit<32>)num_recirculating < MAX_PORTS) {
            bit<1> has_paused_upstream;
            has_paused_upstream_port_state.read(has_paused_upstream, (bit<32>)standard_metadata.ingress_port - 1);
            if (has_paused_upstream == (bit<1>)1) {
                standard_metadata.mcast_grp = 2;
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
        hdr.ethernet.etherType = TYPE_DROP;
        mark_to_drop(standard_metadata);
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
    
    apply {
        if (hdr.ipv4.isValid()) {
            if (standard_metadata.egress_port != standard_metadata.ingress_port) {
                // If its a valid ipv4 packet and its not going back out the same port it came in, we want to check if the egress_port tallies with destIP
                check_pkt_dest.apply();

                if (hdr.ethernet.etherType != TYPE_DROP) {
                    bit<1> paused_state;
                    egress_port_paused_state.read(paused_state, (bit<32>)standard_metadata.egress_port - 1);

                    bit<16> num_recirculating;
                    num_recirc_packets.read(num_recirculating, 0);
                    if (paused_state == (bit<1>)1) {
                        if (hdr.ethernet.etherType != TYPE_RECIRC) {
                            num_recirc_packets.write(0, num_recirculating + (bit<16>)1);
                        }
                        recirculate(standard_metadata);
                    } else {
                        // If there are more than 0 num_recirculating, we can safely decrement
                        if (num_recirculating > (bit<16>)0) {
                            num_recirc_packets.write(0, num_recirculating - (bit<16>)1);

                            // If there are less than MAX_PORTS recirculating packets, then we check whether its index's upstream has been paused.
                            // If it has been paused, we need to resume it.
                            num_recirc_packets.read(num_recirculating, 0);
                            if ((bit<32>)num_recirculating < MAX_PORTS) {
                                bit<1> has_paused_upstream;
                                has_paused_upstream_port_state.read(has_paused_upstream, (bit<32>)num_recirculating);
                                if (has_paused_upstream == (bit<1>)1) {
                                    // TODO: At this point, before recirculate, we have to put (bit<32>)num_recirculating inside the packet somehow,
                                    //       because the ingress pipeline later needs to know which port to send the resume frame to.
                                    //       This output port for this resume frame does not necessarily need to be the same port as the ingress_port of the original packet.
                                    recirculate(standard_metadata);
                                }
                            }
                        }
                    }
                }
            } else {
                // Otherwise, it is going out the same port it came in, this must be a pause/resume packet.
                 if (standard_metadata.mcast_grp == 1) {
                    hdr.ethernet.etherType = TYPE_PAUSE;
                    has_paused_upstream_port_state.write((bit<32>)standard_metadata.egress_port - 1, (bit<1>)1);
                } else if (standard_metadata.mcast_grp == 2) {
                    hdr.ethernet.etherType = TYPE_RESUME;
                    has_paused_upstream_port_state.write((bit<32>)standard_metadata.egress_port - 1, (bit<1>)0);
                }
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
