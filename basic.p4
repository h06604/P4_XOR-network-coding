/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>


const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_NC = 0x90;
#define MTU 1500
#define maximumsize 11808
#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_RESUBMIT 6
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

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
header NC_t{
    bit<4>  primitive;
    bit<12> label;
    bit<8>  prio;
    bit<8>  coeff;
}
header payload_t{
    bit<maximumsize>    input;
}


struct metadata {
    bit<32> packet_length;
    bit<32> packet_length_original;
    bit<maximumsize> payloadtmp;
    bit<32> encodingnumber;
    bit<32> encodingpointer;
    bit<8>  status;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    NC_t         NC;
    payload_t    payload;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition select(standard_metadata.instance_type){
            PKT_INSTANCE_TYPE_NORMAL : parse_packetsize_fisttime;
            PKT_INSTANCE_TYPE_RESUBMIT : parse_packetsize;
        }
    }

    state parse_packetsize_fisttime{
        meta.packet_length = standard_metadata.packet_length;
        meta.packet_length_original = standard_metadata.packet_length;
        transition parse_ethernet;
    }

    state parse_packetsize{
        meta.packet_length = meta.packet_length_original;
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        meta.packet_length = meta.packet_length - 14;
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    } 

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.packet_length = meta.packet_length - 20;
        transition select(hdr.ipv4.protocol) {
            TYPE_NC : parse_NC;          
            default : parse_payload; 
        }
    }
    state parse_NC{
        packet.extract(hdr.NC);
        meta.packet_length = meta.packet_length - 4;
        transition parse_payload;
    }

    state parse_payload{
        packet.extract(hdr.payload);
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

    action forward(macAddr_t dstAddr, egressSpec_t port){
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table forwarding {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            forward;     
            drop;
            NoAction;
        }
        size = 16;
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid()){
            forwarding.apply();
        }
         
    }

}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    register<bit<maximumsize>>(10000) sw_buffer;
    register<bit<32>>(2) pointer;
    bit<maximumsize> registertmp = 1;
    bit<32> registerindex = 32w0x00;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action buffer(){
        pointer.read(meta.encodingnumber, 0);

        hdr.NC.label = (bit<12>)meta.encodingnumber;
        hdr.NC.primitive = 4w1;

        if(meta.encodingnumber == 5000){
            meta.encodingnumber = 0;
        }
        sw_buffer.write(meta.encodingnumber, hdr.payload.input);
        meta.encodingnumber = meta.encodingnumber + 1;
        pointer.write(0,meta.encodingnumber);
    }

    action encoding(){
        pointer.read(meta.encodingpointer, 1);
        
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        hdr.NC.label = (bit<12>)meta.encodingpointer;
        hdr.NC.primitive = 4w3;

        sw_buffer.read(registertmp, meta.encodingpointer);
        sw_buffer.write(meta.encodingpointer, 0);/* clear*/

        if(registertmp != 0){
            hdr.payload.input = registertmp ^ hdr.payload.input;
            meta.encodingpointer = meta.encodingpointer + 1;            
        }

        if(meta.encodingpointer == 5000){
            meta.encodingpointer = 0;
        }

        pointer.write(1,meta.encodingpointer);
    }


    action decoding(){
        pointer.read(meta.encodingpointer, 1);

        hdr.NC.primitive = 4w0;

        sw_buffer.read(registertmp, meta.encodingpointer);
        sw_buffer.write(meta.encodingpointer, 0);/*clear*/

        if(registertmp != 0){
            hdr.payload.input = registertmp ^ hdr.payload.input;
            meta.encodingpointer = meta.encodingpointer + 1;            
        }

        if(meta.encodingpointer == 5000){
            meta.encodingpointer = 0;
        }

        pointer.write(1,meta.encodingpointer);
    }
    action cloning(){
        meta.status=1;
        hdr.NC.primitive = 4w0;
        pointer.read(meta.encodingpointer, 1);
        hdr.NC.label = (bit<12>)meta.encodingpointer;
        clone3(CloneType.E2E, 250, {standard_metadata , meta});
    }

    action remove_NC(){
        hdr.NC.setInvalid();
        hdr.ipv4.protocol = 0x06;
    }
    action noaction_prim(){
        hdr.NC.primitive = 4w0;
    }
    action buffer_prim(){
        hdr.NC.primitive = 4w1;
    }
    action encoding_prim(){
        hdr.NC.primitive = 4w2;
    }
    action decoding_prim(){
        hdr.NC.primitive = 4w3;
    }


    table processing {
        key = {
            hdr.NC.primitive: exact;
        }
        actions = {
            buffer;
            cloning;
            decoding;
        }
        size = 16;
    }

    table processing_redundancy {
        key = {
            meta.status: exact;
        }
        actions = {
            encoding;
        }
        size = 16;
    }

    table add_header{
        key = {
            hdr.ipv4.srcAddr: lpm;
        }
        actions = {
            noaction_prim;
            encoding_prim;
            decoding_prim;
            buffer_prim;
        }
        size = 16;
    }

    table remove_header {
        key = {
            hdr.ethernet.srcAddr: exact;
        }
        actions = {
            remove_NC;
        }
        size = 16;
    }      

    apply {
            if(hdr.payload.isValid() || hdr.NC.isValid()){
                if(hdr.NC.isValid() == false){
                    hdr.NC.setValid();
                    hdr.ipv4.protocol = 0x90;
                    add_header.apply();
                }
                if(meta.status == 1){
                    processing_redundancy.apply();       
                }else{
                    processing.apply();
                }
                remove_header.apply();
            }
        
        if(registertmp == 0){
            drop();
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
        packet.emit(hdr.NC);
        packet.emit(hdr.payload);
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