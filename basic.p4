/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>


const bit<16> TYPE_IPV4 = 0x800;
#define MTU 1500
#define maximumsize 11840

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
header payload_t{
    bit<maximumsize>    input;
}

header payload_SYNACK{
    bit<320>    input;
}

header payload_ACK{
    bit<256>    input;
}

struct metadata {
    bit<32> packet_length;
    bit<maximumsize> payloadtmp;
    bit<32> encodingnumber;/****s1 register2 index0****/
    bit<32> encodingpointer;/****s1 register2 index1****/
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    payload_SYNACK  SYNACK;
    payload_ACK  ACK;
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
        meta.packet_length = standard_metadata.packet_length;
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
        transition select(meta.packet_length) {
            40 : parse_SYNACK;
            32 : parse_ACK;
            1480 : parse_payload;          
            default : accept; 
        }
    }

    state parse_SYNACK{
        packet.extract(hdr.SYNACK);
        transition accept;
    }

    state parse_ACK{
        packet.extract(hdr.ACK);
        transition accept;
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

    register<bit<maximumsize>>(10000) s1_register;
    register<bit<32>>(2) s1_pointer;

    register<bit<maximumsize>>(10000) s2_register;
    register<bit<32>>(2) s2_pointer;   

    bit<maximumsize> s1_registertmp = 1;
    bit<maximumsize> s2_registertmp = 1;
    bit<32> registerindex = 32w0x00;

    action s1_buffer(){
        s1_pointer.read(meta.encodingnumber, 0);


        if(meta.encodingnumber == 10000){
            meta.encodingnumber = 0;
        }
        s1_register.write(meta.encodingnumber, meta.payloadtmp);
        meta.encodingnumber = meta.encodingnumber + 1;
        s1_pointer.write(0,meta.encodingnumber);

    }

    action s1_encoding(){
        /*s1_pointer.read(meta.encodingnumber, 0);*/
        s1_pointer.read(meta.encodingpointer, 1);
        s1_register.read(s1_registertmp, meta.encodingpointer);
        /*s1_register.write(meta.encodingpointer, 0); clear

        if(s1_registertmp != 0){
            meta.payloadtmp = s1_registertmp ^ meta.payloadtmp;
            meta.encodingpointer = meta.encodingpointer + 1;        
        }*/

        meta.payloadtmp = s1_registertmp ^ meta.payloadtmp;
        meta.encodingpointer = meta.encodingpointer + 1;

        if(meta.encodingpointer == 10000){
            meta.encodingpointer = 0;
        }

        /*s1_pointer.write(0,meta.encodingnumber);*/
        s1_pointer.write(1,meta.encodingpointer);
    }

    action s2_buffer(){
        s2_pointer.read(meta.encodingnumber, 0);


        if(meta.encodingnumber == 10000){
            meta.encodingnumber = 0;
        }
        s2_register.write(meta.encodingnumber, meta.payloadtmp);
        meta.encodingnumber = meta.encodingnumber + 1;
        s2_pointer.write(0,meta.encodingnumber);

    }

    action s2_decoding(){
        /*s2_pointer.read(meta.encodingnumber, 0);*/
        s2_pointer.read(meta.encodingpointer, 1);
        s2_register.read(s2_registertmp, meta.encodingpointer);
        /*s2_register.write(meta.encodingpointer, 0); clear
        
        if(s2_registertmp != 0){
            meta.payloadtmp = s2_registertmp ^ meta.payloadtmp;
            meta.encodingpointer = meta.encodingpointer + 1;            
        }*/

        meta.payloadtmp = s2_registertmp ^ meta.payloadtmp;
        meta.encodingpointer = meta.encodingpointer + 1;  
        
        if(meta.encodingpointer == 10000){
            meta.encodingpointer = 0;
        }

        /*s2_pointer.write(0,meta.encodingnumber);*/
        s2_pointer.write(1,meta.encodingpointer);
    }

    action forward(macAddr_t dstAddr, egressSpec_t port){
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action conversion(){
        if(hdr.SYNACK.isValid()){
            meta.payloadtmp = (bit<maximumsize>)hdr.SYNACK.input;
        }
        else if(hdr.ACK.isValid()){
            meta.payloadtmp = (bit<maximumsize>)hdr.ACK.input;
        }
        else if(hdr.payload.isValid()){
            meta.payloadtmp = (bit<maximumsize>)hdr.payload.input;
        }
    }

    action deconversion(){
        if(hdr.SYNACK.isValid()){
            hdr.SYNACK.input = meta.payloadtmp[319:0];
        }
        else if(hdr.ACK.isValid()){
            hdr.ACK.input = meta.payloadtmp[255:0];
        }
        else if(hdr.payload.isValid()){
            hdr.payload.input = meta.payloadtmp;
        }
    }

    table ipv4_forward {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            forward;     
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    table s1_match {
        key = {
            hdr.ethernet.srcAddr: exact;
        }
        actions = {
            s1_buffer;
            s1_encoding;
            drop;     
            NoAction;
        }
        size = 1024;
    }
    table s2_match {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            s2_buffer;
            s2_decoding; 
            drop;    
            NoAction;
        }
        size = 1024;
    }

    apply {
        if (hdr.ipv4.isValid()) {
            if(hdr.SYNACK.isValid() || hdr.ACK.isValid() || hdr.payload.isValid()){
                conversion();
                s1_match.apply(); 
            }
            ipv4_forward.apply();
            if(hdr.SYNACK.isValid() || hdr.ACK.isValid() || hdr.payload.isValid()){
                s2_match.apply(); 
                deconversion();            
            }            
        }
        /*if(s1_registertmp == 0 || s2_registertmp == 0){
            drop();
        }*/
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {



    apply {
        
            
        
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
        packet.emit(hdr.SYNACK);
        packet.emit(hdr.ACK);
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