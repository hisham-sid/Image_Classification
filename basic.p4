/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;


#define BLOOM_FILTER_ENTRIES 445000
#define BLOOM_FILTER_BIT_WIDTH 1

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

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header colors_t {
	bit<8> red;
	bit<8> green;
	bit<8> blue;
}

header counts_t {
	bit<32> number;
        bit<32> low_gray;
	bit<32> mid_gray;
	bit<32> high_gray;
	bit<32> tableval;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    //tcp_t tcp;
    udp_t udp;
    colors_t colors;
    counts_t counts;
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
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        //transition parse_tcp;
        transition parse_udp;
    }
    
    state parse_udp {
        packet.extract(hdr.udp);
        transition parse_color;
    }

    //state parse_tcp {
        //packet.extract(hdr.tcp);
        //transition parse_color;
    //}

    state parse_color {
        packet.extract(hdr.colors);
        transition parse_counts;
     }
    state parse_counts {
        packet.extract(hdr.counts);
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


   register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) bloom_filter;
   
   register<bit<32>>(3) gray_reg; 
   register<bit<32>>(1) count_reg;
   
    bit<32> filter_address;
    bit<1> filter_value;
    bit<32>count;
    bit<32> gray_pixel;
    bit<32> low_gray;
    bit<32> mid_gray;
    bit<32> high_gray;
    int<32> tester;
   

    action drop() {
        mark_to_drop(standard_metadata);
    }

     action compute_hashes(bit<8> colorR, bit<8> colorG, bit<8> colorB){
       //here all the colors are considered to create a hash address for the register position
       hash(filter_address, HashAlgorithm.crc32, (bit<32>)0, {colorR,
                                                           colorG,
                                                           colorB},
                                                           (bit<32>)BLOOM_FILTER_ENTRIES);

    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
	
	
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    action set_port(bit<32> newval) {
	hdr.counts.tableval=newval;
    }
   
    table logmatch {
        key = {
            tester: exact;
        }
        actions = {
            set_port;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
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
	    tester=(int<32>) hdr.counts.number; 
	    //formula is gray=0.299*red + 0.587*green +0.114*blue. I multiplied the formula by 64 to get whole numbers and then shifted 6 bits to the right
	    gray_pixel = 19 * (bit<32>)hdr.colors.red;
            gray_pixel = gray_pixel + 38 * (bit<32>)hdr.colors.green;
	    gray_pixel = gray_pixel + 7 * (bit<32>)hdr.colors.blue;
	    gray_pixel = gray_pixel >> 6;
            
	    
	    //read value from register, store in count
	    count_reg.read(count,0);
	    gray_reg.read(low_gray,0);
	    gray_reg.read(mid_gray,1);
	    gray_reg.read(high_gray,2);


	    compute_hashes(hdr.colors.red,hdr.colors.green,hdr.colors.blue);

	    //read the bloom filter value at that hashed address
	    bloom_filter.read(filter_value,filter_address);

	    //if its 0, that means its a new color, increment counter (also ignore the ending packet)
	    if (hdr.udp.srcPort!=10000) {
		    if ( gray_pixel < 85 ) {
		        	low_gray = low_gray + 1;
	            }
		   else if ( gray_pixel < 170  ) {
		   	mid_gray = mid_gray + 1;
	            }
		   else if (gray_pixel <256)  {
		   	high_gray = high_gray + 1;
                    }
	            if (filter_value==0 )
			    count=count+1;
	    }
	    //if its new color, set the value as 1. If its old, the value is 1 anyways
	    bloom_filter.write(filter_address,1);

	    //write the counter value to register
	    count_reg.write(0,count);
	    gray_reg.write(0,low_gray);
	    gray_reg.write(1,mid_gray);
	    gray_reg.write(2,high_gray);
	
	    //store the value in the dstPort. (this is just a placeholder for testing, we can store it in another part of the packet later)
	    hdr.counts.number=count;
	    hdr.counts.low_gray=low_gray;
	    hdr.counts.mid_gray=mid_gray;
	    hdr.counts.high_gray=high_gray;
            logmatch.apply();
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
    apply {  }
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
        //packet.emit(hdr.tcp);
	packet.emit(hdr.udp);
	//packet.emit(hdr.colors);
	packet.emit(hdr.counts);
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
