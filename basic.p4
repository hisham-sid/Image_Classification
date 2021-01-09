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
	bit<32> sequence;
	bit<32> low_ratio;
	bit<32> mid_ratio;
	bit<32> high_ratio;
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
	/* --------------------------------------------------
	FUNCTION: mul
	GOAL: 	  Compute multiplication of two fixed-point numbers
	INPUTS:  A & B (both 32-bit integers)
	OUTPUT:   A*B (0:28:4 fixed-point number)
	OBS.:     Output is an approximation
	-----------------------------------------------------*/
	control mul(in bit<32> A, 
		    in bit<32> B,
		    inout bit<32> result) {

		bit<32> bothInt =32w0;
		bit<32> AintFrac =32w0;
		bit<32> BintFrac =32w0;
		bit<32> bothFrac =32w0;
		bit<8> tmp=8w0;
		bit<8> tmp2=8w0;

		action store_frac(bit<32> value) {
			bothFrac=value;
		}
		table frac_mul{
			key = {
				tmp: exact;
			}
			actions = {
				store_frac;
				NoAction;
			}
	
			const entries = {
				8w0 : store_frac(0x0);
				8w1 : store_frac(0x0);
				8w2 : store_frac(0x0);
				8w3 : store_frac(0x0);
				8w4 : store_frac(0x0);
				8w5 : store_frac(0x0);
				8w6 : store_frac(0x0);
				8w7 : store_frac(0x0);
				8w8 : store_frac(0x0);
				8w9 : store_frac(0x0);
				8w10 : store_frac(0x0);
				8w11 : store_frac(0x0);
				8w12 : store_frac(0x0);
				8w13 : store_frac(0x0);
				8w14 : store_frac(0x0);
				8w15 : store_frac(0x0);
				8w16 : store_frac(0x0);
				8w17 : store_frac(0x0);
				8w18 : store_frac(0x0);
				8w19 : store_frac(0x0);
				8w20 : store_frac(0x0);
				8w21 : store_frac(0x0);
				8w22 : store_frac(0x0);
				8w23 : store_frac(0x0);
				8w24 : store_frac(0x0);
				8w25 : store_frac(0x0);
				8w26 : store_frac(0x0);
				8w27 : store_frac(0x0);
				8w28 : store_frac(0x0);
				8w29 : store_frac(0x0);
				8w30 : store_frac(0x0);
				8w31 : store_frac(0x0);
				8w32 : store_frac(0x0);
				8w33 : store_frac(0x0);
				8w34 : store_frac(0x0);
				8w35 : store_frac(0x0);
				8w36 : store_frac(0x0);
				8w37 : store_frac(0x0);
				8w38 : store_frac(0x0);
				8w39 : store_frac(0x0);
				8w40 : store_frac(0x1);
				8w41 : store_frac(0x1);
				8w42 : store_frac(0x1);
				8w43 : store_frac(0x1);
				8w44 : store_frac(0x1);
				8w45 : store_frac(0x1);
				8w46 : store_frac(0x1);
				8w47 : store_frac(0x1);
				8w48 : store_frac(0x0);
				8w49 : store_frac(0x0);
				8w50 : store_frac(0x0);
				8w51 : store_frac(0x0);
				8w52 : store_frac(0x0);
				8w53 : store_frac(0x0);
				8w54 : store_frac(0x1);
				8w55 : store_frac(0x1);
				8w56 : store_frac(0x1);
				8w57 : store_frac(0x1);
				8w58 : store_frac(0x1);
				8w59 : store_frac(0x2);
				8w60 : store_frac(0x2);
				8w61 : store_frac(0x2);
				8w62 : store_frac(0x2);
				8w63 : store_frac(0x2);
				8w64 : store_frac(0x0);
				8w65 : store_frac(0x0);
				8w66 : store_frac(0x0);
				8w67 : store_frac(0x0);
				8w68 : store_frac(0x1);
				8w69 : store_frac(0x1);
				8w70 : store_frac(0x1);
				8w71 : store_frac(0x1);
				8w72 : store_frac(0x2);
				8w73 : store_frac(0x2);
				8w74 : store_frac(0x2);
				8w75 : store_frac(0x2);
				8w76 : store_frac(0x3);
				8w77 : store_frac(0x3);
				8w78 : store_frac(0x3);
				8w79 : store_frac(0x3);
				8w80 : store_frac(0x0);
				8w81 : store_frac(0x0);
				8w82 : store_frac(0x0);
				8w83 : store_frac(0x0);
				8w84 : store_frac(0x1);
				8w85 : store_frac(0x1);
				8w86 : store_frac(0x1);
				8w87 : store_frac(0x2);
				8w88 : store_frac(0x2);
				8w89 : store_frac(0x2);
				8w90 : store_frac(0x3);
				8w91 : store_frac(0x3);
				8w92 : store_frac(0x3);
				8w93 : store_frac(0x4);
				8w94 : store_frac(0x4);
				8w95 : store_frac(0x4);
				8w96 : store_frac(0x0);
				8w97 : store_frac(0x0);
				8w98 : store_frac(0x0);
				8w99 : store_frac(0x1);
				8w100 : store_frac(0x1);
				8w101 : store_frac(0x1);
				8w102 : store_frac(0x2);
				8w103 : store_frac(0x2);
				8w104 : store_frac(0x3);
				8w105 : store_frac(0x3);
				8w106 : store_frac(0x3);
				8w107 : store_frac(0x4);
				8w108 : store_frac(0x4);
				8w109 : store_frac(0x4);
				8w110 : store_frac(0x5);
				8w111 : store_frac(0x5);
				8w112 : store_frac(0x0);
				8w113 : store_frac(0x0);
				8w114 : store_frac(0x0);
				8w115 : store_frac(0x1);
				8w116 : store_frac(0x1);
				8w117 : store_frac(0x2);
				8w118 : store_frac(0x2);
				8w119 : store_frac(0x3);
				8w120 : store_frac(0x3);
				8w121 : store_frac(0x3);
				8w122 : store_frac(0x4);
				8w123 : store_frac(0x4);
				8w124 : store_frac(0x5);
				8w125 : store_frac(0x5);
				8w126 : store_frac(0x6);
				8w127 : store_frac(0x6);
				8w128 : store_frac(0x0);
				8w129 : store_frac(0x0);
				8w130 : store_frac(0x1);
				8w131 : store_frac(0x1);
				8w132 : store_frac(0x2);
				8w133 : store_frac(0x2);
				8w134 : store_frac(0x3);
				8w135 : store_frac(0x3);
				8w136 : store_frac(0x4);
				8w137 : store_frac(0x4);
				8w138 : store_frac(0x5);
				8w139 : store_frac(0x5);
				8w140 : store_frac(0x6);
				8w141 : store_frac(0x6);
				8w142 : store_frac(0x7);
				8w143 : store_frac(0x7);
				8w144 : store_frac(0x0);
				8w145 : store_frac(0x0);
				8w146 : store_frac(0x1);
				8w147 : store_frac(0x1);
				8w148 : store_frac(0x2);
				8w149 : store_frac(0x2);
				8w150 : store_frac(0x3);
				8w151 : store_frac(0x3);
				8w152 : store_frac(0x4);
				8w153 : store_frac(0x5);
				8w154 : store_frac(0x5);
				8w155 : store_frac(0x6);
				8w156 : store_frac(0x6);
				8w157 : store_frac(0x7);
				8w158 : store_frac(0x7);
				8w159 : store_frac(0x8);
				8w160 : store_frac(0x0);
				8w161 : store_frac(0x0);
				8w162 : store_frac(0x1);
				8w163 : store_frac(0x1);
				8w164 : store_frac(0x2);
				8w165 : store_frac(0x3);
				8w166 : store_frac(0x3);
				8w167 : store_frac(0x4);
				8w168 : store_frac(0x5);
				8w169 : store_frac(0x5);
				8w170 : store_frac(0x6);
				8w171 : store_frac(0x6);
				8w172 : store_frac(0x7);
				8w173 : store_frac(0x8);
				8w174 : store_frac(0x8);
				8w175 : store_frac(0x9);
				8w176 : store_frac(0x0);
				8w177 : store_frac(0x0);
				8w178 : store_frac(0x1);
				8w179 : store_frac(0x2);
				8w180 : store_frac(0x2);
				8w181 : store_frac(0x3);
				8w182 : store_frac(0x4);
				8w183 : store_frac(0x4);
				8w184 : store_frac(0x5);
				8w185 : store_frac(0x6);
				8w186 : store_frac(0x6);
				8w187 : store_frac(0x7);
				8w188 : store_frac(0x8);
				8w189 : store_frac(0x8);
				8w190 : store_frac(0x9);
				8w191 : store_frac(0xa);
				8w192 : store_frac(0x0);
				8w193 : store_frac(0x0);
				8w194 : store_frac(0x1);
				8w195 : store_frac(0x2);
				8w196 : store_frac(0x3);
				8w197 : store_frac(0x3);
				8w198 : store_frac(0x4);
				8w199 : store_frac(0x5);
				8w200 : store_frac(0x6);
				8w201 : store_frac(0x6);
				8w202 : store_frac(0x7);
				8w203 : store_frac(0x8);
				8w204 : store_frac(0x9);
				8w205 : store_frac(0x9);
				8w206 : store_frac(0xa);
				8w207 : store_frac(0xb);
				8w208 : store_frac(0x0);
				8w209 : store_frac(0x0);
				8w210 : store_frac(0x1);
				8w211 : store_frac(0x2);
				8w212 : store_frac(0x3);
				8w213 : store_frac(0x4);
				8w214 : store_frac(0x4);
				8w215 : store_frac(0x5);
				8w216 : store_frac(0x6);
				8w217 : store_frac(0x7);
				8w218 : store_frac(0x8);
				8w219 : store_frac(0x8);
				8w220 : store_frac(0x9);
				8w221 : store_frac(0xa);
				8w222 : store_frac(0xb);
				8w223 : store_frac(0xc);
				8w224 : store_frac(0x0);
				8w225 : store_frac(0x0);
				8w226 : store_frac(0x1);
				8w227 : store_frac(0x2);
				8w228 : store_frac(0x3);
				8w229 : store_frac(0x4);
				8w230 : store_frac(0x5);
				8w231 : store_frac(0x6);
				8w232 : store_frac(0x7);
				8w233 : store_frac(0x7);
				8w234 : store_frac(0x8);
				8w235 : store_frac(0x9);
				8w236 : store_frac(0xa);
				8w237 : store_frac(0xb);
				8w238 : store_frac(0xc);
				8w239 : store_frac(0xd);
				8w240 : store_frac(0x0);
				8w241 : store_frac(0x0);
				8w242 : store_frac(0x1);
				8w243 : store_frac(0x2);
				8w244 : store_frac(0x3);
				8w245 : store_frac(0x4);
				8w246 : store_frac(0x5);
				8w247 : store_frac(0x6);
				8w248 : store_frac(0x7);
				8w249 : store_frac(0x8);
				8w250 : store_frac(0x9);
				8w251 : store_frac(0xa);
				8w252 : store_frac(0xb);
				8w253 : store_frac(0xc);
				8w254 : store_frac(0xd);
				8w255 : store_frac(0xe);
			}
		}
		apply {
			bit<32> intA = 4w0 ++ A[31:4];
			bit<32> intB = 4w0 ++ B[31:4];
			bit<32> fracA=28w0 ++ A[3:0];
			bit<32> fracB=28w0 ++ B[3:0];
	
			bothInt=intA*intB;
			bothInt=bothInt << 4;

			AintFrac=intA*fracB;
			BintFrac=intB*fracA;

			tmp= A[3:0] ++ B[3:0];
			frac_mul.apply();
			result=bothInt+AintFrac+BintFrac+bothFrac;
		}
		
	}
	/* --------------------------------------------------
	FUNCTION: log2
	GOAL: 	  Compute logarithm base 2
	INPUTS:   x (32-bit integer)
	OUTPUT:   log2 x (0:28:4 fixed-point number)
	OBS.:     Output is an approximation
	-----------------------------------------------------*/
	control log2(in bit<32> x,
		     inout bit<32> log_x){
	
		bit<32> l = 32w0;
		bit<8> xq = 8w0;
		bit<32> log_xq = 32w0;
	
		action store_mssb_index(bit<32> index){
			l = index;
		}
	
		action set_xq(){
			if(l == 0x00000200){xq = x[31:24];}
			if(l == 0x000001F0){xq = x[30:23];}
			if(l == 0x000001E0){xq = x[29:22];}
			if(l == 0x000001D0){xq = x[28:21];}
			if(l == 0x000001C0){xq = x[27:20];}
			if(l == 0x000001B0){xq = x[26:19];}
			if(l == 0x000001A0){xq = x[25:18];}
			if(l == 0x00000190){xq = x[24:17];}
			if(l == 0x00000180){xq = x[23:16];}
			if(l == 0x00000170){xq = x[22:15];}
			if(l == 0x00000160){xq = x[21:14];}
			if(l == 0x00000150){xq = x[20:13];}
			if(l == 0x00000140){xq = x[19:12];}
			if(l == 0x00000130){xq = x[18:11];}
			if(l == 0x00000120){xq = x[17:10];}
			if(l == 0x00000110){xq = x[16:9];}
			if(l == 0x00000100){xq = x[15:8];}
			if(l == 0x000000F0){xq = x[14:7];}
			if(l == 0x000000E0){xq = x[13:6];}
			if(l == 0x000000D0){xq = x[12:5];}
			if(l == 0x000000C0){xq = x[11:4];}
			if(l == 0x000000B0){xq = x[10:3];}
			if(l == 0x000000A0){xq = x[9:2];}
			if(l == 0x00000090){xq = x[8:1];}
			if(l == 0x00000000){xq = x[7:0];}
		}
	
		table MSSB{
			key = {
				x: lpm;
			}
			actions = {
				store_mssb_index;
				NoAction;
			}
	
			const entries = {
				//Most significant set bit position stored in fixed-point representation
	            		0x80000000 &&& 32w0x80000000 : store_mssb_index(0x00000200);  //32
				0x40000000 &&& 32w0xc0000000 : store_mssb_index(0x000001F0); 
	            		0x20000000 &&& 32w0xe0000000 : store_mssb_index(0x000001E0); //30
				0x10000000 &&& 32w0xf0000000 : store_mssb_index(0x000001D0);  
	            		0x08000000 &&& 32w0xf8000000 : store_mssb_index(0x000001C0);
				0x04000000 &&& 32w0xfc000000 : store_mssb_index(0x000001B0);
	            		0x02000000 &&& 32w0xfe000000 : store_mssb_index(0x000001A0);
				0x01000000 &&& 32w0xff000000 : store_mssb_index(0x00000190); //25
	            		0x00800000 &&& 32w0xff800000 : store_mssb_index(0x00000180);
				0x00400000 &&& 32w0xffc00000 : store_mssb_index(0x00000170);
	            		0x00200000 &&& 32w0xffe00000 : store_mssb_index(0x00000160);
				0x00100000 &&& 32w0xfff00000 : store_mssb_index(0x00000150);
	            		0x00080000 &&& 32w0xfff80000 : store_mssb_index(0x00000140); //20
				0x00040000 &&& 32w0xfffc0000 : store_mssb_index(0x00000130);
	            		0x00020000 &&& 32w0xfffe0000 : store_mssb_index(0x00000120);
				0x00010000 &&& 32w0xffff0000 : store_mssb_index(0x00000110);
	            		0x00008000 &&& 32w0xffff8000 : store_mssb_index(0x00000100);
				0x00004000 &&& 32w0xffffc000 : store_mssb_index(0x000000F0); //15
	            		0x00002000 &&& 32w0xffffe000 : store_mssb_index(0x000000E0);
				0x00001000 &&& 32w0xfffff000 : store_mssb_index(0x000000D0);
	            		0x00000800 &&& 32w0xfffff800 : store_mssb_index(0x000000C0);
				0x00000400 &&& 32w0xfffffc00 : store_mssb_index(0x000000B0);
	            		0x00000200 &&& 32w0xfffffe00 : store_mssb_index(0x000000A0); //10
				0x00000100 &&& 32w0xffffff00 : store_mssb_index(0x00000090);
			}
		}
	
		action set_log_xq(bit<32> value){
			log_xq = value;
		}
	
		table logTable{
			key = {
				xq: exact;
			}
	
			actions = {
				set_log_xq;
				NoAction;
			}
	
			const entries = {
				//Log2 of all possible 8-bit integer values
				(8w0) : set_log_xq(0x00000000);
				(8w1) : set_log_xq(0x00000000);
				(8w2) : set_log_xq(0x00000010);
				(8w3) : set_log_xq(0x00000019);
				(8w4) : set_log_xq(0x00000020);
				(8w5) : set_log_xq(0x00000025);
				(8w6) : set_log_xq(0x00000029);
				(8w7) : set_log_xq(0x0000002C);
				(8w8) : set_log_xq(0x00000030);
				(8w9) : set_log_xq(0x00000032);
				(8w10) : set_log_xq(0x00000035);
				(8w11) : set_log_xq(0x00000037);
				(8w12) : set_log_xq(0x00000039);
				(8w13) : set_log_xq(0x0000003B);
				(8w14) : set_log_xq(0x0000003C);
				(8w15) : set_log_xq(0x0000003E);
				(8w16) : set_log_xq(0x00000040);
				(8w17) : set_log_xq(0x00000041);
				(8w18) : set_log_xq(0x00000042);
				(8w19) : set_log_xq(0x00000043);
				(8w20) : set_log_xq(0x00000045);
				(8w21) : set_log_xq(0x00000046);
				(8w22) : set_log_xq(0x00000047);
				(8w23) : set_log_xq(0x00000048);
				(8w24) : set_log_xq(0x00000049);
				(8w25) : set_log_xq(0x0000004A);
				(8w26) : set_log_xq(0x0000004B);
				(8w27) : set_log_xq(0x0000004C);
				(8w28) : set_log_xq(0x0000004C);
				(8w29) : set_log_xq(0x0000004D);
				(8w30) : set_log_xq(0x0000004E);
				(8w31) : set_log_xq(0x0000004F);
				(8w32) : set_log_xq(0x00000050);
				(8w33) : set_log_xq(0x00000050);
				(8w34) : set_log_xq(0x00000051);
				(8w35) : set_log_xq(0x00000052);
				(8w36) : set_log_xq(0x00000052);
				(8w37) : set_log_xq(0x00000053);
				(8w38) : set_log_xq(0x00000053);
				(8w39) : set_log_xq(0x00000054);
				(8w40) : set_log_xq(0x00000055);
				(8w41) : set_log_xq(0x00000055);
				(8w42) : set_log_xq(0x00000056);
				(8w43) : set_log_xq(0x00000056);
				(8w44) : set_log_xq(0x00000057);
				(8w45) : set_log_xq(0x00000057);
				(8w46) : set_log_xq(0x00000058);
				(8w47) : set_log_xq(0x00000058);
				(8w48) : set_log_xq(0x00000059);
				(8w49) : set_log_xq(0x00000059);
				(8w50) : set_log_xq(0x0000005A);
				(8w51) : set_log_xq(0x0000005A);
				(8w52) : set_log_xq(0x0000005B);
				(8w53) : set_log_xq(0x0000005B);
				(8w54) : set_log_xq(0x0000005C);
				(8w55) : set_log_xq(0x0000005C);
				(8w56) : set_log_xq(0x0000005C);
				(8w57) : set_log_xq(0x0000005D);
				(8w58) : set_log_xq(0x0000005D);
				(8w59) : set_log_xq(0x0000005E);
				(8w60) : set_log_xq(0x0000005E);
				(8w61) : set_log_xq(0x0000005E);
				(8w62) : set_log_xq(0x0000005F);
				(8w63) : set_log_xq(0x0000005F);
				(8w64) : set_log_xq(0x00000060);
				(8w65) : set_log_xq(0x00000060);
				(8w66) : set_log_xq(0x00000060);
				(8w67) : set_log_xq(0x00000061);
				(8w68) : set_log_xq(0x00000061);
				(8w69) : set_log_xq(0x00000061);
				(8w70) : set_log_xq(0x00000062);
				(8w71) : set_log_xq(0x00000062);
				(8w72) : set_log_xq(0x00000062);
				(8w73) : set_log_xq(0x00000063);
				(8w74) : set_log_xq(0x00000063);
				(8w75) : set_log_xq(0x00000063);
				(8w76) : set_log_xq(0x00000063);
				(8w77) : set_log_xq(0x00000064);
				(8w78) : set_log_xq(0x00000064);
				(8w79) : set_log_xq(0x00000064);
				(8w80) : set_log_xq(0x00000065);
				(8w81) : set_log_xq(0x00000065);
				(8w82) : set_log_xq(0x00000065);
				(8w83) : set_log_xq(0x00000066);
				(8w84) : set_log_xq(0x00000066);
				(8w85) : set_log_xq(0x00000066);
				(8w86) : set_log_xq(0x00000066);
				(8w87) : set_log_xq(0x00000067);
				(8w88) : set_log_xq(0x00000067);
				(8w89) : set_log_xq(0x00000067);
				(8w90) : set_log_xq(0x00000067);
				(8w91) : set_log_xq(0x00000068);
				(8w92) : set_log_xq(0x00000068);
				(8w93) : set_log_xq(0x00000068);
				(8w94) : set_log_xq(0x00000068);
				(8w95) : set_log_xq(0x00000069);
				(8w96) : set_log_xq(0x00000069);
				(8w97) : set_log_xq(0x00000069);
				(8w98) : set_log_xq(0x00000069);
				(8w99) : set_log_xq(0x0000006A);
				(8w100) : set_log_xq(0x0000006A);
				(8w101) : set_log_xq(0x0000006A);
				(8w102) : set_log_xq(0x0000006A);
				(8w103) : set_log_xq(0x0000006A);
				(8w104) : set_log_xq(0x0000006B);
				(8w105) : set_log_xq(0x0000006B);
				(8w106) : set_log_xq(0x0000006B);
				(8w107) : set_log_xq(0x0000006B);
				(8w108) : set_log_xq(0x0000006C);
				(8w109) : set_log_xq(0x0000006C);
				(8w110) : set_log_xq(0x0000006C);
				(8w111) : set_log_xq(0x0000006C);
				(8w112) : set_log_xq(0x0000006C);
				(8w113) : set_log_xq(0x0000006D);
				(8w114) : set_log_xq(0x0000006D);
				(8w115) : set_log_xq(0x0000006D);
				(8w116) : set_log_xq(0x0000006D);
				(8w117) : set_log_xq(0x0000006D);
				(8w118) : set_log_xq(0x0000006E);
				(8w119) : set_log_xq(0x0000006E);
				(8w120) : set_log_xq(0x0000006E);
				(8w121) : set_log_xq(0x0000006E);
				(8w122) : set_log_xq(0x0000006E);
				(8w123) : set_log_xq(0x0000006F);
				(8w124) : set_log_xq(0x0000006F);
				(8w125) : set_log_xq(0x0000006F);
				(8w126) : set_log_xq(0x0000006F);
				(8w127) : set_log_xq(0x0000006F);
				(8w128) : set_log_xq(0x00000070);
				(8w129) : set_log_xq(0x00000070);
				(8w130) : set_log_xq(0x00000070);
				(8w131) : set_log_xq(0x00000070);
				(8w132) : set_log_xq(0x00000070);
				(8w133) : set_log_xq(0x00000070);
				(8w134) : set_log_xq(0x00000071);
				(8w135) : set_log_xq(0x00000071);
				(8w136) : set_log_xq(0x00000071);
				(8w137) : set_log_xq(0x00000071);
				(8w138) : set_log_xq(0x00000071);
				(8w139) : set_log_xq(0x00000071);
				(8w140) : set_log_xq(0x00000072);
				(8w141) : set_log_xq(0x00000072);
				(8w142) : set_log_xq(0x00000072);
				(8w143) : set_log_xq(0x00000072);
				(8w144) : set_log_xq(0x00000072);
				(8w145) : set_log_xq(0x00000072);
				(8w146) : set_log_xq(0x00000073);
				(8w147) : set_log_xq(0x00000073);
				(8w148) : set_log_xq(0x00000073);
				(8w149) : set_log_xq(0x00000073);
				(8w150) : set_log_xq(0x00000073);
				(8w151) : set_log_xq(0x00000073);
				(8w152) : set_log_xq(0x00000073);
				(8w153) : set_log_xq(0x00000074);
				(8w154) : set_log_xq(0x00000074);
				(8w155) : set_log_xq(0x00000074);
				(8w156) : set_log_xq(0x00000074);
				(8w157) : set_log_xq(0x00000074);
				(8w158) : set_log_xq(0x00000074);
				(8w159) : set_log_xq(0x00000075);
				(8w160) : set_log_xq(0x00000075);
				(8w161) : set_log_xq(0x00000075);
				(8w162) : set_log_xq(0x00000075);
				(8w163) : set_log_xq(0x00000075);
				(8w164) : set_log_xq(0x00000075);
				(8w165) : set_log_xq(0x00000075);
				(8w166) : set_log_xq(0x00000076);
				(8w167) : set_log_xq(0x00000076);
				(8w168) : set_log_xq(0x00000076);
				(8w169) : set_log_xq(0x00000076);
				(8w170) : set_log_xq(0x00000076);
				(8w171) : set_log_xq(0x00000076);
				(8w172) : set_log_xq(0x00000076);
				(8w173) : set_log_xq(0x00000076);
				(8w174) : set_log_xq(0x00000077);
				(8w175) : set_log_xq(0x00000077);
				(8w176) : set_log_xq(0x00000077);
				(8w177) : set_log_xq(0x00000077);
				(8w178) : set_log_xq(0x00000077);
				(8w179) : set_log_xq(0x00000077);
				(8w180) : set_log_xq(0x00000077);
				(8w181) : set_log_xq(0x00000077);
				(8w182) : set_log_xq(0x00000078);
				(8w183) : set_log_xq(0x00000078);
				(8w184) : set_log_xq(0x00000078);
				(8w185) : set_log_xq(0x00000078);
				(8w186) : set_log_xq(0x00000078);
				(8w187) : set_log_xq(0x00000078);
				(8w188) : set_log_xq(0x00000078);
				(8w189) : set_log_xq(0x00000078);
				(8w190) : set_log_xq(0x00000079);
				(8w191) : set_log_xq(0x00000079);
				(8w192) : set_log_xq(0x00000079);
				(8w193) : set_log_xq(0x00000079);
				(8w194) : set_log_xq(0x00000079);
				(8w195) : set_log_xq(0x00000079);
				(8w196) : set_log_xq(0x00000079);
				(8w197) : set_log_xq(0x00000079);
				(8w198) : set_log_xq(0x0000007A);
				(8w199) : set_log_xq(0x0000007A);
				(8w200) : set_log_xq(0x0000007A);
				(8w201) : set_log_xq(0x0000007A);
				(8w202) : set_log_xq(0x0000007A);
				(8w203) : set_log_xq(0x0000007A);
				(8w204) : set_log_xq(0x0000007A);
				(8w205) : set_log_xq(0x0000007A);
				(8w206) : set_log_xq(0x0000007A);
				(8w207) : set_log_xq(0x0000007B);
				(8w208) : set_log_xq(0x0000007B);
				(8w209) : set_log_xq(0x0000007B);
				(8w210) : set_log_xq(0x0000007B);
				(8w211) : set_log_xq(0x0000007B);
				(8w212) : set_log_xq(0x0000007B);
				(8w213) : set_log_xq(0x0000007B);
				(8w214) : set_log_xq(0x0000007B);
				(8w215) : set_log_xq(0x0000007B);
				(8w216) : set_log_xq(0x0000007C);
				(8w217) : set_log_xq(0x0000007C);
				(8w218) : set_log_xq(0x0000007C);
				(8w219) : set_log_xq(0x0000007C);
				(8w220) : set_log_xq(0x0000007C);
				(8w221) : set_log_xq(0x0000007C);
				(8w222) : set_log_xq(0x0000007C);
				(8w223) : set_log_xq(0x0000007C);
				(8w224) : set_log_xq(0x0000007C);
				(8w225) : set_log_xq(0x0000007D);
				(8w226) : set_log_xq(0x0000007D);
				(8w227) : set_log_xq(0x0000007D);
				(8w228) : set_log_xq(0x0000007D);
				(8w229) : set_log_xq(0x0000007D);
				(8w230) : set_log_xq(0x0000007D);
				(8w231) : set_log_xq(0x0000007D);
				(8w232) : set_log_xq(0x0000007D);
				(8w233) : set_log_xq(0x0000007D);
				(8w234) : set_log_xq(0x0000007D);
				(8w235) : set_log_xq(0x0000007E);
				(8w236) : set_log_xq(0x0000007E);
				(8w237) : set_log_xq(0x0000007E);
				(8w238) : set_log_xq(0x0000007E);
				(8w239) : set_log_xq(0x0000007E);
				(8w240) : set_log_xq(0x0000007E);
				(8w241) : set_log_xq(0x0000007E);
				(8w242) : set_log_xq(0x0000007E);
				(8w243) : set_log_xq(0x0000007E);
				(8w244) : set_log_xq(0x0000007E);
				(8w245) : set_log_xq(0x0000007E);
				(8w246) : set_log_xq(0x0000007F);
				(8w247) : set_log_xq(0x0000007F);
				(8w248) : set_log_xq(0x0000007F);
				(8w249) : set_log_xq(0x0000007F);
				(8w250) : set_log_xq(0x0000007F);
				(8w251) : set_log_xq(0x0000007F);
				(8w252) : set_log_xq(0x0000007F);
				(8w253) : set_log_xq(0x0000007F);
				(8w254) : set_log_xq(0x0000007F);
				(8w255) : set_log_xq(0x0000007F);
			}
		}
	
	
		apply{
	            MSSB.apply();
		    set_xq();
	
		    logTable.apply();
		
		    if(l < 0x00000090){
			log_x = log_xq;
		    }
		    else{
			log_x = l - 0x00000080 + log_xq;
		    }
		}//End apply
	}
	
	
	/* --------------------------------------------------
	FUNCTION: pow2
	GOAL: 	  Compute exponential base 2
	INPUTS:   x (0:28:4 fixed-point number)
	OUTPUT:   2^x (0:28:4 fixed-point number)
	OBS.:     Output is an approximation
	-----------------------------------------------------*/
	control pow2(in bit<32> x,
		     inout bit<32> result){
	
		bit<32> tmpx = 32w0;	
		bit<32> int_part = 32w1;
		bit<32> frac_part = 0x00000010;
	
		action calc_neg_exp(bit<32> expValue){
			frac_part = expValue;
		}
	
		table negFracExp {
			key = {
				tmpx[3:0] : exact;
			}
			
			actions = {
				calc_neg_exp;
				NoAction;
			}
	
			const entries = {
				(4w1) : calc_neg_exp(0x0000000F);
				(4w2) : calc_neg_exp(0x0000000E);
				(4w3) : calc_neg_exp(0x0000000E);
				(4w4) : calc_neg_exp(0x0000000D);
				(4w5) : calc_neg_exp(0x0000000C);
				(4w6) : calc_neg_exp(0x0000000C);
				(4w7) : calc_neg_exp(0x0000000B);
				(4w8) : calc_neg_exp(0x0000000B);
				(4w9) : calc_neg_exp(0x0000000A);
				(4w10) : calc_neg_exp(0x0000000A);
				(4w11) : calc_neg_exp(0x00000009);
				(4w12) : calc_neg_exp(0x00000009);
				(4w13) : calc_neg_exp(0x00000009);
				(4w14) : calc_neg_exp(0x00000008);
				(4w15) : calc_neg_exp(0x00000008);
			}
		}
	
		action calc_pos_exp(bit<32> expValue){
			frac_part = expValue;
		}
	
		table posFracExp {
			key = {
				x[3:0] : exact;
			}
			
			actions = {
				calc_pos_exp;
				NoAction;
			}
	
			const entries = {
				(4w1) : calc_pos_exp(0x00000010);
				(4w2) : calc_pos_exp(0x00000011);
				(4w3) : calc_pos_exp(0x00000012);
				(4w4) : calc_pos_exp(0x00000013);
				(4w5) : calc_pos_exp(0x00000013);
				(4w6) : calc_pos_exp(0x00000014);
				(4w7) : calc_pos_exp(0x00000015);
				(4w8) : calc_pos_exp(0x00000016);
				(4w9) : calc_pos_exp(0x00000017);
				(4w10) : calc_pos_exp(0x00000018);
				(4w11) : calc_pos_exp(0x00000019);
				(4w12) : calc_pos_exp(0x0000001A);
				(4w13) : calc_pos_exp(0x0000001C);
				(4w14) : calc_pos_exp(0x0000001D);
				(4w15) : calc_pos_exp(0x0000001E);
			}
		}
	
	
		apply{
		    if( x == 32w0 ){
			result = 0x00000010;
		    }
		    else{
		    	if( x[31:31] == 1w1 ){
				//Negative exponent
			int_part = 32w0x00000010;
				tmpx = (~x) + 1;
	
				//Compute integer part of exponent. Must do RIGHT shifts.
				int_part = int_part >> tmpx[11:4];
	
				if( tmpx[3:0] != 4w0 ){
				    //Compute fractional part
	                	    negFracExp.apply();
	               		}
	
				//TODO: add overflow checks
				result = int_part * frac_part;
				result = result >> 4;
		    	}
	            	else{
				//Positive exponent
	
				//Compute integer part of exponent. Must do LEFT shifts.
				int_part = int_part << x[11:4];
	
	                	if( x[3:0] != 4w0 ){
				    //Compute fractional part
	                	    posFracExp.apply();
	                	}
		
				//TODO: add overflow checks
				result = int_part * frac_part;
	            	}
	
			
		    }
	
		}//End apply
	}
	
	
	/* --------------------------------------------------
	FUNCTION: div
	GOAL: 	  Divide two values
	INPUTS:   A (32-bit integer)
		  B (32-bit integer)
	OUTPUT:   A/B (0:28:4 fixed-point number)
	OBS.:     Output is an approximation
	-----------------------------------------------------*/
	control div(in bit<32> A, 
		    in bit<32> B,
		    inout bit<32> result){
	
		log2() logA;
		log2() logB;
		pow2() pow;
	
		bit<32> tmp = 32w0;
		bit<32> logAA = 32w0;
		bit<32> logBB = 32w0;
	
		apply{
			logA.apply(A, logAA);
			logB.apply(B, logBB);
	        	tmp = logAA-logBB;
			pow.apply(tmp, result);
		}
	}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {


   register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) bloom_filter;
   bit<32> filter_address;
   bit<1> filter_value;  
   
   register<bit<32>>(3) gray_reg;
   bit<32> low_gray;
   bit<32> mid_gray;
   bit<32> high_gray;
   bit<32> low_ratio=32w0;
   bit<32> mid_ratio=32w0;
   bit<32> high_ratio=32w0; 


   register<bit<32>>(1) count_reg;
   bit<32>count;
   bit<32> gray_pixel=32w0;
   
    register<bit<32>>(2) gray_maxmin;
    bit<32> min_gray;
    bit<32> max_gray;
    bit<32> contrast;   

		   
    div() DivLowGray;
    div() DivMidGray;
    div() DivHighGray;
    div() DivContrast;
    mul() MulTest;
    mul() MulRed;
    mul() MulGreen;
    mul() MulBlue;
    
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


	    //formula is gray=0.299*red + 0.587*green +0.114*blue
	   bit<32> red_C=(bit<32>)hdr.colors.red << 4;
	   bit<32> green_C=(bit<32>)hdr.colors.green << 4;
	   bit<32> blue_C=(bit<32>)hdr.colors.blue << 4;
          

	    bit<32> red_M=32w6; //approx 0.299
	    bit<32> green_M=32w9; //approx 0.587
            bit<32> blue_M=32w2; //approx 0.114
	    bit<32> coeff_result=32w0;

	    MulRed.apply(red_M,red_C,coeff_result);
	    gray_pixel=gray_pixel+coeff_result;
	    MulGreen.apply(green_M,green_C,coeff_result);						//using color information to convert to grayscale value
	    gray_pixel=gray_pixel+coeff_result;
	    MulBlue.apply(blue_M,blue_C,coeff_result);
	    gray_pixel=gray_pixel+coeff_result;

	    bit<4> floating=gray_pixel[3:0];
	    gray_pixel=gray_pixel >> 4;
	    if (floating >= 8) {
		gray_pixel=gray_pixel+1;
	    }
	    if (gray_pixel > 255) gray_pixel = 32w255;
	

	    
	    //read value from register, store in count
	    count_reg.read(count,0);
	    gray_reg.read(low_gray,0);
	    gray_reg.read(mid_gray,1);
	    gray_reg.read(high_gray,2);
	    gray_maxmin.read(min_gray,0);
	    gray_maxmin.read(max_gray,1);

	    if (min_gray==0) min_gray=99999;
	    if (gray_pixel > max_gray) max_gray=gray_pixel;						//for finding maximum and minimum intensity for contrast calculation
	    if (gray_pixel < min_gray && gray_pixel!=0) min_gray=gray_pixel;


	    compute_hashes(hdr.colors.red,hdr.colors.green,hdr.colors.blue);

	    //read the bloom filter value at that hashed address
	    bloom_filter.read(filter_value,filter_address);

	    //if its 0, that means its a new color, increment counter
	    if (hdr.udp.srcPort!=10000) {
		    if ( gray_pixel < 85 ) {
		        	low_gray = low_gray + 1;
	            }
		   else if ( gray_pixel < 170  ) {
		   	mid_gray = mid_gray + 1;
	            }
		   else if (gray_pixel < 256)  {
		   	high_gray = high_gray + 1;
                    }
	            if (filter_value==0 ) {
			    count=count+1;
		    }
	    }
	    else {
		bit<32> total_pixel=hdr.counts.sequence;
		DivLowGray.apply(low_gray,total_pixel,low_ratio);
		DivMidGray.apply(mid_gray,total_pixel,mid_ratio);
		DivHighGray.apply(high_gray,total_pixel,high_ratio);
		hdr.counts.low_ratio=low_ratio;
		hdr.counts.mid_ratio=mid_ratio;
		hdr.counts.high_ratio=high_ratio;

		//Contrast
		bit<32> contrast_num=max_gray-min_gray;
		contrast_num=contrast_num <<4;
		bit<32> contrast_den=max_gray+min_gray;
		contrast_den=contrast_den <<4;
		DivContrast.apply(contrast_num,contrast_den,contrast);
		hdr.counts.sequence=contrast;
		
		
	    }

	    //if its new color, set the value as 1. If its old, the value is 1 anyways
	    bloom_filter.write(filter_address,1);

	    //write the counter value to register
	    count_reg.write(0,count);
	    gray_reg.write(0,low_gray);
	    gray_reg.write(1,mid_gray);
	    gray_reg.write(2,high_gray);
	    gray_maxmin.write(0,min_gray);
	    gray_maxmin.write(1,max_gray);
	
	    //store the value in the dstPort. (this is just a placeholder for testing, we can store it in another part of the packet later)
	    hdr.counts.number=count;
	    hdr.counts.low_gray=low_gray;
	    hdr.counts.mid_gray=mid_gray;
	    hdr.counts.high_gray=high_gray;

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
