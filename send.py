#!/usr/bin/env python3
import argparse
import sys
import socket
import random
import struct

#Pillow for image processing
from PIL import Image
from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import *

class Colors(Packet):
    name = "Colors "
    fields_desc=[ XByteField("red",0),
                 XByteField("green",0),
                 XByteField("blue",0) ]

class Counts(Packet):
    name="Counts"
    fields_desc=[ BitField("number",0,32),
                 BitField("low_gray",0,32),
                 BitField("mid_gray",0,32),
                 BitField("high_gray",0,32),
                 BitField("table_val",0,32),
                 BitField("contrast",0,32),
                 BitField("max",0,32),
                 BitField("min",0,32) ]

#getting the interface from the interface list
def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():

   #ensuring two arguments are required
    if len(sys.argv)<3:
        print ('pass 2 arguments: <destination> "<image>"')
        exit(1)

    #acquire the MAC address of destination and interface
    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    print("sending on interface %s to %s" % (iface, str(addr)))

    #load the image provided in the argument, convert to RGB color pallette and extract dimensions
    image=Image.open(sys.argv[2])
    rgb_image=image.convert("RGB")
    w,h=rgb_image.size

    #iterate every pixel primarily by row and then column
    #pktstart =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    #pktstart= pktstart /IP(dst=addr) / UDP(dport=random.randint(10000,60000), sport=1) 
    #pktstart.show()
    for j in range(h):
        for i in range(w):

            #get the RGB tuple at each pixel
            pixel=rgb_image.getpixel((i,j))

	    #retrieve the integer values of the R,G and B colors
            redC,greenC,blueC=pixel

	    #include the color values as a custom header named Colors, send it to the destination
            pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
            pkt = pkt /IP(dst=addr) / UDP(dport=random.randint(10000,60000), sport=random.randint(10001,60000))/Colors(red=redC,green=greenC,blue=blueC)/Counts(number=random.randint(1,200))
            pkt.show()
            sendp(pkt, iface=iface, verbose=False)
	
    pkt2 =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt2= pkt2 /IP(dst=addr) / UDP(dport=random.randint(10000,60000), sport=10000)/Colors()/Counts(number=random.randint(1,3))  
    pkt2.show()
    sendp(pkt2, iface=iface, verbose=False)
if __name__ == '__main__':
    main()
