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
    fields_desc=[ XByteField("red1",0),
                 XByteField("green1",0),
                 XByteField("blue1",0),
                 XByteField("red2",0),
                 XByteField("green2",0),
                 XByteField("blue2",0),
                 XByteField("red3",0),
                 XByteField("green3",0),
                 XByteField("blue3",0),
                 XByteField("red4",0),
                 XByteField("green4",0),
                 XByteField("blue4",0),]

class Counts(Packet):
    name="Counts"
    fields_desc=[ BitField("number",0,32),
                 BitField("low_gray",0,32),
                 BitField("mid_gray",0,32),
                 BitField("high_gray",0,32),
                 BitField("sequence",0,32),
                 BitField("low_ratio",0,32),
                 BitField("mid_ratio",0,32),
                 BitField("high_ratio",0,32) ]

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

    sqn=0;

    s = conf.L2socket(iface=iface)

    #iterate every pixel primarily by row and then column
    for j in range(0,h,2):
        for i in range(0,w,2):

            #get the RGB tuple at each pixel
            pixel1=rgb_image.getpixel((i,j))
            pixel2=rgb_image.getpixel((i+1,j))
            pixel3=rgb_image.getpixel((i,j+1))
            pixel4=rgb_image.getpixel((i+1,j+1))

	    #retrieve the integer values of the R,G and B colors
            redC1,greenC1,blueC1=pixel1
            redC2,greenC2,blueC2=pixel2
            redC3,greenC3,blueC3=pixel3
            redC4,greenC4,blueC4=pixel4

	    #include the color values as a custom header named Colors, send it to the destination
            pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
            pkt = pkt /IP(dst=addr) / UDP(dport=random.randint(10000,60000), sport=random.randint(10001,60000))/Colors(red1=redC1,green1=greenC1,blue1=blueC1,red2=redC2,green2=greenC2,blue2=blueC2,red3=redC3,green3=greenC3,blue3=blueC3,red4=redC4,green4=greenC4,blue4=blueC4)/Counts(sequence=sqn)
            pkt.show()
            sqn=sqn+1
            s.send(pkt)
	
    pkt2 =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt2= pkt2 /IP(dst=addr) / UDP(dport=random.randint(10000,60000), sport=10000)/Colors()/Counts(sequence=sqn)  
    pkt2.show()
    sendp(pkt2, iface=iface, verbose=False)
if __name__ == '__main__':
    main()
