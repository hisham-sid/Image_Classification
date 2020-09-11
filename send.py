#!/usr/bin/env python3
import argparse
import sys
import socket
import random
import struct

#Pillow for image processing
from PIL import Image
from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP

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
    for j in range(h):
        for i in range(w):

            #get the RGB tuple at each pixel
            pixel=rgb_image.getpixel((i,j))

	    #map the pixel int values to strings, then join them with a space delimiter
            the_string=' '.join(map(str,pixel))

	    #include the string as the payload of the packet, send it to the destination
            pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
            pkt = pkt /IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / the_string
            pkt.show2()
            sendp(pkt, iface=iface, verbose=False)
	
if __name__ == '__main__':
    main()
