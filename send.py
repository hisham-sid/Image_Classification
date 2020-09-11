#!/usr/bin/env python3
import argparse
import sys
import socket
import random
import struct
import numpy as np

from PIL import Image
from scipy.ndimage import zoom
from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP

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

    if len(sys.argv)<3:
        print ('pass 2 arguments: <destination> "<image>"')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    print("sending on interface %s to %s" % (iface, str(addr)))

    image=Image.open(sys.argv[2])
    w,h=image.size
    print(w)
    print(h)
    for j in range(h):
        for i in range(w):
            rgb_image=image.convert("RGB")
            pixel=rgb_image.getpixel((i,j))
            the_string=' '.join(map(str,pixel))
            print(the_string)
            pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
            pkt = pkt /IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / the_string
            pkt.show2()
            sendp(pkt, iface=iface, verbose=False)
	
if __name__ == '__main__':
    main()
