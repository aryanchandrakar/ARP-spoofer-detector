#!/usr/bin/env/python

# watching arp tables the change of mac but it wont work if the attack is already going from long time
# we go by working of arp op, hwdst, psrc
# we check if source ip is ip of router by sniffing

import scapy.all as scapy
#for http packets


# RUN ARP SPOOFER FOR EXTERNAL WIFI NETWORK ATTACKS !!!!

def get_mac(ip):
    # dicovering client thru mac request who has which mac
    arp_request=scapy.ARP(pdst=ip)
    # the mac of the address we arp request ff:ff:ff....
    broadcast= scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast= broadcast/arp_request
    # to get the field that can be edited
    answerlist=scapy.srp(arp_request_broadcast, timeout=40, verbose=False)[0]
    return answerlist[0][1].hwsrc

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op==2:
        # check for arp layer and is it of type "is at", relation between mac and ip
        try:
            real_mac=get_mac(packet[scapy.ARP].psrc)
            response_mac=packet[scapy.ARP].hwsrc
            if real_mac != response_mac:
                print("[~] you are under attack")
            # print(packet.show())
        except IndexError:
            pass

sniff("wlan0")