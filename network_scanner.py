# !/usr/bin/env python

import scapy.all as scapy
import optparse


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        clients_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(clients_dict)

    return clients_list


def print_result(results_list):
    print("IP\t\t\tMAC Address\n---------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="ip", help="Give ip address or range")

    (options, argumenats) = parser.parse_args()

    if not options.ip:
        parser.error("[-] Please specify an IP ,use --help for more info.")

    return options


options = get_arguments()
scan_results = scan(options.ip)
print_result(scan_results)
