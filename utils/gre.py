from scapy.all import *

# *****************************************************************

# GRE to Normal IP packet converter

# *****************************************************************


def convert_gre_tun_to_ip(pkt):
    ether_layer_packet = pkt[Ether].copy()  # create the deep copy of packet
    ether_layer_packet.remove_payload()
    return ether_layer_packet / pkt[IP][2]


def convert_gre_tun_to_ip_batch_online(pkt_lst):
    modified_pkt_lst = []
    for p in pkt_lst:
        modified_pkt = convert_gre_tun_to_ip(p)
        modified_pkt_lst.append(modified_pkt)
    return modified_pkt_lst
