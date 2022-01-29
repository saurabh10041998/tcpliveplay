from scapy.all import *


def convert_sll_to_ether(pkt, smac = "ff:ff:ff:ff:ff:ff", dmac = "ff:ff:ff:ff:ff:ff"):
	ip_layer_packet = pkt.getlayer(IP)
	ether_layer_packet = Ether(src = smac, dst = dmac)
	return ether_layer_packet/ip_layer_packet


def convert_sll_to_ether_batch_online(pkt_lst):
	modified_pkt_lst = []
	for p in pkt_lst:
		ether_packet = convert_sll_to_ether(p)
		modified_pkt_lst.append(ether_packet)
	return modified_pkt_lst



def convert_sll_to_ether_batch_offline(pkt_lst,outfile =  "modified_sll_to_ether.pcap"):
	modified_pkt_lst = convert_sll_to_ether_batch_online(pkt_lst)
	wrpcap(outfile, modified_pkt_lst)



# *****************************************************************

		# GRE to Normal IP packet converter

# *****************************************************************


def convert_gre_tun_to_ip(pkt):
	ether_layer_packet = pkt[Ether].copy()			# create the deep copy of packet
	ether_layer_packet.remove_payload()
	return ether_layer_packet / pkt[IP][2]

def convert_gre_tun_to_ip_batch_online(pkt_lst):
	modified_pkt_lst = []
	for p in pkt_lst:
		modified_pkt = convert_gre_tun_to_ip(p)
		modified_pkt_lst.append(modified_pkt)
	return modified_pkt_lst