#! /usr/bin/python3
from scapy.all import *
import sys
import random
import argparse
from Helper import convert_gre_tun_to_ip_batch_online,convert_sll_to_ether_batch_online

"""
NOTE 
    This script assumes that there is only 1 TCP stream in the PCAP file and that 
    you wish to replay the role of the client

"""
##################### Scapy initial configuration ####################################
# setting the configs required for scapy to work. (https://scapy.readthedocs.io/en/latest/troubleshooting.html)
conf.L3socket = L3RawSocket
conf.verbose = 3


##################### Global command line variables ##################################

pcap_file_path = ""
iface = ""
src_port = -1
dst_port = -1
#acks
ACK = 0x10
#client closing the connection
RSTACK = 0x14
src_ip = "127.0.0.1"
src_mac = "00:00:00:00:00:00"

dest_ip = "127.0.0.1"
gateway = "00:00:00:00:00:00" 



##################### Getting the TCP payload length, for ack no. calculation #####################
def get_tcp_payload_length(p):
    if str(p[TCP].flags) == "SA":
        return 1
    ip_total_len = p.getlayer(IP).len
    ip_header_len = p.getlayer(IP).ihl * 32 // 8
    tcp_header_len = p.getlayer(TCP).dataofs * 32 // 8
    return ip_total_len - ip_header_len - tcp_header_len

###################### Sending and sniffing the packet on interface ######################
def sendpacket(list_packets, inface):
    rcv, _ = sr(list_packets, iface = inface, multi =  True, timeout = 5)
    recvSeqNum = -1
    payload_len = -1
    if rcv:
        print("[*] Printing the received packet", rcv)
        for idx in range(len(rcv)):
            received_packet = cast(Packet, rcv[idx][1])
            received_packet.show()
            if 'TCP' in received_packet:
                if received_packet[TCP].seq >= 0:
                    recvSeqNum = received_packet[TCP].seq
                    payload_len = get_tcp_payload_length(received_packet)
    return recvSeqNum, payload_len

def replay(infile, inface):
    ############ Initialization of the variables ################################
    recvSeqNum = 0    
    payload_len = 0
    list_packets = []    
    i = 0
    lst_packet = []
    ########### Checking the layers and applying the transformations ###################

    lst_packet_from_file = rdpcap(infile)
    if lst_packet_from_file[0].haslayer(GRE):
        lst_packet = convert_gre_tun_to_ip_batch_online(lst_packet_from_file)
    else:
        lst_packet = lst_packet_from_file

    if lst_packet[0].haslayer(CookedLinux):
        lst_packet = convert_sll_to_ether_batch_online(lst_packet)
    else:
        lst_packet = lst_packet

    #################  Replaying th packet on the interface ############################
    for p in lst_packet:
        if 'IP' in p and 'TCP' in p:
            eth = p[Ether]
            ip = p[IP]            
            tcp = p[TCP]

            ## modifying the quad ## 

            ip.src = src_ip
            eth.src = src_mac
            ip.dst = dest_ip
            eth.dst = gateway
            tcp.sport = src_port

            ### filtering packets to destination process ###
            if tcp.dport == dst_port:                
                if (tcp.flags & ACK) or (tcp.flags == RSTACK):
                    tcp.ack = recvSeqNum + payload_len
                    print("[+] tcp number in sync..")
                del ip.chksum
                del tcp.chksum
                if tcp.flags & ACK:
                    print("[+] tcp acks", tcp.ack)
                # recraft the packet for sending it on loopback interface.
                modified_ip_packet = IP(p[IP].__bytes__()[0:p[IP].len])    # scrape the ethernet trailer 
                list_packets.append(modified_ip_packet)
                continue
            else:               
                i += len(list_packets)            
                print("[+] Sending", i, "th Packet")
                r, pl = sendpacket(list_packets, inface)
                if r != -1:
                    recvSeqNum = r
                if pl != -1:
                    payload_len = pl
                list_packets = []

    if len(list_packets) != 0:
        i += len(list_packets)
        print("[+] sending", i, "Packet")
        r, pl = sendpacket(list_packets, inface)
            

def printUsage(prog):
    print("%s <pcapPath> <interface>" % prog)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = "tcpliveplay python script")
    parser.add_argument("-f", "--pcap", required = True, help = "path to pcap file")
    parser.add_argument("-i", "--iface", required = True, help = "interface")
    parser.add_argument("-s", "--src", required = True, help = "source IP")
    parser.add_argument("-d", "--dst", required = True, help = "destination IP")
    parser.add_argument("--sport", type = int ,required=False, default = -1, help="source port as client")
    parser.add_argument("--dport", type = int ,required=True, help = "destination port of tcp process")
    args = vars(parser.parse_args())
    pcap_file_path = args['pcap']
    iface = args['iface']
    src_ip = args['src']
    dest_ip = args['dst']
    if args['sport'] != -1:
        src_port = args['sport']
    else:
        src_port = 17079            #TODO: add random port choosing logic
    dst_port = args['dport']
    replay(pcap_file_path,iface)
