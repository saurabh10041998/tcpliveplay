# Tcpliveplay python script
This script is used to simulate tcp connections from the captured tcp traffic on the live network


## Why to rewrite this python version of tcpliveplay.c from tcpreplay
- well, tcpliveplay.c is no longer updated since 4 jul 2020
- **It(tcpliveplay.c) does not even complete the tcp handshake**
- no facility for the rewriting packet. Need to use the tcprewrite and then feed to tcpliveplay
- need to enable flags for CRC, IP and TCP checksum recomputation
- I want something simple pythonic proof of concept for tcp
- no facility to see the responce for the packets

## Project dependencies
- python 3
- scapy


## What a noobish python implemetation
Yes probably you are right, I am not pro.. Show me how to do it better. A nice pull request might cheer me up :)

## usage
```bash
./tcp-exec.py -f <path_to_pcap_file> -i <interface> -s source_ip -d destination_ip --sport=<source_port> --dport=<destination_port>
```

## help menu
```bash
./tcp-exec.py -h

usage: tcp-exec.py [-h] -f PCAP -i IFACE -s SRC -d DST [--sport SPORT] --dport DPORT

tcpliveplay python script

optional arguments:
  -h, --help            show this help message and exit
  -f PCAP, --pcap PCAP  path to pcap file
  -i IFACE, --iface IFACE
                        interface
  -s SRC, --src SRC     source IP
  -d DST, --dst DST     destination IP
  --sport SPORT         source port as client
  --dport DPORT         destination port of tcp process
```

## Examples
```bash
./tcpexec.py -f /path/to/file.pcap -i lo -s 127.0.0.1 -d 127.0.0.1 --sport=9002 --dport=4189
```

The above example will play the tcp packets between 127.0.0.1:9002(us) and 127.0.0.1:4189(server). Obviously some process must be in listen mode at port 4189 to accept the packet and send us the acknowledgment.

## Tasks to be established

- [x] Replaying the single tcp stream on interface
- [x] Adding destination port as command line argument 
- [ ] Smart selection of the interface based on the source IP
- [ ] Smart selection between whether to use layer 2 routing or layer 3 routing
- [ ] Grabbing mac and ip of interface 
- [ ] if layer 2 routing used, calculate the next hop mac
- [ ] can we simulate multiple TCP stream ??