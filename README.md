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


## usage
```bash
./tcp-exec.py -f <path_to_pcap_file> -i <interface> -s source_ip -d destination_ip --sport=<source_port>
```

## help menu
```bash
./tcp-exec.py -h

usage: tcp-exec.py [-h] -f PCAP -i IFACE -s SRC -d DST [--sport SPORT]

tcpliveplay python script

optional arguments:
  -h, --help            show this help message and exit
  -f PCAP, --pcap PCAP  path to pcap file
  -i IFACE, --iface IFACE
                        interface
  -s SRC, --src SRC     source IP
  -d DST, --dst DST     destination IP
  --sport SPORT         source port as client
```

## Examples
```bash
./tcpexec.py -f /path/to/file.pcap -i lo -s 127.0.0.1 -d 127.0.0.1 --sport=9002
```

The above example will play the tcp packets between 127.0.0.1:9002(us) and 127.0.0.1:4189(server). Obviously some process must be in listen mode at port 4189 to accept the packet and send us the acknowledgment.