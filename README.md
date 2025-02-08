# Packet Analyzer

Packet analyzer for '.pcap' format files generated by Wireshark.

## 1- How to compile and run your code

### Clone repository

```
git clone https://github.com/50516021/Packet_sniffer
```

### Environment setting

Use `requirements.txt` to install necessary packages:

```
pip install -r requirements.txt
```

### Running main code

The main script `pktsniffer.py` will analyze your `.pcap` file
(replace `<python>` depending your python environment):

```
<python> pktsniffer -r yourfile.pcap
```

## 2- Examples of command-line usage

### To limit packets to show

To limit number of packets to show, use `-c` option:

```
<python> pktsniffer -r yourfile.pcap -c 5
```

### Address & Port filters

`--net` filters packets based on a network address. For example, pktsniffer -r file.pcap -net 192.168.1.0 will display all packets where either the source or destination IP belongs to the 192.168.1.x network (treat last 0 as a wildcard):

```
<python> pktsniffer -r yourfile.pcap -net 192.168.1.0
```

`--host` filters packets based on a host network address:

```
<python> pktsniffer -r yourfile.pcap --host 192.168.0.1
```

`--port` filters packets based on a source/destination port number. This will be applied both TCP and UDP protocols:

```
<python> pktsniffer -r yourfile.pcap --host 192.168.0.1
```

### Protocol filter

`--ip` filters packets based on protocol type (TCP, UDP, ICMP):

```
<python> pktsniffer -r yourfile.pcap --ip tcp
<python> pktsniffer -r yourfile.pcap --ip udp
<python> pktsniffer -r yourfile.pcap --ip icmp
```

You can also use abbreviations:

```
<python> pktsniffer -r yourfile.pcap --tcp
<python> pktsniffer -r yourfile.pcap --udp
<python> pktsniffer -r yourfile.pcap --icmp
```
