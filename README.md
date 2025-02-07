# Packet Analyzer

Packet analyzer for '.pcap' format files generated by Wireshark.

## 1- How to compile and run your code

### Environment setting

Use `requirements.txt` to install necessary packages:

```
pip install -r requirements.txt
```

### Running main code

The main script `pktsniffer.py` will analyze your `.pcap` file:

```
pktsniffer -r yourfile.pcap
```

## 2- Examples of command-line usage

### To show fewer packets

To limit number of packets to show, use `-c` option:

```
pktsniffer -r yourfile.pcap -c 5
```

### Other filters

`pktsniffer.py` also supports `host`, `port`, `ip`, `tcp`, `udp`, `icmp`, `-net` flags to filter packets.
For example:

```
pktsniffer -r file.pcap host 192.168.0.1
pktsniffer -r file.pcap port 80
pktsniffer -r file.pcap -net 192.168.1.0
```

`-net` filters packets based on a network address. For example, pktsniffer -r file.pcap -net 192.168.1.0 will display all packets where either the source or destination IP belongs to the 192.168.1.x network.
