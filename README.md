# CSC361 Assignment 3 - TraceRoute Analyzer

## Overview
TraceRoute Analyzer is a Python-based network analysis tool designed to parse and analyze PCAP (Packet Capture) 
files. It extracts essential details from network packets, including IP addresses, protocol information, and 
calculates Round-Trip Times (RTTs) for intermediate nodes. This tool is particularly useful for network diagnostics 
and research.

## Requirements
- Python 3.x
- PCAP file for analysis

## Features
1. Global Header Parsing: Reads and parses the global header of a PCAP file.
2. Packet Header Parsing: Extracts and interprets information from packet headers.
3. IPV4 Header Parsing: Analyzes IPv4 headers for IP addresses, protocol types, and other details.
4. UDP and ICMP Header Parsing: Processes UDP and ICMP headers, extracting relevant information like ports and sequence numbers.
5. Protocol Analysis: Checks the IP header of all datagrams in the trace file and lists the set of values in the protocol field.
6. Fragmentation Analysis: Determines how many fragments were created from the original datagram and the offset of the last fragment.
7. Advanced RTT Calculations: Calculates average and standard deviation of RTTs between the source node and intermediate/ultimate destination nodes.
8. Output: Prints source and destination IP addresses, intermediate nodes, protocol information, packet fragments, and RTT values.

## Installation and Execution
1. Ensure Python 3.x is installed on your system.
2. Place the `TraceRouteAnalyzer.py` file in a desired directory.
3. Use a terminal or command prompt to navigate to the directory.
4. Run the script using Python and provide a PCAP file as an argument.

## Output Format
- Lists IP addresses of source and ultimate destination nodes.
- Displays IP addresses of intermediate nodes in order of hop count.
- Shows values in the protocol field of IP headers.
- Indicates the number of fragments and the offset of the last fragment.
- Provides average RTT and standard deviation for each node.

## Usage
- To utilize the TraceRoute Analyzer, you need to provide a single argument, which is the file path to a PCAP file. Follow these steps 
  to run the script from your terminal:

    ```bash
    python3 TraceRouteAnalyzer.py <sample_trace_file.cap>

## Limitations
- Supports only IPv4, ICMP, and UDP protocols.
- May not handle corrupted or malformed PCAP files effectively.
- RTT calculation accuracy depends on input data quality.
