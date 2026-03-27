# Basic Network Sniffer

This project is a Python-based network packet sniffer developed using Scapy.
It captures live network traffic and displays useful packet information such as IP addresses, protocol, ports, and payload.

## Features

* Capture live network packets
* Display source IP and destination IP
* Detect protocol (TCP, UDP, ICMP)
* Show source and destination ports
* Display timestamp
* Extract packet payload (hex format)
* Packet counter
* Save captured packets to capture_log.txt

## Requirements

Python 3.x
Scapy library

Install dependency:
pip install scapy

## How to Run

Run the script as administrator:

python basic_network_sniffer.py

Press CTRL + C to stop capturing packets.

## Example Output

Packet #1
Protocol: TCP
Source IP: 192.168.1.6
Destination IP: 20.189.173.1
Source Port: 20504
Destination Port: 443

## Project Purpose

This project was created as part of CodeAlpha Cyber Security Internship Task 1.

## Author

Ritej Gupta
Cybersecurity Intern
GitHub: https://github.com/ritej9215
