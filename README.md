# CNIP Project – Network Traffic Monitoring System

## 1. Project Overview
The Network Traffic Monitoring System is a Computer Networks and Internet Protocols (CNIP) project developed using Python. It monitors network traffic and displays information about packets transmitted across a network.

## 2. Objectives
- To monitor network traffic in real time.
- To capture and display network packet information.
- To identify source and destination IP addresses.
- To identify packet protocols such as TCP and UDP.
- To understand how data packets travel through a network.

## 3. Technologies Used
- **Programming Language:** Python
- **Libraries:** Scapy (if used in the project)
- **Interface:** Command-Line Interface (CLI) and/or Graphical User Interface (GUI)
- **Platform:** Windows
- **Version Control:** Git and GitHub

## 4. Features
- Real-time network packet monitoring.
- Displays source and destination IP addresses.
- Identifies network protocols.
- Shows packet counts and traffic information.
- Provides a graphical dashboard if included in the project.

## 5. Project Structure
```text
CNIP-Project/
├── monitor.py
├── dashboard.py
└── README.md
```

*Note: Update the file names above to match the actual files in your repository.*

## 6. Requirements
- Python installed on the system.
- Required Python libraries installed.
- Network connection.
- Administrator privileges may be required for packet capture on Windows.

## 7. How to Run the Project
1. Download or clone this repository.
2. Open Command Prompt in the project folder.
3. Install the required libraries according to the project code.
4. Run the monitoring program:

```bash
python monitor.py
```

5. If the project includes a separate dashboard, run it using the appropriate command, for example:

```bash
python dashboard.py
```

*Run the dashboard command only if the file is designed to start independently.*

## 8. Expected Output
The system displays network packet information, including:
- Packet number
- Source IP address
- Destination IP address
- Protocol type

Example:

```text
NETWORK TRAFFIC MONITOR
Monitoring packets...

Packet: 1 | Source: 192.168.1.10 | Destination: 192.168.1.20 | Protocol: TCP
Packet: 2 | Source: 192.168.1.20 | Destination: 192.168.1.10 | Protocol: UDP
```

*The IP addresses above are illustrative examples.*

## 9. Applications
- Learning computer networking concepts.
- Understanding TCP/IP communication.
- Observing network packet transmission.
- Demonstrating basic network monitoring concepts.

## 10. Limitations
- Packet visibility depends on network configuration and capture permissions.
- Encrypted network traffic content may not be readable.
- The project is intended for educational purposes and is not a complete enterprise-grade network security solution.

## 11. Future Enh
