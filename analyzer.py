
from scapy.all import rdpcap, IP, TCP, UDP


def analyze_pcap(file_path):
    """
    Analyze a real PCAP or PCAPNG file.
    """

    packets = rdpcap(file_path)

    results = []

    suspicious_ports = [21, 22, 23, 3389]

    for packet in packets:

        if IP not in packet:
            continue

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        protocol = "Other"

        source_port = "-"
        destination_port = "-"

        if TCP in packet:

            protocol = "TCP"

            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        elif UDP in packet:

            protocol = "UDP"

            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        alert = False
        alert_message = ""

        if destination_port in suspicious_ports:

            alert = True

            alert_message = (
                f"Connection to suspicious port "
                f"{destination_port}"
            )

        results.append({

            "source_ip": source_ip,

            "destination_ip": destination_ip,

            "protocol": protocol,

            "source_port": source_port,

            "destination_port": destination_port,

            "alert": alert,

            "alert_message": alert_message

        })

    return results


def analyze_traffic(packet_count=20):
    """
    Generate sample traffic for the dashboard demo.

    This is used when no PCAP file has been uploaded.
    """

    sample_packets = [

        {
            "source_ip": "192.168.1.10",
            "destination_ip": "142.250.72.14",
            "protocol": "TCP",
            "source_port": 52341,
            "destination_port": 443
        },

        {
            "source_ip": "192.168.1.10",
            "destination_ip": "8.8.8.8",
            "protocol": "UDP",
            "source_port": 53122,
            "destination_port": 53
        },

        {
            "source_ip": "192.168.1.10",
            "destination_ip": "192.168.1.1",
            "protocol": "TCP",
            "source_port": 52110,
            "destination_port": 80
        },

        {
            "source_ip": "192.168.1.15",
            "destination_ip": "172.217.164.110",
            "protocol": "TCP",
            "source_port": 51422,
            "destination_port": 443
        },

        {
            "source_ip": "192.168.1.10",
            "destination_ip": "1.1.1.1",
            "protocol": "UDP",
            "source_port": 54821,
            "destination_port": 53
        },

        {
            "source_ip": "192.168.1.20",
            "destination_ip": "192.168.1.1",
            "protocol": "TCP",
            "source_port": 49821,
            "destination_port": 80
        },

        {
            "source_ip": "192.168.1.10",
            "destination_ip": "104.18.32.47",
            "protocol": "TCP",
            "source_port": 52388,
            "destination_port": 443
        },

        {
            "source_ip": "192.168.1.15",
            "destination_ip": "8.8.4.4",
            "protocol": "UDP",
            "source_port": 53211,
            "destination_port": 53
        },

        {
            "source_ip": "192.168.1.10",
            "destination_ip": "192.168.1.1",
            "protocol": "TCP",
            "source_port": 50120,
            "destination_port": 22
        },

        {
            "source_ip": "192.168.1.20",
            "destination_ip": "142.250.72.14",
            "protocol": "TCP",
            "source_port": 51234,
            "destination_port": 443
        }

    ]

    results = []

    suspicious_ports = [21, 22, 23, 3389]

    for packet in sample_packets[:packet_count]:

        alert = False
        alert_message = ""

        if packet["destination_port"] in suspicious_ports:

            alert = True

            alert_message = (
                f"Connection to suspicious port "
                f"{packet['destination_port']}"
            )

        packet["alert"] = alert

        packet["alert_message"] = alert_message

        results.append(packet)

    return results

