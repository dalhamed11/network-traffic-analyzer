# Network Traffic Analyzer

A Python-based network traffic analyzer for cybersecurity learning.

## Overview

Network Traffic Analyzer is a lightweight cybersecurity tool built with Python and Flask.

The project allows users to upload PCAP and PCAPNG files, analyze network packets, inspect IP addresses and ports, and identify potentially suspicious network activity.

## Features

* Upload PCAP and PCAPNG files
* Analyze network packets using Scapy
* Display source and destination IP addresses
* Detect TCP and UDP traffic
* Identify source and destination ports
* Detect connections to suspicious ports
* Display security alerts
* Interactive web dashboard
* Sample traffic analysis for demonstration

## Technologies

* Python
* Flask
* Scapy
* HTML
* CSS
* JavaScript

## Project Structure

```text
network-traffic-analyzer/
│
├── analyzer.py
├── app.py
├── requirements.txt
├── README.md
│
├── uploads/
│
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── script.js
│
└── templates/
    └── index.html
```

## How It Works

1. The user uploads a PCAP or PCAPNG file.
2. Flask receives the uploaded file.
3. Scapy reads and analyzes the captured packets.
4. The application extracts IP addresses, protocols, and ports.
5. The analyzer checks for connections to predefined suspicious ports.
6. Results are displayed through the web dashboard.

## Security Detection

The current version identifies connections to commonly monitored ports:

* FTP - 21
* SSH - 22
* Telnet - 23
* RDP - 3389

These ports are flagged as potentially suspicious for learning and monitoring purposes.

## Installation

Clone the repository:

```bash
git clone https://github.com/dalhamed11/network-traffic-analyzer.git
```

Move into the project directory:

```bash
cd network-traffic-analyzer
```

Install the required packages:

```bash
pip install -r requirements.txt
```

Run the application:

```bash
flask --app app run --port 5001 --debug
```

Then open the application in your browser.

## Limitations

Live packet capture may not be available in restricted environments such as GitHub Codespaces because raw network packet capture requires additional system permissions.

For this reason, the project supports PCAP file analysis and includes sample traffic for demonstration.

## Future Improvements

* Advanced threat detection
* IP address reputation checks
* Traffic filtering and search
* Protocol statistics
* Traffic visualization
* Export analysis reports
* More sophisticated anomaly detection

## Author

Danah Alhamed

GitHub: [dalhamed11](https://github.com/dalhamed11)

````

⚠️ **مهم:** داخل `README.md` هنا فيه Markdown fences خاصة بالـREADME نفسه. هذه المرة **انسخي الكود كاملًا كما هو** داخل الملف؛ أما في ملفات Python سابقًا كنا نحذر من ` ```python ` لأنها ليست جزءًا من كود Python.

بعدها **Ctrl + S** فقط.

لما تخلصين اكتبي **تم**، وننتقل مباشرة لآخر خطوة: **Commit + Push إلى GitHub** 🚀
````

