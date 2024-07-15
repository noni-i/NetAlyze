# NetAlyze

NetAlyze is a powerful packet sniffer written in Python, designed to filter and analyze network traffic based on IP addresses, TCP, UDP, ICMP protocols, and ports.

![image](https://github.com/user-attachments/assets/721a46ec-2035-47d9-94c7-b1706f682760)


## Features

**IP Filtering** :  Capture packets from specific IP addresses.<br>
**Protocol Filtering** : Filter packets by TCP, UDP, and ICMP protocols.<br>
**Port Filtering** :  Focus on network traffic through specified ports.<br>
**Real-time Analysis** : Monitor and analyze packets in real time.

![image](https://github.com/user-attachments/assets/9483015d-bdcc-43e8-881b-d936c84f7f25)

## Installation

1.Clone the repository:<br>
```<bash> 
git clone https://github.com/noni-i/NetAlyze.git
```

2.Navigate to the project directory:<br>
```<bash>
cd NetAlyze
```

3.Install the required dependencies:<br>
```<bash>
pip install -r requirements.txt
```

## Usage
To run NetAlyze, use the following command:

```<bash>
python netalyze.py
```

## Options

filter(ip.addr="iphere"): Filter packets from a specific IP address.<br>
filter(tcp or udp or icmp): Filter packets by protocol (TCP, UDP, ICMP).<br>
filter(port="porthere"): Filter packets by specific port.<br>

### Examples

Filter by IP address:

```<bash>
filter(ip.addr="192.168.0.1")
```

Filter by protocol (TCP):

```<bash>
filter(tcp)
```

Filter by port (80):

```filter(port="80")```

## Contact
For any questions or suggestions, feel free to open an issue or contact me directly @noni-i.
