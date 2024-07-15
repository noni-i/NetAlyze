#scapy to capture the packets
from scapy.all import sniff, IP, TCP, UDP, ICMP
import re
import datetime

#generates the spaces after the ips during execution
def spaces(length):
    totalL = len(length)
    spaces = ' ' * (19 - totalL)
    return spaces
#generates the spaces after the ports during execution
def spacesPort(length):
    port = str(length)
    totalL = len(port)
    spaces = ' ' * (9 - totalL)
    return spaces

#the function of packet capturing
def packet_callback(packet):

    packet_time = datetime.datetime.fromtimestamp(packet.time)
    time = packet_time.strftime('%Y-%m-%d %H:%M:%S')

    #prints out TCP packets
    if packet.haslayer(TCP):
        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            tcp_layer = packet.getlayer(TCP)
            print(f"| {time}    | {ip_layer.src}{spaces(ip_layer.src)}| {tcp_layer.sport}{spacesPort(tcp_layer.sport)}| -> | {ip_layer.dst}{spaces(ip_layer.dst)}| {tcp_layer.dport}{spacesPort(tcp_layer.dport)}| TCP                |")

    # prints out UDP packets
    if packet.haslayer(UDP):
        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            udp_layer = packet.getlayer(UDP)
            print(f"| {time}    | {ip_layer.src}{spaces(ip_layer.src)}| {udp_layer.sport}{spacesPort(udp_layer.sport)}| -> | {ip_layer.dst}{spaces(ip_layer.dst)}| {udp_layer.dport}{spacesPort(udp_layer.dport)}| UDP                |")

    # prints out ICMP packets
    if packet.haslayer(ICMP):
        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            icmp_layer = packet.getlayer(ICMP)
            print(f"| {time}    | {ip_layer.src}{spaces(ip_layer.src)}|          | -> | {ip_layer.dst}{spaces(ip_layer.dst)}|          | ICMP Type {icmp_layer.type} Code {icmp_layer.code} |")

#filter function
def get_filter_input(filter):

    filterRe = re.search("filter\([^)]*\)", filter)
    filter_parts = filterRe.group().lower().split(",")

    filter_complete = []

    if filter_parts:
        for i in filter_parts:
            address = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', i)
            if address:
                if f"ip.addr=\"{address.group(0)}\"" in i:
                    filter_complete.append(f"host {address.group(0)}")

            if "tcp" in i:
                filter_complete.append("tcp")

            if "udp" in i:
                filter_complete.append("udp")

            if "icmp" in i:
                filter_complete.append("icmp")

            port = re.search(r'([0-9]+)', i)
            if port:
                if f"port=\"{port.group(0)}\"" in i:
                    filter_complete.append(f"port {port.group(0)}")

    return " and ".join(filter_complete)


if __name__ == "__main__":

    #color
    BLUE = "\033[34m"
    RESET = "\033[0m"

    print(f"{BLUE}      ___           ___                       ___                                     ___           ___    ")
    print(f"{BLUE}     /__/\         /  /\          ___        /  /\                        ___        /  /\         /  /\   ")
    print(f"{BLUE}     \  \:\       /  /:/_        /  /\      /  /::\                      /__/|      /  /::|       /  /:/_  ")
    print(f"{BLUE}      \  \:\     /  /:/ /\      /  /:/     /  /:/\:\    ___     ___     |  |:|     /  /:/:|      /  /:/ /\ ")
    print(f"{BLUE}  _____\__\:\   /  /:/ /:/_    /  /:/     /  /:/~/::\  /__/\   /  /\    |  |:|    /  /:/|:|__   /  /:/ /:/_")
    print(f"{BLUE} /__/::::::::\ /__/:/ /:/ /\  /  /::\    /__/:/ /:/\:\ \  \:\ /  /:/  __|__|:|   /__/:/ |:| /\ /__/:/ /:/ /\ ")
    print(f"{BLUE} \  \:\~~\~~\/ \  \:\/:/ /:/ /__/:/\:\   \  \:\/:/__\/  \  \:\  /:/  /__/::::\   \__\/  |:|/:/ \  \:\/:/ /:/")
    print(f"{BLUE}  \  \:\  ~~~   \  \::/ /:/  \__\/  \:\   \  \::/        \  \:\/:/      ~\~~\:\      |  |:/:/   \  \::/ /:/")
    print(f"{BLUE}   \  \:\        \  \:\/:/        \  \:\   \  \:\         \  \::/         \  \:\     |  |::/     \  \:\/:/ ")
    print(f"{BLUE}    \  \:\        \  \::/          \__\/    \  \:\         \__\/           \__\/     |  |:/       \  \::/  ")
    print(f"{BLUE}     \__\/         \__\/                     \__\/                                   |__|/         \__\/   ")
    print(" ")
    print(" ")
    print(f"{BLUE}					            .:..:. Coded by @erjonahmeti .:..:.{RESET}")
    print(" ")
    print("     Netalyze is a packet sniffer coded in Python, designed for network monitoring and analysis.")
    print("This tool is capable of capturing and filtering network packets based on various criteria, including IP")
    print("                 addresses, protocols (TCP, UDP, ICMP), and port numbers.")
    print(" ")
    print("The filter format is as it goes \"filter(argument)\" ")
    print("The arguments can be ip.addr=\"ipv4 here\", tcp, udp, icmp, or port=\"port here\"")
    print("e.g. filter(ip.addr=\"192.168.0.1\", tcp, port=\"80\")")
    print(" ")
    input = input("If you have a filter enter here using the format above (leave blank if not): ")

    #conditions for filtering
    if input:
        filter_string = get_filter_input(input)
        print(f"Using filter: {filter_string}")
        print("| Time                   | Source             | SPort    |    | Destination        | Dport    | Protocol           |")
        print("--------------------------------------------------------------------------------------------------------------------")
        sniff(filter=filter_string, prn=packet_callback, store=0)
    else:
        print("| Time                   | Source             | SPort    |    | Destination        | Dport    | Protocol           |")
        print("--------------------------------------------------------------------------------------------------------------------")
        sniff(prn=packet_callback, store=0)
