import enum
import socket
import sys
import threading
import time

NUM_OF_TCP_CONNECTIONS = 0
NUM_OF_UDP_CONNECTIONS = 0
MAX_UDP_CONNECTION = 0
MAX_TCP_CONNECTION = 0
UDP_D_GATEWAY = None
TCP_D_GATEWAY = None
UPD_IP = None
TCP_IP = None

INIT_IP = '0.0.0.0'
LATT = None
LONGT = None

# N_ASSIGNED_IP = 'assigned_ip'
# N_D_DISTANCE = 'direct_distance'
# N_SOCKET = 'socket'
# {d_gateway: {'assigned_ip': x, 'direct_distance': d, 'socket': s}}
# NEIGHBOURS = dict()
ASSIGNED_UDP_IP = None

# {src_ip: dataString}
DATA_COLLECTED = dict()  # Collect chunks of data for later concatenation

# {target_IP: {P_SWITCH: p, P_DISTANCE: d}} shortest path from current switch to target through the P_SWITCH
P_SWITCH = "switch"
P_DISTANCE = "distance"
PATH = None

DISC_MODE = 0x01
OFFER_MODE = 0x02
REQ_MODE = 0x03
ACK_MODE = 0x04
DATA_MODE = 0x05  # Receive data from the adapter
IS_AVAIL_MODE = 0x06  # The switch send packet to ask whether the adapter is available
AVAIL_MODE = 0x07  # The adapter tells the switch it is available to rcv packet
LOCATION_MODE = 0x08  # The switch tells the location to its peer
BRC_MODE = 0X09
CHUNK_MODE = 0x0a
LAST_CHUNK_MODE = 0x0b
VALID_MODES = [DISC_MODE, OFFER_MODE, REQ_MODE, ACK_MODE, DATA_MODE, AVAIL_MODE,
               IS_AVAIL_MODE, LOCATION_MODE, BRC_MODE, CHUNK_MODE, LAST_CHUNK_MODE]


class Pkt_type(enum.Enum):
    DATA = 'DATA'
    GREETING = 'GREETING'
    DATA_COM = 'DATA_COM'
    LOCATION = 'LOCATION'
    BROADCAST = 'BROADCAST'


def create_packet(src_ip, dst_ip, reserved, mode, data=None):
    # reserved = bytes(3)
    mode = bytes([mode])
    packet = bytearray()
    # remember big-endian
    packet += (src_ip + dst_ip + reserved + mode)
    for d in data:
        packet += d
    return packet


# c_type = "client" | "server", protocol = "UDP" | "TCP"
def rcv_packet(packet, c_type, s, protocol="TCP", udp_addr=None):
    global ASSIGNED_UDP_IP
    global NUM_OF_TCP_CONNECTIONS
    global MAX_TCP_CONNECTION
    global LATT
    global LONGT
    global tcp_socket

    return_packets = []

    try:
        (src_ip, dest_ip, reserved, mode, assigned_ip) = extract_packet(
            packet, Pkt_type.GREETING)  # bytes
    except:
        return

    if mode == OFFER_MODE:
        # Send REQ, as a client that is not assigned IP yet
        new_src_ip = INIT_IP
        new_dst_ip = src_ip
        new_mode = REQ_MODE
        req_pkt = create_packet(socket.inet_aton(new_src_ip), new_dst_ip, bytes(
            3), new_mode, (assigned_ip,))
        if protocol == "TCP":
            s.sendall(req_pkt)
        else:
            s.sendto(req_pkt, udp_addr)
        return_packets = [req_pkt]

    elif mode == ACK_MODE or (mode == LOCATION_MODE and c_type == "server"):
        if c_type == "client":
            # Update NEIGHBOURS
            ASSIGNED_UDP_IP = socket.inet_ntoa(assigned_ip)
            if protocol == "UDP":
                return

    elif mode == IS_AVAIL_MODE:
        new_src_ip = dest_ip
        new_dst_ip = src_ip
        new_mode = AVAIL_MODE
        avail_pkt = create_packet(new_src_ip, new_dst_ip, bytes(
            3), new_mode, (bytes(),))
        s.sendto(avail_pkt, udp_addr)

    elif mode == DATA_MODE or mode == CHUNK_MODE or mode == LAST_CHUNK_MODE:
        # Disp message to the screen
        data_b = assigned_ip
        message = data_b.decode()
        o_src_ip = socket.inet_ntoa(src_ip)
        if mode == CHUNK_MODE:
            if o_src_ip not in DATA_COLLECTED:
                DATA_COLLECTED[o_src_ip] = message
            else:
                DATA_COLLECTED[o_src_ip] += message
        elif mode == LAST_CHUNK_MODE:
            DATA_COLLECTED[o_src_ip] += message
            print(
                f'\b\bReceived from {socket.inet_ntoa(src_ip)}: {DATA_COLLECTED[o_src_ip]}', flush=True)
            print("> ", end="", flush=True)
        else:
            print(
                f'\b\bReceived from {socket.inet_ntoa(src_ip)}: {message}', flush=True)
            print("> ", end="", flush=True)

    return return_packets


def extract_packet(packet, p_type=None):
    try:
        src_ip = packet[:4]
        dest_ip = packet[4:8]
        reserved = packet[8:11]
        mode = packet[11]
        if mode not in VALID_MODES:
            return None
    except:
        return None

    if p_type == None:
        return (src_ip, dest_ip, reserved, mode)

    if p_type == Pkt_type.DATA or p_type == Pkt_type.GREETING:
        data = packet[12:]
        return (src_ip, dest_ip, reserved, mode, data)

    elif p_type == Pkt_type.DATA_COM:
        return (src_ip, dest_ip, reserved, mode)

    elif p_type == Pkt_type.LOCATION:
        LATT = packet[12:14]
        LONGT = packet[14:]
        return (src_ip, dest_ip, reserved, mode, LATT, LONGT)

    elif p_type == Pkt_type.BROADCAST:
        target_ip = packet[12:16]
        distance = packet[16:]
        return (src_ip, dest_ip, reserved, mode, target_ip, distance)


def send_message(packet):
    global udpSock
    global serverAddressPort
    udpSock.sendto(packet, serverAddressPort)


def rcv_command():
    global params
    while True:
        try:
            command = input("> ")
        except EOFError:
            break
        command_elements = command.split(" ")
        if command_elements[0] == "send":
            rcv_ip_address = command_elements[1]
            message_quote = command_elements[2]
            message = ""
            if message_quote[0] == '"' and message_quote[-1] == '"':
                message = message_quote[1:-1]
            else:
                continue
            # make data packet
            data_packet = create_packet(socket.inet_aton(ASSIGNED_UDP_IP), socket.inet_aton(
                rcv_ip_address), bytes(3), DATA_MODE, data=(str.encode(message),))
            # send to the switch
            send_message(data_packet)


def wait_for_packet():
    global udpSock
    # Data communication
    data, srv_address = udpSock.recvfrom(1500)
    rcv_packet(data, "client", udpSock, protocol="UDP",
               udp_addr=serverAddressPort)
    while True:
        # Rcv dat packet and display
        data, srv_address = udpSock.recvfrom(1500)
        rcv_packet(data, "client", udpSock, protocol="UDP",
                   udp_addr=serverAddressPort)


# Read params
params = sys.argv
port = int(params[1])

HOST = "127.0.0.1"
serverAddressPort = (HOST, port)
bufferSize = 1500

# Create a UDP socket at client side
udpSock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

# Greeting Protocol

# create DISC packet
disc_packet = create_packet(socket.inet_aton(INIT_IP), socket.inet_aton(
    INIT_IP), bytes(3), DISC_MODE, data=(socket.inet_aton(INIT_IP),))

# as a client, send packet with UDP protocol to given port
udpSock.sendto(disc_packet, serverAddressPort)

# recv offer
data, srv_address = udpSock.recvfrom(1500)
# send req
rcv_packet(data, "client", udpSock, protocol="UDP", udp_addr=serverAddressPort)
# recv ack and set the assigned ip addr
data, srv_address = udpSock.recvfrom(1500)
rcv_packet(data, "client", udpSock, protocol="UDP", udp_addr=serverAddressPort)

wait_for_packet_thread = threading.Thread(target=wait_for_packet)
wait_for_packet_thread.start()

rcv_command()
