import enum
import io
import ipaddress
import math
import socket
import struct
import sys
import threading
from binascii import hexlify, unhexlify

lock = threading.Lock()

MAX_PKT_LEN = 1500
MAX_DATA_LEN = MAX_PKT_LEN - 12

INIT_IP = '0.0.0.0'
LATT = None
LONGT = None

N_ASSIGNED_IP = 'assigned_ip'
N_D_DISTANCE = 'direct_distance'
N_UDP_ADDR = 'udp_addr'
N_SOCKET = 'socket'
N_TIMER = 'timer'
# {d_gateway: {'assigned_ip': x, 'direct_distance': d, 'socket': s}}
NEIGHBOURS = dict()


P_SWITCH = "switch"
P_DISTANCE = "distance"
# {target_IP: {P_SWITCH: p, P_DISTANCE: d}} shortest path from current switch to target through the P_SWITCH
PATH = dict()

DQ_PKT = "packet"
DQ_S = "socket"
# {target_ip: {"packet": array of packets, "socket": s}}
DATA_QUEUE = dict()  # Data to send to adapter when it is available

# {src_ip: dataString}
DATA_COLLECTED = dict()  # Collect chunks of data for later concatenation

DISC_MODE = 0x01
OFFER_MODE = 0x02
REQ_MODE = 0x03
ACK_MODE = 0x04
DATA_MODE = 0x05  # Receive data from the adapter
IS_AVAIL_MODE = 0x06  # The switch send packet to ask whether the adapter is available
AVAIL_MODE = 0x07  # The adapter tells the switch it is available to rcv packet
LOCATION_MODE = 0x08  # The switch tells the location to its peer
BRC_MODE = 0x09
CHUNK_MODE = 0x0a
LAST_CHUNK_MODE = 0x0b
VALID_MODES = [DISC_MODE, OFFER_MODE, REQ_MODE, ACK_MODE, DATA_MODE, AVAIL_MODE,
               IS_AVAIL_MODE, LOCATION_MODE, BRC_MODE, CHUNK_MODE, LAST_CHUNK_MODE]

NUM_OF_TCP_CONNECTIONS = 0
NUM_OF_UDP_CONNECTIONS = 0
MAX_UDP_CONNECTION = 0
MAX_TCP_CONNECTION = 0
UDP_D_GATEWAY = None
TCP_D_GATEWAY = None
UPD_IP = None
TCP_IP = None


class Pkt_type(enum.Enum):
    DATA = 'DATA'
    GREETING = 'GREETING'
    DATA_COM = 'DATA_COM'
    LOCATION = 'LOCATION'
    BROADCAST = 'BROADCAST'


def convert_reserved_value(val):
    bytes_val = val.to_bytes(3, 'big')
    hex_val = hexlify(bytes_val).decode('utf-8')
    return unhexlify(hex_val)


def assign_new_ip(type):
    global NUM_OF_TCP_CONNECTIONS
    global NUM_OF_UDP_CONNECTIONS

    if type == "TCP":
        # remember to handle special cases 0 - 255
        next_ip = ipaddress.ip_address(
            TCP_D_GATEWAY) + 1 + NUM_OF_TCP_CONNECTIONS
        NUM_OF_TCP_CONNECTIONS += 1
    elif type == "UDP":
        next_ip = ipaddress.ip_address(
            UDP_D_GATEWAY) + 1 + NUM_OF_UDP_CONNECTIONS
        NUM_OF_UDP_CONNECTIONS += 1
    return str(ipaddress.ip_address(next_ip))


def ip_to_bin(ip):
    return ' ' .join(format(int(x), '08b') for x in ip.split('.'))


def longest_prefix_matching(dest_ip, ip_list):
    # ip_list = tuple(ip_list)
    dest_ip_bin = ip_to_bin(dest_ip)
    longest_matchings = []
    for ip in ip_list:
        longest_matching = 0
        ip_bin = ip_to_bin(ip)
        for index, b in enumerate(dest_ip_bin):
            if ip_bin[index] == b:
                longest_matching += 1
            else:
                break
        longest_matchings.append(longest_matching)
    if longest_matchings:
        return ip_list[longest_matchings.index(max(longest_matchings))]
    else:
        return None


def extract_packet(packet, p_type=None):
    try:
        src_ip = packet[:4]
        dest_ip = packet[4:8]
        reserved = packet[8:11]
        mode = packet[11]
        if not mode in VALID_MODES:
            return None
    except IndexError:
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
        LONGT = packet[14:16]
        return (src_ip, dest_ip, reserved, mode, LATT, LONGT)

    elif p_type == Pkt_type.BROADCAST:
        target_ip = packet[12:16]
        distance = packet[16:20]
        return (src_ip, dest_ip, reserved, mode, target_ip, distance)


def foo():
    pass

# c_type = "client" | "server", protocol = "UDP" | "TCP"


def rcv_packet(packet, c_type, s, protocol="TCP", udp_addr=None, tcp_addr=None):
    global NEIGHBOURS
    global NUM_OF_TCP_CONNECTIONS
    global MAX_TCP_CONNECTION
    global LATT
    global LONGT
    global tcp_socket
    global PATH

    return_packets = []
    try:
        (src_ip, dest_ip, reserved, mode, assigned_ip) = extract_packet(
            packet, Pkt_type.GREETING)  # bytes
    except:
        return

    if mode == DISC_MODE:
        if protocol == "UDP" and NUM_OF_UDP_CONNECTIONS < MAX_UDP_CONNECTION:
            new_src_ip = UDP_D_GATEWAY
            assigned_ip = assign_new_ip("UDP")
            new_dst_ip = src_ip
            new_mode = OFFER_MODE
            offer_pkt = create_packet(socket.inet_aton(new_src_ip), new_dst_ip, bytes(
                3), new_mode, (socket.inet_aton(assigned_ip),))
            s.sendto(offer_pkt, udp_addr)
        elif protocol == "TCP" and NUM_OF_TCP_CONNECTIONS < MAX_TCP_CONNECTION:
            new_src_ip = TCP_D_GATEWAY
            assigned_ip = assign_new_ip("TCP")
            new_dst_ip = src_ip
            new_mode = OFFER_MODE
            offer_pkt = create_packet(socket.inet_aton(new_src_ip), new_dst_ip, bytes(
                3), new_mode, (socket.inet_aton(assigned_ip),))
            s.sendall(offer_pkt)

        return_packets = [offer_pkt]

    elif mode == OFFER_MODE:
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

    elif mode == REQ_MODE:
        # Send ack
        if protocol == "TCP":
            new_src_ip = TCP_D_GATEWAY
            n_info = {N_ASSIGNED_IP: TCP_D_GATEWAY,
                      N_SOCKET: s, N_TIMER: threading.Timer(5.0, foo)}
        elif protocol == "UDP":
            new_src_ip = UDP_D_GATEWAY
            n_info = {N_ASSIGNED_IP: UDP_D_GATEWAY,
                      N_SOCKET: s, N_UDP_ADDR: udp_addr, N_TIMER: threading.Timer(5.0, foo)}

        new_dst_ip = assigned_ip
        new_mode = ACK_MODE

        # Update NEIGHBOURS
        # if c_type == "server" and protocol == "UDP":
        NEIGHBOURS[socket.inet_ntoa(assigned_ip)] = n_info

        ack_pkt = create_packet(socket.inet_aton(new_src_ip), new_dst_ip, bytes(
            3), new_mode, (assigned_ip,))

        if protocol == "TCP":
            s.sendall(ack_pkt)
        else:
            s.sendto(ack_pkt, udp_addr)

    # When the server rcv the Location packet
    elif mode == ACK_MODE or (mode == LOCATION_MODE and c_type == "server"):
        if c_type == "client":
            # Update NEIGHBOURS
            n_info = {N_ASSIGNED_IP: socket.inet_ntoa(
                assigned_ip), N_SOCKET: s, N_TIMER: threading.Timer(5.0, foo)}
            NEIGHBOURS[socket.inet_ntoa(src_ip)] = n_info
            # Update PATH
            new_src_ip = assigned_ip
        else:
            new_src_ip = socket.inet_aton(
                TCP_D_GATEWAY if protocol == "TCP" else UDP_D_GATEWAY)

        # Send its Location back
        new_dst_ip = src_ip
        new_mode = LOCATION_MODE
        latt = struct.pack('>H', LATT)
        longt = struct.pack('>H', LONGT)
        location_pkt = create_packet(
            new_src_ip, new_dst_ip, bytes(3), new_mode, (latt, longt,))

        if protocol == "TCP":
            s.sendall(location_pkt)
        else:
            s.sendto(location_pkt, udp_addr)

    elif mode == DATA_MODE or mode == CHUNK_MODE or mode == LAST_CHUNK_MODE:
        # Send DATA packet:
        packet_len = len(packet)
        packet_chunks = []
        split = False
        # First local switch

        if packet_len > MAX_PKT_LEN:
            split = True
            data_len = packet_len - 12
            num_full_packets = math.floor(data_len/MAX_DATA_LEN)
            # Chunks of packet
            for i in range(num_full_packets):
                new_reserved = convert_reserved_value(i*MAX_DATA_LEN)
                new_mode = CHUNK_MODE
                data_chunk = assigned_ip[i*MAX_DATA_LEN:(MAX_DATA_LEN*(i+1))]
                packet_chunk = create_packet(
                    src_ip, dest_ip, new_reserved, new_mode, (data_chunk,))
                packet_chunks.append(packet_chunk)
            # Last packet chunk
            consumed_data_len = num_full_packets * MAX_DATA_LEN
            remain_data_len = data_len - consumed_data_len
            if remain_data_len > 0:
                new_reserved = convert_reserved_value(MAX_DATA_LEN)
                new_mode = LAST_CHUNK_MODE
                remain_data = assigned_ip[consumed_data_len:data_len]
                last_packet_chunk = create_packet(
                    src_ip, dest_ip, new_reserved, new_mode, (remain_data,))
                packet_chunks.append(last_packet_chunk)
        else:
            packet_chunks = [packet]

        # Switch receives chunks of data whose destination is its ip addr
        o_dest_ip = socket.inet_ntoa(dest_ip)
        o_src_ip = socket.inet_ntoa(src_ip)
        if o_dest_ip == TCP_D_GATEWAY or o_dest_ip == UDP_D_GATEWAY:  # The switch received the message
            data_b = assigned_ip
            message = data_b.decode()
            if mode == DATA_MODE:
                print(
                    f'\b\bReceived from {socket.inet_ntoa(src_ip)}: {message}', flush=True)
                print("> ", end="", flush=True)
            elif mode == CHUNK_MODE:
                if o_src_ip not in DATA_COLLECTED:
                    DATA_COLLECTED[o_src_ip] = message
                else:
                    DATA_COLLECTED[o_src_ip] += message
            elif mode == LAST_CHUNK_MODE:
                DATA_COLLECTED[o_src_ip] += message
                print(
                    f'\b\bReceived from {socket.inet_ntoa(src_ip)}: {DATA_COLLECTED[o_src_ip]}', flush=True)
                print("> ", end="", flush=True)

            return

        # Determine next switch to send
        if o_dest_ip not in PATH.keys():
            # Find in the NEIGHBOUTS the assigned ip that has given socket
            this_assigned_ip = None
            for n_ip in NEIGHBOURS:
                if NEIGHBOURS[n_ip][N_SOCKET] == s:
                    this_assigned_ip = n_ip
            candidates = list(NEIGHBOURS.keys())
            candidates.remove(this_assigned_ip)
            # next ip except for the sending ip
            next_ip = longest_prefix_matching(o_dest_ip, candidates)
        else:
            next_ip = PATH[o_dest_ip][P_SWITCH]
            if not next_ip:
                next_ip = o_dest_ip

        sock_to_send = NEIGHBOURS[next_ip][N_SOCKET]

        # Update Data queue and send AVAIL_MODE
        if UDP_D_GATEWAY and TCP_D_GATEWAY:
            next_ip = o_dest_ip
            if next_ip not in NEIGHBOURS:
                return

        # Update the data queue for next switch
        if next_ip not in DATA_QUEUE:
            DATA_QUEUE[next_ip] = {
                DQ_PKT: packet_chunks, DQ_S: sock_to_send}
        elif next_ip in DATA_QUEUE and not DATA_QUEUE[next_ip][DQ_PKT]:
            DATA_QUEUE[next_ip][DQ_PKT] = packet_chunks
        else:
            DATA_QUEUE[next_ip][DQ_PKT].extend(packet_chunks)

        # Send AVAIL_MODE to the next switch, save packets to queue if data chunks
        if mode == CHUNK_MODE:
            return

        dest_timer = NEIGHBOURS[next_ip][N_TIMER]
        if not dest_timer.is_alive():  # Check the timer
            new_mode = IS_AVAIL_MODE
            is_avail_packet = create_packet(
                socket.inet_aton(NEIGHBOURS[next_ip][N_ASSIGNED_IP]), socket.inet_aton(next_ip), bytes(3), new_mode, (bytes(),))
            if TCP_D_GATEWAY and UDP_D_GATEWAY:
                udp_addr = NEIGHBOURS[next_ip][N_UDP_ADDR]
                sock_to_send.sendto(is_avail_packet, udp_addr)
            else:
                sock_to_send.sendall(is_avail_packet)

            try:
                dest_timer.start()
            except RuntimeError:
                dest_timer = threading.Timer(5.0, foo)
                dest_timer.start()
            return

    elif mode == IS_AVAIL_MODE:
        new_src_ip = dest_ip
        new_dst_ip = src_ip
        new_mode = AVAIL_MODE
        avail_pkt = create_packet(new_src_ip, new_dst_ip, bytes(
            3), new_mode, (bytes(),))
        if protocol == "UDP":
            s.sendto(avail_pkt, udp_addr)
        else:
            s.sendall(avail_pkt)

    elif mode == AVAIL_MODE:
        sock_to_send = DATA_QUEUE[socket.inet_ntoa(src_ip)][DQ_S]
        packet_list = DATA_QUEUE[socket.inet_ntoa(src_ip)][DQ_PKT]
        for packet in packet_list:
            if protocol == "UDP":
                sock_to_send.sendto(packet, udp_addr)
            else:
                sock_to_send.sendall(packet)
        # reset data queue
        packet_list = []

    # Calc distance and broadcast
    if mode == LOCATION_MODE:
        try:
            (src_ip, dest_ip, reserved, mode, latt, longt) = extract_packet(
                packet, Pkt_type.LOCATION)  # bytes
        except:
            return

        new_mode = BRC_MODE
        rcv_latt = int.from_bytes(latt, 'big')
        rcv_longt = int.from_bytes(longt, 'big')
        distance = math.floor(
            math.sqrt((LATT - rcv_latt)**2 + (LONGT - rcv_longt)**2))

        if distance > 1000:
            return

        # Update NEIGHBOURS direct distance
        NEIGHBOURS[socket.inet_ntoa(src_ip)][N_D_DISTANCE] = distance
        # Update PATH distance
        if socket.inet_ntoa(src_ip) not in PATH or (socket.inet_ntoa(src_ip) in PATH and PATH[socket.inet_ntoa(src_ip)][P_DISTANCE] > distance):
            PATH[socket.inet_ntoa(src_ip)] = {
                P_SWITCH: None, P_DISTANCE: distance}
        if UDP_D_GATEWAY and c_type == "server":  # Local switch with 2 IP recv location
            # Send distance of UDP port to global switch
            new_src_ip = dest_ip
            new_dest_ip = src_ip
            distance_pkt = create_packet(new_src_ip, new_dest_ip, bytes(
                3), new_mode, (socket.inet_aton(UDP_D_GATEWAY), distance.to_bytes(4, byteorder='big'),))
            s.sendall(distance_pkt)
            return

        # Broadcast distance to all of the NEIGHBOURS
        for n_ip in NEIGHBOURS.keys():
            if n_ip == socket.inet_ntoa(src_ip):
                continue
            new_src_ip = NEIGHBOURS[n_ip][N_ASSIGNED_IP]
            new_dst_ip = n_ip
            distance_b = (
                distance + NEIGHBOURS[n_ip][N_D_DISTANCE]).to_bytes(4, byteorder='big')
            new_pkt = create_packet(socket.inet_aton(
                new_src_ip), socket.inet_aton(new_dst_ip), bytes(3), new_mode, (src_ip, distance_b,))

            skt = NEIGHBOURS[n_ip][N_SOCKET]
            if protocol == "TCP":
                skt.sendall(new_pkt)
            else:
                skt.sendto(new_pkt, udp_addr)
            return_packets.append(new_pkt)

    elif mode == BRC_MODE:
        try:
            (src_ip, dest_ip, reserved, mode, target_ip,
             distance) = extract_packet(packet, Pkt_type.BROADCAST)
        except:
            return

        new_mode = BRC_MODE
        o_src_ip = socket.inet_ntoa(src_ip)
        o_dst_ip = socket.inet_ntoa(dest_ip)
        o_target_ip = socket.inet_ntoa(target_ip)
        int_distance = int.from_bytes(distance, "big")

        # Already in PATH with smaller distance
        if (o_target_ip in PATH and PATH[o_target_ip][P_SWITCH] == o_src_ip and PATH[o_target_ip][P_DISTANCE] < int_distance):
            return

        # Update PATH if this S is not the target S and target S is not in PATH or target S already in PATH, but with larger distance
        if o_target_ip != TCP_D_GATEWAY and (not o_target_ip in PATH) or (o_target_ip in PATH and PATH[o_target_ip][P_DISTANCE] > int_distance):
            if not UDP_D_GATEWAY or (UDP_D_GATEWAY and o_target_ip != UDP_D_GATEWAY):
                PATH[o_target_ip] = {
                    P_SWITCH: o_src_ip, P_DISTANCE: int_distance}

        # Brc to NEIGHBOURS
        for n_ip in NEIGHBOURS.keys():
            # Else if the neighbour's ip addr != src,dest,target
            # Send the BRC to it
            if n_ip != o_src_ip and n_ip != o_dst_ip and n_ip != o_target_ip:
                new_src_ip = NEIGHBOURS[n_ip][N_ASSIGNED_IP]
                new_dst_ip = n_ip
                new_d_int = int_distance + NEIGHBOURS[n_ip][N_D_DISTANCE]
                new_d = new_d_int.to_bytes(4, byteorder='big')
                new_pkt = create_packet(socket.inet_aton(
                    new_src_ip), socket.inet_aton(new_dst_ip), bytes(3), new_mode, (target_ip, new_d,))
                skt = NEIGHBOURS[n_ip][N_SOCKET]
                if protocol == "TCP":
                    skt.sendall(new_pkt)
                else:
                    skt.sendto(new_pkt, udp_addr)

    return return_packets


def create_packet(src_ip, dst_ip, reserved, mode, data=None):
    # reserved = bytes(3)
    mode = bytes([mode])
    packet = bytearray()
    # remember big-endian
    packet += (src_ip + dst_ip + reserved + mode)
    for d in data:
        packet += d
    return packet


def send_connect(port):
    # create DISC packet
    disc_packet = create_packet(socket.inet_aton(INIT_IP), socket.inet_aton(
        INIT_IP), bytes(3), DISC_MODE, data=(socket.inet_aton(INIT_IP),))

    # as a client, send packet with TCP to given port
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, port))
    s.sendall(disc_packet)

    while True:
        data = s.recv(1500)
        lock.acquire()
        rcv_packet(data, "client", s)
        lock.release()


def udp():
    while True:
        packet, address = udp_socket.recvfrom(55296)
        udp_thread = threading.Thread(
            target=udp_handle, args=(packet, address,))
        udp_thread.start()


def udp_handle(packet, address):
    lock.acquire()
    rcv_packet(packet, "server", udp_socket,
               protocol="UDP", udp_addr=address)
    lock.release()


def tcp():
    while True:
        conn, addr = tcp_socket.accept()
        tcp_handle_thread = threading.Thread(
            target=tcp_handle, args=(conn, addr,))
        tcp_handle_thread.start()


def handle_tcp_pkt(packet, conn):
    rcv_packet(packet, "server", conn)


def tcp_handle(conn, addr):
    with conn:
        while True:
            packet = conn.recv(1500)
            rcv_packet(packet, "server", conn)


def handle_command(command):
    if command.split(" ", 1)[0] == "connect" and len(params) < 6:
        dst_port = int(command.split(" ", 1)[1])
        send_connect(dst_port)


def rcv_command():
    while True:
        try:
            command = input("> ")
            command_thread = threading.Thread(
                target=handle_command, args=(command,))
            command_thread.start()
        except EOFError:
            break


# Read params
params = sys.argv
switch_type = params[1]

LATT = params[3]
LONGT = params[4]
if switch_type == "local":
    UDP_IP = params[2]
    if len(params) == 6:
        TCP_IP = params[3]
        LATT = params[4]
        LONGT = params[5]
else:
    TCP_IP = params[2]

LATT = int(LATT)
LONGT = int(LONGT)

HOST = "127.0.0.1"

if switch_type == "local":
    # UDP: Conenct with the Adapter
    UDP_IP = UDP_IP.split("/")
    UDP_D_GATEWAY = UDP_IP[0]
    MAX_UDP_CONNECTION = 2**(32 - int(UDP_IP[1])) - 2

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((HOST, 0))
    udp_port = udp_socket.getsockname()[1]

    print(udp_port, flush=True)

    udp_thread = threading.Thread(target=udp)
    udp_thread.start()

if switch_type == "local" and len(params) == 6 or switch_type == "global":
    # TCP: Connect with other switches
    TCP_IP = TCP_IP.split("/")
    TCP_D_GATEWAY = TCP_IP[0]
    MAX_TCP_CONNECTION = 2**(32 - int(TCP_IP[1])) - 2

    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.bind((HOST, 0))
    tcp_socket.listen()

    tcp_port = tcp_socket.getsockname()[1]
    print(tcp_port, flush=True)

    tcp_thread = threading.Thread(target=tcp)
    tcp_thread.start()

rcv_command()
