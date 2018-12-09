# ====================================================================================================================
#   chat_client.py
#           use TCP to connect to, exchange data with multi-client listener process
#           communications protocol:
#           -.  individual messages: each consists of a variable-length packet with fixed-size header
#               -.  header: a two-byte integer, encoded as a byte array, XDR-standard byte order
#               -.  body:  message proper, encoded as a byte array
#           -.  overall exchange
#               -.  client sends a series of messages to the server
#               -.  client reads messages from server, using separate thread
# -------------------------------------------------------------------------------------------------------------------
#   author: Phil Pfeiffer
#   last updated:  October 2018
# -------------------------------------------------------------------------------------------------------------
#   usage:
#       <program-name>  <server-IP>  <server-URL>  <server-port>
#       command line arguments:
#           server-IP:   IP address to assign to server
#               format:   --server-IP  <IP address>       or  -ip <IP address>
#                  IP address format:
#                      standard IPv4 format - w.x.y.z, where 0 <= w, x, y, z <= 255
#                  default value:  None
#           server-URL:  IP address for server to contact
#               format:  --server-host <path expression>  or  -host <URL expression>
#                  URL format:
#                      standard DNS format - a(.b(.c(.d... ))),
#                      where the different tokens are valid DNS character strings
#                  default value:  localhost
#           server-port:  integer in the range 0..65535, representing a port to contact
#               default:  10000
#
#    Notes: If both server-IP and server-URL are present,
#           server-URL must resolve to the IP address specified by server-IP
# ====================================================================================================================

# +++++++++++++++++++++++++++++++++++++++++++++
# imports
# +++++++++++++++++++++++++++++++++++++++++++++
#
# argparse -
#     argparse.add_argument - specify one in a series of arguments to parse
#     argparse.Argument_parser - create a string parser
#     argparse.ArgumentTypeError - exception to raise on failed parse
#     argparse.parse_args - do the parse
# multiprocessing -
#     multiprocessing.current_process - retrieve a handle on the current process's attributes
# os -
#     os.getpid - get current process's process identifier
# random -
#     random.randint - return a random number in a specified range
#     random.seed - initialize random library random number generators
#     random.uniform - generate quasi-random number within a given range, over a uniform distribution
# socket -
#     socket.gethostbyname - get IP address for hostname
#     socket.socket - instantiates a socket
#     socket.connect - connects to a remote TCP socket
#     socket.sendall - sends data to opposite connection endpoint, retrying until all data is sent or error is detected
#     socket.recv - receives data from opposite connection endpoint
#     socket.close - closes socket connection
# sys -
#     sys.byteorder - current platform's native byteorder
# threading -
#     threading.Thread - instantiate a thread
# time -
#     time.ctime - generate human readable time of day
#     time.sleep - stop processing for specified number of seconds
#
import argparse
import multiprocessing
import os
import random
import socket
import sys
import threading
import time
import json

# +++++++++++++++++++++++++++++++++++++++++++++
# supporting constants
# +++++++++++++++++++++++++++++++++++++++++++++
#
(MIN_TCP_PORT_NUM, MAX_TCP_PORT_NUM) = (1, 65535)  # range of values for valid port numbers
(MESSAGE_COUNT_MIN, MESSAGE_COUNT_MAX) = (5, 8)  # number of messages to send, min and max
(MESSAGE_DELAY_MIN, MESSAGE_DELAY_MAX) = (2, 4)  # delay between messages to send in seconds, min and max
TCP_PORT_RANGE = 10000
DEFAULT_HOST = 'localhost'  # default to server on this host
DEFAULT_PORT = 11000  # default to port 10000 on this host

bytes_in_representation = lambda value: (value.bit_length() + 7) // 8
BYTES_PER_SHORT = bytes_in_representation(
    2 ** 16 - 1)  # number of bytes per XDR short int to transmit - sets length of byte array


# +++++++++++++++++++++++++++++++++++++++++++++
# supporting functions
# +++++++++++++++++++++++++++++++++++++++++++++

def err_to_str(exception):
    """ return '' if the exception object is empty - otherwise the string that it contains """
    return '' if str(exception) is None else ': ' + str(exception)


# ----------------------------------------------
#  command line parsing
# ----------------------------------------------
#
def port_parser(string, **kwargs):
    """ parse and validate port for receiving client connections """
    try:
        portnum = int(string)
        if portnum < MIN_TCP_PORT_NUM:
            print('?? TCP port value (%d) too low; changing to %d' % (portnum, MIN_TCP_PORT_NUM))
        else:
            if portnum > MAX_TCP_PORT_NUM:
                print('?? TCP port value (%d) too high; changing to %d' % (portnum, max(TCP_PORT_RANGE)))
        return max(min(portnum, MAX_TCP_PORT_NUM), MIN_TCP_PORT_NUM)
    except:
        syndrome = 'invalid port count: %s\ncount must be a positive integer in range %d - %d' % (
        string, MIN_UDP_PORT_NUM, MAX_UDP_PORT_NUM)
        raise argparse.ArgumentTypeError(syndrome)


def IPv4_addr_parser(string):
    """ validate an IPv4-style address """
    octets = string.split(".")
    try:
        assert len(octets) == 4 and all([0 <= value <= 255 for value in int(octet) in octets])
        return string
    except:
        raise argparse.ArgumentTypeError('invalid IP address (%s): must be of the form num.num.num.num' % string)


def hostname_parser(string):
    """ validate a DNS-style hostname """
    try:
        hostaddr = socket.gethostbyname(string)
        return (string, hostaddr)
    except OSError as err:
        raise argparse.ArgumentTypeError('invalid hostname (%s): %s' % (string, err_to_str(err)))


# ----------------------------------------------
# advisory message generation
# ----------------------------------------------
#
def message_header(process_name, column_width=1):
    """
    generate message header with process ID
        process_name - process name for header
        column_width - size of column in which to place process_name, left-justified
    """
    return '%s/%s (ID %5d):%s - ' % (time.ctime(), process_name, os.getpid(), ' ' * (column_width - len(process_name)))


# ----------------------------------------------
# socket communications management primitives
# ----------------------------------------------

def instantiate_TCP_client_socket(server_address):
    """  configure a nonblocking socket at specified host and port
         inputs:
         -.  server_address:  (host, port) for socket service access point, as pair
         returns the configured socket
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except Exception as err:
        raise OSError("couldn't instantiate TCP socket")
    print('connecting to {} port {}'.format(*server_address))
    try:
        sock.connect(server_address)
        return sock
    except Exception as err:
        syndrome = "couldn't connect to %s, port %d: %s" % (server_address[0], server_address[1], err_to_str(err))
        raise OSError(syndrome)


def send_message_with_initial_byte_count(sock, message, byte_count_size=BYTES_PER_SHORT):
    """ send message, prefixed by a standard-network-order byte count,
        verifying that the byte count is byte_count_size bytes in length
    """

    # msg_package_map[]
    encoded_message = json.dumps(message).encode()
    potential_syndrome = "?? excessive length (%d) for outgoing text (%s)" % (len(encoded_message), message)
    assert (bytes_in_representation(len(encoded_message)) <= byte_count_size), potential_syndrome
    #
    # finally, send outgoing byte count, followed by message
    #
    sock.send(socket.htons(len(encoded_message)).to_bytes(byte_count_size, byteorder=sys.byteorder,
                                                          signed=False) + encoded_message)


def receive_message_with_initial_byte_count(sock, residue=b'', byte_count_size=BYTES_PER_SHORT):
    """ receive message, prefixed by a standard-network-order byte count.
    """
    # ---------------------------------------------------------------------------------------------
    def receive_k_bytes(k=BYTES_PER_SHORT, residue=b''):
        """ receive k bytes from socket connection sock, from which residue bytes have previouisly been extracted
            -. account for residue required because messages can be delivered in irregularly sized packets
            -. treat bytes in residue as initial part of data received
            -. return the k byte sequence received, plus the residue
        """
        while len(residue) < k:
            try:
                chunk = sock.recv(k - len(residue))
            except OSError:
                raise RuntimeError("socket connection broken")
            if chunk == b'':
                raise RuntimeError("socket connection broken")
            residue = residue + chunk
        result, residue = residue[:k], residue[k:]
        return result

    # ---------------------------------------------------------------------------------------------
    # first, get byte count for message, correcting for network order; then, get message proper
    byte_count = socket.ntohs(int.from_bytes(receive_k_bytes(byte_count_size), byteorder=sys.byteorder, signed=False))
    return (receive_k_bytes(byte_count).decode(), residue)


# +++++++++++++++++++++++++++++++++++++++++++++++++++++
# socket communications management thread
# +++++++++++++++++++++++++++++++++++++++++++++++++++++
def receive_messages_from_server(connection):
    """ receive messages from server indefinitely
        -.  connection - connection to use for receiving messages
    """
    message_residue = b''
    try:
        while True:
            (server_text, message_residue) = receive_message_with_initial_byte_count(sock, message_residue)
            display_message (json.loads(server_text))
    except RuntimeError:
        return


def display_message(msg):
    global my_handle
    my_handle = msg['to']['handle']
    if msg['from']["handle"]:
        sender = msg['from']["handle"]
    else:
        if msg['from']["socket"] == sock.getsockname():
            sender = "me"
        else:
            sender = msg['from']["handle"] or msg['from']["socket"][0] + ":" + str(msg['from']["socket"][1])
    padding = " "*(40-len(msg['payload']))
    print("{}{}  <<<<{}".format(msg['payload'],padding,sender))


def parse_user_input(msg):
    out_message = {"from": {"socket": sock.getsockname(), "handle": my_handle},
                   "send_time": time.time(),
                   "payload": msg}
    return out_message


def get_user_input():
    msg = input()
    return msg


class Client_server(object):

    def __init__(self):

        self.handle = ""


# ===============================================
#    Program Main
# ===============================================
#
# ---------------------------------------
#   define what to send to the server
# ---------------------------------------
#

# ---------------------------------------
#   define what to send to the server
# ---------------------------------------
#

# get name of self for error messages
#
my_name = multiprocessing.current_process().name
me = lambda: message_header(my_name, len(my_name))
debug_mode = False
# use current time to seed random number generator, making thread sleep times quasi-nondeterministic
#
random.seed()

try:
    # set up to acquire arguments from command line
    parser = argparse.ArgumentParser()
    parser.add_argument('-host', '--server-host', type=hostname_parser, dest='server_host', default=None, )
    parser.add_argument('-ip', '--server-IP', type=IPv4_addr_parser, dest='server_IP', default=None, )
    parser.add_argument('-port', '--server-port', type=port_parser, dest='server_port', default=DEFAULT_PORT, )

    # parse the arguments, filling out the lists of parameters for thread launch
    parsed_args = parser.parse_args()

    # postprocess host, IP arguments to set default / validate consistency, depending on what's there
    if parsed_args.server_IP is None:
        try:
            parsed_args.server_IP = socket.gethostbyname(DEFAULT_HOST) if parsed_args.server_host is None else \
            parsed_args.server_host[1]
        except OSError as err:
            raise OSError('invalid hostname (%s): %s' % (parsed_args.server_host[0], err_to_str(err)))
    else:
        specified_IP, specified_host, actual_IP = parsed_args.server_host[1], parsed_args.server_host[
            0], parsed_args.server_IP
        syndrome = "specified IP address (%s) for specified server host (%s) differs from actual IP address (%s)" % specified_IP, specified_host, actual_IP
        assert parsed_args.server_host[1] == parsed_args.server_IP, syndrome

    # --------------------------------------------------
    #  Set up socket for communications with server
    # --------------------------------------------------
    sock = instantiate_TCP_client_socket((parsed_args.server_IP, parsed_args.server_port))

    # --------------------------------------------------------------------------------
    #   launch concurrent thread to read messages from server;
    #   send messages to server, interspersed with delays
    # --------------------------------------------------------------------------------
    receiver_thread = threading.Thread(target=receive_messages_from_server, args=(sock,)).start()
    try:

        while True:

            msg = get_user_input( )
            if msg.lower() =="/exit":
                break
            msg = parse_user_input(msg)
            # display_message(msg)
            send_message_with_initial_byte_count(sock, msg)

            # for msg in client_content:
            #     time.sleep(random.uniform(MESSAGE_DELAY_MIN, MESSAGE_DELAY_MAX))
            #     msg = parse_user_input(msg)
            #     display_message(msg)
            #     send_message_with_initial_byte_count(sock, msg)
    except Exception as err:
        print('?? server terminated connection: %s' % err_to_str(err))
        raise
    #
    # end of exchange with server.  
    #
    sock.shutdown(socket.SHUT_RDWR)
    sock.close()
    if receiver_thread is not None:
        receiver_thread.join()

    print(me() + 'exiting -  Goodbye')

except Exception as err:
    print('?? ' + me() + 'aborting' + err_to_str(err))
    if debug_mode:
        raise

