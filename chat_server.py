# ====================================================================================================================
#   (04.1a) TCP multi-client listener process.py
#           use TCP select() mechanism to connect to and exchange data between multiple, concurrent client processes
#           communications protocol:
#           -.  individual messages each consists of a variable-length packet with fixed-size header
#               -.  header: a two-byte integer, encoded as a byte array, XDR-standard byte order
#               -.  body:  message proper, encoded as a byte array
#           -.  overall exchange
#               -.  server "opens for business", then
#               -.  repeatedly uses select() to service port activity,
#                   -.  handling connect requests by either
#                       -.  honoring new requests, up to the limit, or
#                       -.  sending an error message and closing the connection if at limit
#                   -.  handling incoming texts by writing them to all other connected clients,
#                       prefixed by originating client IP address, port
#               -.  continuing until all clients have disconnected
# -------------------------------------------------------------------------------------------------------------------
#   author: adapted from Doug Hellman, _The Python 3 Standard Library by Example_, by Phil Pfeiffer
#   last updated:  October 2018
# -------------------------------------------------------------------------------------------------------------
#   usage:
#       <program-name>  <server-port>  <maximum-clients>
#       command line arguments:
#           server-port:  integer in the range 0..65535, representing a port to contact
#               default:  DEFAULT_PORT, a program constant
#           max-clients:  positive integer, representing a maximum number of clients to service
#               default:  DEFAULT_MAX_CLIENT_COUNT, a program constant
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
# select -
#     select.select - return when one of a set of socket connections shows activity
# socket -
#     socket.accept - accept a connection with a remote host
#     socket.bind - associates a socket with a port
#     socket.close - closes socket connection
#     socket.getnameinfo - get host, port for open socket
#     socket.listen - set maximum number of simultaneous connections
#     socket.recv - receives data from opposite connection endpoint
#     socket.sendall - sends data to opposite connection endpoint, retrying until all data is sent or error is detected
#     socket.setblocking - when called with 0, opens socket as nonblocking.
#     socket.socket - instantiates a socket
# sys -
#     sys.byteorder - current platform's native byteorder
# time -
#     time.ctime - generate human readable time of day
#
import argparse
import multiprocessing
import os
import select
import socket
import sys
import time
import json
import re

# +++++++++++++++++++++++++++++++++++++++++++++
# supporting constants
# +++++++++++++++++++++++++++++++++++++++++++++
#
(MIN_TCP_PORT_NUM, MAX_TCP_PORT_NUM) = (1, 65535)  # range of values for valid port numbers

DEFAULT_HOST = 'localhost'  # default to server on this host
DEFAULT_PORT = 11000  # default to port 10000 on the server host
DEFAULT_CONCURRENT_CONNECTIONS = 1  # default to one connection at a time
DEFAULT_HANDLE_REGEX = r'^[a-z0-9-]{3,8}$'  #between 3 and 8 alpha-numeric character that can include hypen
(MIN_MAX_CLIENT_COUNT, MAX_MAX_CLIENT_COUNT) = (1, 10)  # range of values for valid simultaneous connection counts
DEFAULT_MAX_CLIENT_COUNT = 5  # default to 5 "live" connections at a time

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

def port_parser(string):
    """ parse and validate port for receiving client connections """
    try:
        portnum = int(string)
        if portnum < MIN_TCP_PORT_NUM:
            print('?? TCP port value (%d) too low; changing to %d' % (portnum, MIN_TCP_PORT_NUM))
        elif portnum > MAX_TCP_PORT_NUM:
            print('?? TCP port value (%d) too high; changing to %d' % (portnum, max(TCP_PORT_RANGE)))
        return max(min(portnum, MAX_TCP_PORT_NUM), MIN_TCP_PORT_NUM)
    except:
        syndrome = 'invalid port count: %s\ncount must be a positive integer in range %d - %d' % (
        string, MIN_TCP_PORT_NUM, MAX_TCP_PORT_NUM)
        raise argparse.ArgumentTypeError(syndrome)


def max_client_count_parser(string):
    """ parse and validate client count for limiting simultaneous client connections """
    try:
        max_client_count = int(string)
        if max_client_count < MIN_MAX_CLIENT_COUNT:
            print('?? maximum client count (%d) too low; changing to %d' % (max_client_count, MIN_MAX_CLIENT_COUNT))
        elif max_client_count > MAX_MAX_CLIENT_COUNT:
            print(
                '?? maximum client count (%d) too high; changing to %d' % (max_client_count, max(MAX_MAX_CLIENT_COUNT)))
        return max(min(max_client_count, MAX_MAX_CLIENT_COUNT), MIN_MAX_CLIENT_COUNT)
    except:
        syndrome = 'invalid maximum client count: %s\ncount must be a positive integer in range %d - %d' % (
        string, MIN_MAX_CLIENT_COUNT, MAX_MAX_CLIENT_COUNT)
        raise argparse.ArgumentTypeError(syndrome)


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


# +++++++++++++++++++++++++++++++++++++++++++++
# supporting classes - client processing
# +++++++++++++++++++++++++++++++++++++++++++++

class ClientConnection(object):
    """ manage a client socket's lifetime communications.
        Design notes:
        -.  Python's __getattr__ method has been used to delegate references to undefined attributes to
            this class's underlying socket object.
        -.  Using __setattr__ to delegate updates to undefined attributes to this class's underlying socket
            object would incur considerable additional complexity - e.g.,
            -.  using self.__dict__ to hold the names of attributes that should be resolved locally
            -.  using a step like setting an "is_initialized" flag in self.__dict__ to
                relative to self
        see http://code.activestate.com/recipes/389916-example-setattr-getattr-overloading/ for details
    """

    def __init__(self, serversocket, byte_count_size=BYTES_PER_SHORT):
        """ serversocket_ - the TCP server socket from which to obtain the client connection
            residue_from_previous_messages - leftover bytes from earlier communications received
            pending_messages - list of pending messages to send
        """
        self.socket_, self.ip = serversocket.accept()
        self.socket_.setblocking(False)
        self.handle = ''
        self.residue_from_previous_messages = b''
        self.pending_messages = []
        self.byte_count_size = byte_count_size
        self.__dict__['initialized_'] = True

    def socket(self):
        """ return connection's socket """
        return self.socket_

    def sockname(self):
        """ return host and port for server side of connection """
        return self.socket_.getsockname()

    def peername(self):
        """ return host and port for client side of connection """
        return self.socket_.getpeername()

    def recv(self):
        """ receive variable-length message from client. format: standard-network-order byte count, followed by message body """

        # ----------------------------------------------------------
        def receive_k_bytes(k=self.byte_count_size):
            """ receive k bytes from socket connection, from which residue bytes have previouisly been extracted
                -. account for residue required because messages can be delivered in irregularly sized packets
                -. treat bytes in residue as initial part of data received
                -. return the k byte sequence received, updating the residue
            """
            chunk = b''
            while len(self.residue_from_previous_messages) < k:
                try:
                    chunk = self.socket_.recv(k - len(self.residue_from_previous_messages))
                except ConnectionResetError as err:
                    print("{} {}".format(self.socket_.getpeername(), err))
                    # self.socket_.close()
                    raise

                if chunk == b'':
                    raise RuntimeError("socket connection broken")
                self.residue_from_previous_messages = self.residue_from_previous_messages + chunk
            result, self.residue_from_previous_messages = self.residue_from_previous_messages[
                                                          :k], self.residue_from_previous_messages[k:]
            return result

        # ----------------------------------------------------------
        # first, get byte count for message, correcting for network order; then, get message proper
        self.socket_.setblocking(True)
        byte_count_for_this_message = socket.ntohs( int.from_bytes(receive_k_bytes(), byteorder=sys.byteorder, signed=False))
        message = receive_k_bytes(byte_count_for_this_message)
        print('received {} from {}, port {}'.format (message, *self.peername()))
        self.socket_.setblocking(False)
        return message.decode()

    # -----------------------------------------------------------------
    # manage one receive action, updating connection_list as required
    # -----------------------------------------------------------------
    #

    def enqueue(self, message):
        """ enqueue message for send to client """
        self.pending_messages += [message]

    def send(self):
        """ send next enqueued variable-length message to client.
            format: standard-network-order byte count, followed by message body
        """
        if self.pending_messages:
            (this_message, self.pending_messages) = (self.pending_messages[0], self.pending_messages[1:])
            encoded_message = json.dumps(this_message).encode()
            if bytes_in_representation(len(encoded_message)) > self.byte_count_size:
                raise RuntimeError(
                    "?? excessive length (%d) for outgoing text (%s)" % (len(encoded_message), this_message))
            #
            # finally, send outgoing byte count, followed by message
            #
            self.socket_.sendall(
                socket.htons(len(encoded_message)).to_bytes(self.byte_count_size, byteorder=sys.byteorder, signed=False) + encoded_message)

    def close(self):
        """ close connection, warning if unsent messages are present """
        if self.pending_messages:
            print("?? closing client socket with unsent messages. message list follows. ")
            for message in self.pending_messages:
                print("*** ", message)
        self.socket_.shutdown(socket.SHUT_RDWR)
        self.socket_.close()

    # delegate other attribute references to the underlying socket object
    #
    def __getattr__(self, attr):
        return getattr(self.socket_, attr)

    def __setattr__(self, attr, value):
        if not self.__dict__.get('initialized_', False):  return super(ClientConnection, self).__setattr__(attr, value)
        if attr in self.__dict__:  return super(ClientConnection, self).__setattr__(attr, value)
        return super(ClientConnection, self).__setattr__(self.socket_, value)


# a simple-minded implementation of a list that allows for socket extraction and lookups.
# problem:  the connections routine would be more efficient with a reverse sockets-to-connections dict.
# to implement this improvement would require
# -.  revising __init__ to take a second, sockets-to-connections dict
# -.  revising __getslice__ to extract the appropriate subdict when the list is sliced
# -.  overloading append(), insert(), remove(), and __delitem__ to incrementally modify sockets-to-connections dict
# see https://docs.python.org/3/reference/datamodel.html#emulating-container-types for details.
#




class ClientConnectionList(list):
    """ manage a list of client sockets """

    def __init__(self, connection_list=[]):
        """
        __init__ parameters:
            connection_list - client objects to store in the list
        """
        super().__init__(connection_list)

    def sockets(self):
        """ extract the list of socket objects proper from the connection objects """
        return [connection.socket() for connection in self]

    def get_client_by_socket(self, socket):
        """ extract the appropriate connection object from the list, based on the socket """
        candidate_connection_objects = [connection for connection in self if connection.socket() is socket]
        assert len(candidate_connection_objects) != 0, "?? socket %s not found in list of client objects" % socket
        assert len(
            candidate_connection_objects) == 1, "?? socket %s appears in list of client objects multiple times" % socket
        return candidate_connection_objects[0]

    def get_client_by_handle(self, handle):
        """ extract the appropriate connection object from the list, based on the handle """
        candidate_client_objects = [client for client in self if client.handle == handle]
        assert len(  candidate_client_objects) < 2, "?? socket %s appears in list of client objects multiple times" % handle
        if candidate_client_objects:
            return candidate_client_objects[0]
        return None

    def __getitem__(self, item):
        result = list.__getitem__(self, item)
        try:
            return ClientConnectionList(result)
        except TypeError:
            return result

    def __delitem__(self, item):
        result = list.__delitem__(self, item)
        try:
            return ClientConnectionList(result)
        except TypeError:
            return result

    def __getslice__(self, i, j):
        return ClientConnectionList(list.__getslice__(self, i, j))

    def __add__(self, other):
        return ClientConnectionList(list.__add__(self, other))

    def __mul__(self, other):
        raise RuntimeError("socket replication not supported")

    def __str__(self):
        return list.__str__([str(self[i]) for i in range(len(self))])

    # ===============================================
    #    Program Main
    # ===============================================
    #
    # what to combine with the client
    #
    # get name of self for error messages
    #


class ChatServer(object):

    def __init__(self, server_host, server_port, max_client, regex_pattern):
        """inputs:
             -.  server_address:  (host, port) for socket service access point, as pair
             -.  client_count:    number of incoming connections to support
        """
        self.host = server_host
        self.server_port = server_port
        self.client_count = max_client
        self.regex_pattern = regex_pattern
        self.server_address = (self.host, self.server_port)
        self.clients = ClientConnectionList()
        #create a map of messages to functions
        self.msg_map = { "C2C": self.request_c2c,
                         "C2G": self.request_c2g,
                         "C2S": self.request_c2s
                         }

    def instantiate_server_socket(self):

        """  configure a nonblocking socket at specified host and port

             returns the configured socket
        """
        # instantiate the socket
        try:
            my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except Exception as err:
            raise OSError('could not instantiate TCP socket')

        #  bind this socket to the specified port
        try:
            my_socket.bind(server_address)
        except Exception as err:
            raise OSError('could not bind to %s, port %d: %s' % (*self.server_address, err_to_str(err)))

        #  specify number of simultaneous clients to support
        try:
            my_socket.listen(self.client_count)
        except Exception as err:
            raise OSError('could not connect to %s, port %d: %s' % (*self.server_address, err_to_str(err)))

        self.server_socket = my_socket

        return my_socket

    def run_server(self):

        # -----------------------------------------------------------------------------------
        #  obtain a first client, adding it to the list of current_clients
        # -----------------------------------------------------------------------------------
        self.get_new_connection(first_conn=True)
        # -----------------------------------------------------------------------------------
        #    Look for requests from interested clients,
        #    -.  fielding connection requests, up to limit -
        #        and closing connections beyond limit, with error messages
        #    -.  pushing sent content to other clients, prepended with connection information
        # ------------------------------------------------------------------------------------
        while True:

                # need try/except block because aborting connections generates exceptions that bypass select
            try:
                if self.clients:
                # check for channel activity
                    try:
                        (connection_request, recvable_sockets, sendable_sockets,  problem_client_sockets) = self.get_sockets_activity()
                    except:
                        break

                    # check for connection requests
                    if connection_request:
                        self.get_new_connection()

                    # drop clients for sockets that have encountered exceptions
                    for problem_client in [self.clients.get_client_by_socket(socket) for socket in problem_client_sockets]:
                        self.manage_problem_client(problem_client)
                        if problem_client.socket() in recvable_sockets: recvable_sockets.remove(problem_client.socket())
                        if problem_client.socket() in sendable_sockets: sendable_sockets.remove(problem_client.socket())

                    # obtain messages from active clients, enqueuing them to send to other clients
                    for client in [self.clients.get_client_by_socket(socket) for socket in recvable_sockets]:
                        try:
                            self.manage_read_request(client)
                        except SyntaxError as err:
                            pass
                        except Exception as err:
                            if client.socket() in recvable_sockets:
                                recvable_sockets.remove(client.socket())
                            if client.socket() in sendable_sockets:
                                sendable_sockets.remove(client.socket())
                            print("removing disconnected {} from clients".format(client.getpeername()))
                            client.close()
                            self.clients.remove(client)
                            # pass

                    # check for messages to send and the ability to send them
                    for client in [self.clients.get_client_by_socket(socket) for socket in sendable_sockets]:
                            self.manage_send_request(client)


                    time.sleep(0.1)
                else:
                    self.get_new_connection(first_conn=True)

            except Exception as err:
                raise

        self.shut_down_server()
        # halt all remaining dialogues with clients, if any


    def shut_down_server(self):
        for client in self.clients:
            client.close()

        # end of all exchanges
        self.server_socket.close()
        print(me() + 'exiting')

    def get_new_connection(self, first_conn=False):

        if first_conn:
            self.server_socket.setblocking(True)
            print('No clients connected - listening for connections on {} at port {}'.format(*self.server_address))
            new_conn = ClientConnection(self.server_socket)
            self.add_connection(new_conn)
            self.server_socket.setblocking(False)
        elif len(self.clients.sockets()) < parsed_args.max_client_count:
            new_conn = ClientConnection(self.server_socket)
            self.add_connection(new_conn)
        else:
            new_conn = ClientConnection(self.server_socket)
            self.reject_connection(new_conn)

    def reject_connection(self, new_conn):
        syndrome = "client limit (%d) exceeded" % self.client_count
        print('refusing connection from %s, port %s; %s' % (*new_conn.peername(), syndrome))
        # alert rejected client to the refusal
        self.send_s2c(new_conn, "?? refusing connection: %s" % syndrome)
        new_conn.close()

    def add_connection(self, new_conn):
        self.clients += [new_conn]
        payload = """Welcome to OOChat
        COMMANDS: 
        @<handle_name>        - to send a direct message to <handle_name>
        /handle:<handle_name> - to set handle
        /list_handles         - to see handles of all users in chat
        /exit                 - to exit"""
        self.send_s2c(new_conn, payload)
        print("{}, {} added".format(*new_conn.peername()))

    @staticmethod
    def func_not_found():  # just in case we dont have the function
        raise("No Function Found!")

    def manage_read_request(self, client):
        """  try to accept and print incoming message from client
             -.  on success, enqueue it for remaining clients
             -.  on failure, issue error message, remove client from connection_list,
                 and propagate exception to caller for further corrective action
        """

        # obtain the message
        message = client.recv()
        message = json.loads(message)
        msg = message["payload"].strip()
        if msg.startswith("/"):
            type = "c2s"
        elif msg.startswith("@"):
            type = "c2c"
        else:
            type = "c2g"

        func = getattr(self, "request_"+type)
        func(client, message)
        # self.msg_map[message['type']](client, message)

    def request_c2c(self, from_client, data):
        if from_client.handle:
            to_handle = data["payload"].split(" ")[0]
            client = self.clients.get_client_by_handle(to_handle)
            if client:
                data["to"] = {"socket": client.getpeername(), "handle": client.handle}
                data["payload"] = " ".join(data["payload"].split(" ")[1:])
                client.enqueue(data)
            else:
                self.send_s2c(from_client, "client {} does not exit or is disconnected".format(to_handle))
        else:
            self.send_s2c(from_client, "set your handle using /handle:<handle_name> before sending a direct message")

    def request_c2g(self, from_client, data):
        # enqueue it for resend
        for other_client in [c for c in self.clients if c is not from_client]:
            data["to"] = {"socket": other_client.getpeername(), "handle": other_client.handle}
            other_client.enqueue(data)

    def request_c2s(self, from_client, data):
        # TODO: parse the command for errors here
        try:
            msg = data['payload']

            func = getattr(self, "command_"+msg.split(":")[0][1:])
            func (from_client, msg.strip())
        except:
            msg='invalid command syntax'
            self.send_s2c(from_client,"error:"+msg)
            raise SyntaxError(msg)

    def command_handle(self,from_client, msg):
        handle = msg.split(":")[1].strip()
        if not re.match(self.regex_pattern, handle):
            self.send_s2c(from_client, "{} is invalid handle format".format(handle))
        elif [c for c in self.clients if c.handle == "@"+handle]:
            self.send_s2c(from_client, "{} already exit. choose another handle".format(handle))
        else:
            from_client.handle =  "@"+handle
            self.send_s2c(from_client, "Success!. Your new handle is {}".format(from_client.handle))

    def command_list_handles(self, from_client, handle):
        handles =  [c.handle for c in self.clients if c.handle]
        self.send_s2c(from_client, "\n".join(handles) or "No user with registered handles")


    def send_s2c(self, client, payload):
        out_message = { "from": { "socket": self.server_address, "handle": "chatserver"},
                        "to": {"socket": client.getpeername(), "handle": client.handle},
                        "send_time": time.time(),
                        "type": "s2c",
                        "payload": payload
                        }
        client.enqueue(out_message)
        client.send()

    # -----------------------------------------------------------------
    # manage one send action, updating connection_list as required
    # -----------------------------------------------------------------
    #
    def manage_send_request(self, client):
        """  try to output message to this client
             -.  on failure, issue error message, remove client from connection_list,
                 and propagate exception to caller for further corrective action
        """
        try:
            client.send()
        except Exception as err:
            # condition, when encountered, denotes socket closing
            (this_client_host, this_client_port) = client.getpeername()
            print('closing connection from {}, port {} - {}'.format(this_client_host, this_client_port, err_to_str(err)))
            client.close()
            self.clients.remove(client)
            raise
    # ---------------------------------------------------------------------------
    # manage one problem client action, updating connection_list as required
    # ---------------------------------------------------------------------------
    #
    def manage_problem_client(self, problem_client):
        """  issue error message, then shut down the problem connection, removing it from the active connection list """
        (problem_client_host, problem_client_port) = problem_client.getpeername()
        print('exception for %s, port %s: closing connection' % (problem_client_host, problem_client_port))
        problem_client.close()
        self.clients.remove(problem_client)

    # -----------------------------------------------------
    # wrapper for "select from active sockets" function
    # -----------------------------------------------------
    #
    def get_sockets_activity(self, timeout=None):
        """ select.select() provides a fairly ratty, undifferentiated interface.
            clean it up by
            -.  preprocessing socket inputs per what select.select() wants, then
            -.  throwing an exception if the server_socket is in the problem sockets
            -.  breaking result down into four categories:
                -.  open connection requests
                -.  "receive content" requests
                -.  channels that are free to receive responses
                -.  channels that have detectable anomalies
        """
        client_sockets = self.clients.sockets()
        all_channels = all_request_channels = [self.server_socket] + client_sockets
        (active_sockets, available_response_channels, problem_sockets) = select.select(all_request_channels,
                                                                                       client_sockets, all_channels,
                                                                                       timeout)
        if self.server_socket in problem_sockets:
            raise OSError('?? server socket failure')

        return (
            self.server_socket in active_sockets,
            [socket for socket in active_sockets if socket is not self.server_socket],
            available_response_channels,
            [socket for socket in problem_sockets if socket is not self.server_socket]
        )


# ===============================================
#    Program Main
# ===============================================
#
# what to combine with the client
#
# get name of self for error messages

debug_mode = False
my_name = multiprocessing.current_process().name
me = lambda: message_header(my_name, len(my_name))

try:
    # set up to acquire arguments from command line
    #
    parser = argparse.ArgumentParser()
    parser.add_argument('-port', '--server-port', type=port_parser, dest='server_port', default=DEFAULT_PORT, )
    parser.add_argument('-maxc', '--max-client-count', type=max_client_count_parser, dest='max_client_count', default=DEFAULT_MAX_CLIENT_COUNT, )
    parser.add_argument('-regex', '--handle-regex', type=str, dest='regex', default=DEFAULT_HANDLE_REGEX, )

    # parse the arguments, filling out the lists of parameters for thread launch
    #
    parsed_args = parser.parse_args()
    possible_syndrome = "?? invalid client count parameter (%d) - must be a positive integer" % parsed_args.max_client_count
    assert parsed_args.max_client_count > 0, possible_syndrome

    server_address = (DEFAULT_HOST, parsed_args.server_port)

    server = ChatServer(DEFAULT_HOST, parsed_args.server_port, parsed_args.max_client_count + 1, parsed_args.regex)
    server.instantiate_server_socket()
    server.run_server()

except Exception as err:
    print('?? ' + me() + 'aborting' + err_to_str(err))
    if debug_mode:
        raise

# http://code.activestate.com/recipes/531824-chat-server-client-using-selectselect/
# https://github.com/antoineFrau/python-chat/blob/master/ChatServer.py
# https://github.com/stephenmcd/grillo/blob/master/grillo.py