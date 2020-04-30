#!/usr/bin/env python3

# Copyright 2018 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Server to mock SIBRA bandwidth reservations

Protocol:
one reservation per client
based on TCP, every message is terminated by a line break
C and S denote Client and Server respectively:

    Make a new reservation (handshake):
        C: RESV {{BW_CLS}} {{PATH}}
        S: GRANT {{BW_CLS}}

    The server can change a reservation at any time:
        S: GRANT {{BW_CLS}}

    The server can expire a reservation at any time:
        S: EXPIRE

    The server can clean a reservation at any time:
        S: CLEAN

    The server can drop a reservation at any time (quit):
        S: DROP

    Error handling: if the server encounters an error, it sends the following to the client:
        S: ERROR {{message}}

The server closes the connection after an EXPIRE, CLEAN or DROP.
"""

# CONFIG
DEFAULT_IP = '127.0.0.1'
DEFAULT_PORT = 10001
DEFAULT_BW_CLS = 4
# END CONFIG

import argparse
import inspect
import re
import socket
import socketserver
import sys
import threading
import time
from io import BytesIO


class ReservationManager:
    def __init__(self, default_bw_cls):
        self.default_bw_cls = default_bw_cls
        self.mutex = threading.Lock()
        self.client_counter = 0
        self.clients = {}

    def add(self, client_address, send, error, close):
        self.mutex.acquire()
        self.client_counter += 1
        client_id = self.client_counter
        self.clients[client_id] = {
            'send': send,
            'error': error,
            'close': close,
            'address': client_address,
        }
        self.mutex.release()
        return client_id

    def reserve(self, client_id, bw_cls, path):
        self.mutex.acquire()
        if client_id not in self.clients:
            print("Client ID {} invalid!".format(client_id))
            self.mutex.release()
            return

        if 'path' in self.clients[client_id]:
            self.clients[client_id]['error']('Handshake already performed')
            self.mutex.release()
            return

        print("Client {} [{}] requests bwCls {} on {}".format(client_id, self.clients[client_id]['address'], bw_cls, path))
        if bw_cls > args.default_bw_cls:
            bw_cls = args.default_bw_cls
            print("Can only grant {}".format(bw_cls))

        self.clients[client_id]['bw_cls'] = bw_cls
        self.clients[client_id]['path'] = path

        self.mutex.release()
        self.clients[client_id]['send']('GRANT {}'.format(bw_cls))

    def change(self, client_id, bw_cls):
        self.mutex.acquire()
        if client_id not in self.clients:
            print("Client ID {} invalid!".format(client_id))
            self.mutex.release()
            return

        self.clients[client_id]['bw_cls'] = bw_cls
        self.mutex.release()
        self.clients[client_id]['send']('GRANT {}'.format(bw_cls))
        print("Ok")

    def remove(self, client_id):
        self.mutex.acquire()
        if client_id not in self.clients:
            print("Client ID {} invalid!".format(client_id))
            self.mutex.release()
            return None, None

        send = self.clients[client_id]['send']
        close = self.clients[client_id]['close']
        del self.clients[client_id]
        self.mutex.release()
        return send, close

    def drop(self, client_id):
        send, close = self.remove(client_id)
        if callable(send):
            send('DROP')
            close()
            print("Ok")

    def expire(self, client_id, ):
        send, close = self.remove(client_id)
        if callable(send):
            send('EXPIRE')
            close()
            print("Ok")

    def clean(self, client_id):
        send, close = self.remove(client_id)
        if callable(send):
            send('CLEAN')
            close()
            print("Ok")


class SIBRAMocker(socketserver.BaseRequestHandler):
    """
    The request handler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def __init__(self, request, client_address, server):
        self.resv_mgr = server.resv_mgr
        self.client_id = self.resv_mgr.add(client_address[0], self.respond, self.error, self.close_socket)
        self.comm_mutex = threading.Lock()
        self.closed = False
        print("New client {}".format(self.client_id))
        super().__init__(request, client_address, server)

    def respond(self, message):
        self.comm_mutex.acquire()
        self.request.sendall((message + '\n').encode())
        self.comm_mutex.release()

    def error(self, message, line=None):
        if line is None:
            print(message)
        else:
            print('{} in {}'.format(message, line.strip()))
        self.respond('ERROR ' + message)

    def close_socket(self):
        self.request.shutdown(socket.SHUT_RDWR)
        self.request.close()
        self.closed = True

    def handle_line(self, line):
        line = line.decode()
        cmd = line.split(' ', 2)
        if cmd[0] == 'RESV' and len(cmd) == 3:
            bw_cls = cmd[1]
            path = cmd[2].strip()

            try:
                bw_cls = int(bw_cls)
            except ValueError:
                self.error('BW_CLS must be numeric', line)
            else:
                self.resv_mgr.reserve(self.client_id, bw_cls, path)
        else:
            self.error('unable to parse command', line)
            print(cmd)

    def handle(self):
        # self.request is the TCP socket connected to the client
        self.request.setblocking(False)
        with BytesIO() as buffer:
            # idea from https://stackoverflow.com/questions/29023885/python-socket-readline-without-socket-makefile
            while not self.closed:
                resp = b''
                try:
                    resp = self.request.recv(5)
                    if resp == b'':
                        break
                except BlockingIOError:
                    if len(buffer.getvalue()) == 0:
                        time.sleep(.2)

                if len(buffer.getvalue()) > 0 or len(resp) > 0:
                    buffer.write(resp)  # Write to the BytesIO object
                    buffer.seek(0)  # Set the file pointer to the SoF
                    start_index = 0  # Count the number of characters processed
                    for line in buffer:
                        if line[-1:] == b'\n':
                            start_index += len(line)
                            self.handle_line(line)

                    """ If we received any newline-terminated lines, this will be nonzero.
                        In that case, we read the remaining bytes into memory, truncate
                        the BytesIO object, reset the file pointer and re-write the
                        remaining bytes back into it.  This will advance the file pointer
                        appropriately.  If start_index is zero, the buffer doesn't contain
                        any newline-terminated lines, so we set the file pointer to the
                        end of the file to not overwrite bytes.
                    """
                    if start_index:
                        buffer.seek(start_index)
                        remaining = buffer.read()
                        buffer.truncate(0)
                        buffer.seek(0)
                        buffer.write(remaining)
                    else:
                        buffer.seek(0, 2)
            if not self.closed:
                self.resv_mgr.remove(self.client_id)


class CommandLineHandler:
    def __init__(self, resv_mgr, line):
        args = re.split('\s+', line.strip())
        if len(args) == 1 and args[0] == '':
            return

        cmd = args.pop(0)
        try:
            handler = getattr(self, cmd)
        except AttributeError:
            print("Unknown command {}".format(cmd))
            return

        if cmd[0] == '_' or not callable(handler):
            print("Unknown command {}".format(cmd))
            return

        signature = inspect.signature(handler)
        min_args = 0
        max_args = len(signature.parameters)
        for param in signature.parameters:
            if signature.parameters[param].default == inspect._empty:
                min_args += 1

        if len(args) < min_args or len(args) > max_args:
            print("Command {} requires at least {} and at most {} arguments".format(cmd, min_args, max_args))
            return

        self.resv_mgr = resv_mgr  # type: ReservationManager
        handler(*args)

    def list(self):
        self.resv_mgr.mutex.acquire()
        has_reservations = False
        for client_id in self.resv_mgr.clients:
            has_reservations = True
            if 'path' in self.resv_mgr.clients[client_id]:
                print("Client {}\tbw class {} via {}".format(
                    client_id,
                    self.resv_mgr.clients[client_id]['bw_cls'],
                    self.resv_mgr.clients[client_id]['path'],
                ))
            else:
                print("CLient {}\tidle".format(client_id))
        self.resv_mgr.mutex.release()

        if not has_reservations:
            print("No reservations")

    def change(self, client_id, bw_cls):
        try:
            bw_cls = int(bw_cls)
            client_id = int(client_id)
        except ValueError:
            print("ERROR: client and reservation ID and bw class must be numeric")
        else:
            self.resv_mgr.change(client_id, bw_cls)

    def drop(self, client_id):
        try:
            client_id = int(client_id)
        except ValueError:
            print("ERROR: client and reservation ID and bw class must be numeric")
        else:
            self.resv_mgr.drop(client_id)

    def clean(self, client_id):
        try:
            client_id = int(client_id)
        except ValueError:
            print("ERROR: client and reservation ID and bw class must be numeric")
        else:
            self.resv_mgr.clean(client_id)

    def expire(self, client_id):
        try:
            client_id = int(client_id)
        except ValueError:
            print("ERROR: client and reservation ID and bw class must be numeric")
        else:
            self.resv_mgr.expire(client_id)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Server to mock SIBRA bandwidth reservations.')
    parser.add_argument('--addr', metavar='IP', type=str, default=DEFAULT_IP, help='the IP address to listen')
    parser.add_argument('--port', metavar='P', type=int, default=DEFAULT_PORT, help='the port to listen')
    parser.add_argument('--default-bw-cls', metavar='C', type=int, default=DEFAULT_BW_CLS,
                        help='the default bwCls to provide right away')
    args = parser.parse_args()

    print('Starting server on %s:%d, providing reservations of up to bwCls %d' % (args.addr, args.port, args.default_bw_cls))
    server = socketserver.ThreadingTCPServer((args.addr, args.port), SIBRAMocker)
    server.resv_mgr = ReservationManager(args.default_bw_cls)
    threading.Thread(target=server.serve_forever).start()

    print('Use list, change, drop, clean and expire to manipulate reservations')
    try:
        for line in sys.stdin:
            CommandLineHandler(server.resv_mgr, line)
    except KeyboardInterrupt:
        pass

    print('Stopping server...')
    server.shutdown()
