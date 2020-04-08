#!/usr/bin/env python3

import argparse
import socket
import time

# CONFIG
DEFAULT_IP = '127.0.0.1'
DEFAULT_PORT = 10001
DEFAULT_BW_CLS = 4
# END CONFIG


def fetch(s, n):
    i = 0
    while i < n:
        buf = s.recv(100)
        if buf == b'':
            print('Server closed connection')
            return
        print(buf)
        i += len(buf.split(b'\n')) - 1


parser = argparse.ArgumentParser(description='Client to test mock SIBRA server.')
parser.add_argument('--addr', metavar='IP', type=str, default=DEFAULT_IP, help='the IP address to connect to')
parser.add_argument('--port', metavar='P', type=int, default=DEFAULT_PORT, help='the port to connect to')

args = parser.parse_args()

print('Client to test server on %s:%d' % (args.addr, args.port))

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((args.addr, args.port))

    s.sendall(b'RESV 3 path 1\n')
    fetch(s, 5)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((args.addr, args.port))
    s.sendall(b'RESV 4 path 2\n')
    fetch(s, 1)

    s.sendall(b'RESV 5 path 3\n')
    fetch(s, 5)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((args.addr, args.port))
    s.sendall(b'RESV blubb path 1\n')
    fetch(s, 5)
