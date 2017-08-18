import gevent
from gevent import monkey
from gevent.pool import Pool
from gevent import select
from gevent.server import StreamServer
from gevent import socket
import struct
from pprint import pprint
from crypto.sodium import SodiumAeadCrypto
import random
import ssl

BUFFER = 1024

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1', 12345))
send_msg = '\x05\x01\x00'
sock.sendall(send_msg)
recv = sock.recv(2)
if recv == '\x05\x00':
    send_msg = '\x05\x01\x00\x03\x09baidu.com\x01\xbb'
    sock.sendall(send_msg)
    recv = sock.recv(BUFFER)
    if recv[:4] == '\x05\x00\x00\x01':
        send_msg = '123456789a'
        sock.sendall(send_msg)
        recv = sock.recv(BUFFER)
        print recv



