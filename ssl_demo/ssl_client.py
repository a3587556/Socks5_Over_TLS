# coding=utf-8
"""
desc..
    :copyright: (c) 2016 by fangpeng(@beginman.cn).
    :license: MIT, see LICENSE for more details.
"""
import socket
import ssl
from pprint import pprint

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
HOSTNAME = "127.0.0.1"
# Whether to try to verify other peers’ certificates and how to behave if verification fails.
# This attribute must be one of CERT_NONE, CERT_OPTIONAL or CERT_REQUIRED.
context.verify_mode = ssl.CERT_REQUIRED
# Wether to match the peer cert’s hostname with `match_hostname()` in `SSLSocket.do_handshake()`.
context.check_hostname = True

# Load CA used to validate other peers’ certificates when `verify_mode` is other than `CERT_NONE`.
#context.load_verify_locations('cert.pem')
context.load_default_certs()

ssl_sock = context.wrap_socket(s, server_hostname="v2.5inb4d.com")

ssl_sock.connect((HOSTNAME, 54321))

pprint(ssl_sock.getpeercert())

ssl_sock.send(b'a'*100)
data = ssl_sock.recv(1024)
print ("Received:", len(data), data)
ssl_sock.close()