import gevent
from gevent import monkey
from gevent.pool import Pool
from gevent import select
from gevent.server import StreamServer
from gevent import socket
import ssl
import sys


monkey.patch_all()

BUFFER = 4096
SOCK_V5 = 5
RSV = 0
ATYP_IP_V4 = 1
ATYP_DOMAINNAME = 3
CMD_CONNECT = 1
IMPLEMENTED_METHODS = (2, 0)

def _usage():
    print 'Usage: ./client.py l:port c:host:port'

class SockV5Server(object):

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.pool = Pool(1000)
        self.server = StreamServer((self.host, self.port),
                                   self.handler)

    def close_sock_and_exit(self, client_sock=None, server_sock=None):
        if client_sock:
            if not client_sock.closed:
                try:
                    client_sock.shutdown(socket.SHUT_RDWR)
                except Exception:
                    client_sock.close()

        if server_sock:
            if not server_sock.closed:
                try:
                    server_sock.shutdown(socket.SHUT_RDWR)
                except Exception:
                    server_sock.close()

        g = gevent.getcurrent()
        g.kill()

    def piping_client_and_target(self, client_sock, server_sock):
        inputs = [client_sock, server_sock]
        while True:
            try:
                in_ready, out_ready, ex_ready = select.select(inputs, [], [])
                for sock in in_ready:
                    if sock == client_sock:
                        self.recv_and_send_msg(client_sock, server_sock)
                    elif sock == server_sock:
                        self.recv_and_send_msg(server_sock, client_sock)
            except Exception:
                self.close_sock_and_exit(client_sock, server_sock)

    def recv_and_send_msg(self, recv_sock, send_sock):
        # recv() is a block I/O in the views of programmer, it returns '' when
        # remote has been closed.
        msg = recv_sock.recv(BUFFER)
        if msg == '':
            self.close_sock_and_exit(recv_sock, send_sock)
        send_sock.sendall(msg)

    def handler(self, client_sock, address):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = False
        ctx.load_default_certs()
        ssl_server_sock = ctx.wrap_socket(server_sock)
        try:
            ssl_server_sock.connect((dhost, dport))
            self.piping_client_and_target(client_sock, ssl_server_sock)
        except Exception:
            send_msg = '\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00'
            client_sock.sendall(send_msg)
            self.close_sock_and_exit(client_sock)    

    def serve_forever(self):
        self.server.serve_forever()


if '__main__' == __name__:
    arg = sys.argv
    if len(arg) != 3:
        _usage()
        sys.exit(1)
    global dhost
    global dport
    lhost = "127.0.0.1"
    targv = [sys.argv[1], sys.argv[2]]
    for i in [0, 1]:
        s = targv[i].split(":")
        if len(s) == 2 and (s[0] == "l" or s[0] == "L"): #l:port
            lport = int(s[1])
        elif len(s) == 3 and (s[0] == "c" or s[0] == "C"): # c:host:port
            dhost = s[1]
            dport = int(s[2])
        else:
            _usage()
            sys.exit(1)

    sock_v5_server = SockV5Server(lhost, lport)
    sock_v5_server.serve_forever()
    sys.exit(0)