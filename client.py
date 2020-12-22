import gevent
from gevent import monkey
from gevent.pool import Pool
from gevent import select
from gevent.server import StreamServer
from gevent import socket
from crypto.sodium import SodiumAeadCrypto
import ssl
import sys
import time


monkey.patch_all()

BUFFER = 4096
SOCK_V5 = 5
RSV = 0
ATYP_IP_V4 = 1
ATYP_DOMAINNAME = 3
CMD_CONNECT = 1
IMPLEMENTED_METHODS = (2, 0)


def _usage():
    print '''Usage: ./client.py l:port c:host:port
Usage: ./client.py l:host:port c:host:port'''

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

    def process_version_and_auth(self, client_sock):
        recv = client_sock.recv(BUFFER)
        if len(recv) > 0:
            if ord(recv[0]) != SOCK_V5:
                self.close_sock_and_exit(client_sock)

            method = None
            num_methods = ord(recv[1])
            methods = [ord(recv[i + 2]) for i in range(num_methods)]
            for imp_method in IMPLEMENTED_METHODS:
                if imp_method in methods:
                    method = imp_method
                    break

            if method is None:
                self.close_sock_and_exit(client_sock)

            send_msg = '\x05' + chr(method)
            client_sock.send(send_msg)

    def process_sock_request(self, client_sock):
        recv = client_sock.recv(BUFFER)
        if len(recv) > 0:
            send_buff = recv[3:]
            cmd = ord(recv[1])
            if cmd == CMD_CONNECT:
                # Only connect cmd is supported.
                server_sock = self.connect_target_server_and_reply(client_sock, send_buff)
            else:
                self.close_sock_and_exit(client_sock)

            return server_sock
        else:
            self.close_sock_and_exit(client_sock)

    def get_ssl_server_sock(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        ctx.load_default_certs()
        ssl_server_sock = ctx.wrap_socket(server_sock,server_hostname=dhost) # dhost is your cert domain name

        return ssl_server_sock

    def ciper_msg(self, msg):
        cipher = SodiumAeadCrypto('chacha20-ietf-poly1305',
                                  b'k' * 32, b'i' * 32, 1)
        data = cipher.encrypt_once(msg)
        return data

    def deciper_msg(self, msg):
        decipher = SodiumAeadCrypto('chacha20-ietf-poly1305',
                                     b'k' * 32, b'i' * 32, 0)
        try:
            de_msg =  decipher.decrypt_once(msg)
            return de_msg
        except Exception:
            print 'Decrypt data failed'
            return ''

    def connect_target_server_and_reply(self, client_sock, send_buff):
        ssl_server_sock = self.get_ssl_server_sock()
        try:
            ssl_server_sock.connect((dhost, dport))
        except Exception:
            print 'server %s connect error, maybe it closed!' % dhost
            self.close_sock_and_exit(client_sock)
        ssl_server_sock.sendall(self.ciper_msg(send_buff))

        recv = self.deciper_msg(ssl_server_sock.recv(BUFFER))
        if recv == '':
            self.close_sock_and_exit(client_sock, ssl_server_sock)

        if ord(recv[0]) == 10 and ord(recv[1]) == 24:
            send_msg = '\x05\x00\x00\x01\x00\x00\x00\x00\x0a\x17'
            client_sock.send(send_msg)
        else:
            print "Can't connect to the target"
            print ord(recv[0]),ord(recv[1])
            send_msg = '\x05\x01\x00\x01\x00\x00\x00\x00\x0a\x17'
            client_sock.send(send_msg)
            self.close_sock_and_exit(client_sock, ssl_server_sock)
        return ssl_server_sock

    def piping_client_and_target(self, client_sock, server_sock):
        inputs = [client_sock, server_sock]
        while True:
            try:
                in_ready, out_ready, ex_ready = select.select(inputs, [], [])
                for sock in in_ready:
                    if sock == client_sock:
                        self.recv_and_send_msg(client_sock, server_sock, flag='to_server')
                    elif sock == server_sock:
                        self.recv_and_send_msg(server_sock, client_sock, flag='to_client')
            except Exception:
                self.close_sock_and_exit(client_sock, server_sock)

    def recv_and_send_msg(self, recv_sock, send_sock, flag = None):
        # recv() is a block I/O in the views of programmer, it returns '' when
        # remote has been closed.
        recv = recv_sock.recv(BUFFER)
        if recv == '':
            # NOTE(deliang) there exists a bug here
            # the thread exits if either of the sockets is closed, which may
            # lose some packages sometimes.
            self.close_sock_and_exit(recv_sock, send_sock)

        if flag == 'to_client':
            msg_len = ord(recv[0]) * 256 + ord(recv[1])
            self.msg_recv_buff = recv[2:]
            recv_len = len(self.msg_recv_buff)
            while recv_len < msg_len:
                msg = recv_sock.recv(BUFFER)
                self.msg_recv_buff += msg
                recv_len += len(msg)

            msg = self.deciper_msg(self.msg_recv_buff)
            if len(msg) > 0:
                send_sock.sendall(msg)
        else:
            msg = self.ciper_msg(recv)
            msg_len = len(msg)
            msg_len_hex = self.msg_len_to_hex_string(msg_len)
            msg = msg_len_hex + msg
            send_sock.sendall(msg)
        

    def msg_len_to_hex_string(self, int_port):
        port_hex_string = chr(int_port / 256) + chr(int_port % 256)
        return port_hex_string

    def handler(self, client_sock, address):
        self.process_version_and_auth(client_sock)
        server_sock = self.process_sock_request(client_sock)
        self.piping_client_and_target(client_sock, server_sock)

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
        if len(s) == 2 and (s[0] == "l" or s[0] == "L"):  # l:port
            lport = int(s[1])
        elif len(s) == 3 and (s[0] == "l" or s[0] == "L"):  # l:host:port
            lhost = s[1]
            lport = int(s[2])
        elif len(s) == 3 and (s[0] == "c" or s[0] == "C"):  # c:host:port
            dhost = s[1]
            dport = int(s[2])
        else:
            _usage()
            sys.exit(1)
    print time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()), 'Client started ...'
    sock_v5_server = SockV5Server(lhost, lport)
    sock_v5_server.serve_forever()
    sys.exit(0)
