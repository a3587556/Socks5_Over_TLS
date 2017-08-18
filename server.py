import gevent
from gevent import monkey
from gevent.pool import Pool
from gevent import select
from gevent.server import StreamServer
from gevent import socket
import ssl
from crypto.sodium import SodiumAeadCrypto
import time
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
    print '''Usage: ./server.py l:port
Usage: ./server.py l:host:port'''

class SockV5Server(object):

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.pool = Pool(1000)
        self.server = StreamServer((self.host, self.port),
                                   self.handler, server_side=True,
                                     certfile='your crt',
                                     keyfile='you key',
                                     ssl_version=ssl.PROTOCOL_TLSv1)

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

    def deciper_msg(self, msg):
        decipher = SodiumAeadCrypto('chacha20-ietf-poly1305',
                                     b'k' * 32, b'i' * 32, 0)
        de_msg = decipher.decrypt_once(msg)
        return de_msg

    def ciper_msg(self, msg):
        cipher = SodiumAeadCrypto('chacha20-ietf-poly1305',
                                  b'k' * 32, b'i' * 32, 1)
        data = cipher.encrypt_once(msg)
        return data

    def recv_all_data(self,sock):
        encry_data = []
        while True:
            temp_date = sock.recv(BUFFER)
            if temp_date == '':
                break
            else:
                encry_data.append(temp_date)
        return ''.join(encry_data)

    def process_sock_request(self, client_sock):
        recv = client_sock.recv(BUFFER)
        if len(recv) > 0:
            recv = self.deciper_msg(recv)
            addr_type = ord(recv[0])
            if addr_type == ATYP_IP_V4:
                addr = socket.inet_ntoa(recv[1:5])
            elif addr_type == ATYP_DOMAINNAME:
                addr_len = ord(recv[1])
                addr = socket.gethostbyname(recv[2:2 + addr_len])
            else:
                print 'exit'
                # only ipv4 addr or domain name is supported.
                self.close_sock_and_exit(client_sock)
            port = ord(recv[-2]) * 256 + ord(recv[-1])
            return self.connect_target_server_and_reply(client_sock,
                                                                   addr, port)
        else:
            self.close_sock_and_exit(client_sock)

    def connect_target_server_and_reply(self, client_sock, addr, port):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server_sock.connect((addr, port))
            send_msg = self.ciper_msg('\x0a\x18')
            client_sock.sendall(send_msg)
        except Exception:
            print 'server %s connect error' % addr
            send_msg = self.ciper_msg('\x0a\x17')
            client_sock.sendall(send_msg)
            self.close_sock_and_exit(client_sock)

        return server_sock

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

        if flag == 'to_server':
            msg_len = ord(recv[0])* 256 + ord(recv[1])
            self.msg_recv_buff = recv[2:]
            recv_len = len(self.msg_recv_buff)
            while recv_len < msg_len:
                msg = recv_sock.recv(BUFFER)
                self.msg_recv_buff += msg
                recv_len += len(msg)

            msg = self.deciper_msg(self.msg_recv_buff)
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
        #self.process_version_and_auth(client_sock)
        server_sock = self.process_sock_request(client_sock)
        self.piping_client_and_target(client_sock, server_sock)

    def serve_forever(self):
        self.server.serve_forever()


if '__main__' == __name__:
    arg = sys.argv
    if len(arg) != 2:
        _usage()
        sys.exit(1)
    lhost = "127.0.0.1"
    targv = sys.argv[1]
    s = targv.split(":")
    if len(s) == 2 and (s[0] == "l" or s[0] == "L"):  # l:port
        lport = int(s[1])
    elif len(s) == 3 and (s[0] == "l" or s[0] == "L"):  # l:host:port
            lhost = s[1]
            lport = int(s[2])
    else:
        _usage()
        sys.exit(1)

    print time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()), 'Server started ...'
    sock_v5_server = SockV5Server(lhost, lport)
    sock_v5_server.serve_forever()
    sys.exit(0)