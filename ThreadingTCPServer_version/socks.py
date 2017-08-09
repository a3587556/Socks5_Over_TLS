import socket, sys, select, SocketServer, struct, time
import ssl, _ssl

class MySSL_TCPServer(SocketServer.TCPServer):
    def __init__(self, server_address, RequestHandlerClass, certfile, keyfile, ssl_version=ssl.PROTOCOL_TLSv1,
                 bind_and_activate=False):
        SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
        self.certfile = certfile
        self.keyfile = keyfile
        self.ssl_version = ssl_version

    def get_request(self):
        newsocket, fromaddr = self.socket.accept()
        connstream = ssl.wrap_socket(newsocket, server_side=True,
                                     certfile=self.certfile,
                                     keyfile=self.keyfile,
                                     ssl_version=self.ssl_version)
        return connstream, fromaddr

class ThreadingTCPServer(SocketServer.ThreadingMixIn, MySSL_TCPServer): pass

class Socks5Server(SocketServer.StreamRequestHandler):
    def close_sock_and_exit(self, sock, remote):
        if sock:
            if not sock.close():
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
        if remote:
            if not remote.close():
                remote.shutdown(socket.SHUT_RDWR)
                remote.close()

    def handle_tcp(self, sock, remote):
        fdset = [sock, remote]
        while True:
            r, w, e = select.select(fdset, [], [])
            if sock in r:
                if remote.send(sock.recv(4096)) <= 0:
                    self.close_sock_and_exit(sock, remote)
                    break
            if remote in r:
                if sock.send(remote.recv(4096)) <= 0:
                    self.close_sock_and_exit(sock, remote)
                    break

    def handle(self):
        try:
            print 'socks connection from ', self.client_address
            sock = self.connection
            # 1. Version
            sock.recv(262)
            sock.send(b"\x05\x00");
            # 2. Request
            data = self.rfile.read(4)
            mode = ord(data[1])
            addrtype = ord(data[3])
            if addrtype == 1:  # IPv4
                addr = socket.inet_ntoa(self.rfile.read(4))
            elif addrtype == 3:  # Domain name
                addr = self.rfile.read(ord(sock.recv(1)[0]))
            port = struct.unpack('>H', self.rfile.read(2))
            reply = b"\x05\x00\x00\x01"
            try:
                if mode == 1:  # 1. Tcp connect
                    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    remote.connect((addr, port[0]))
                    print 'Tcp connect to', addr, port[0]
                else:
                    reply = b"\x05\x07\x00\x01"  # Command not supported
                #local = remote.getsockname()
                #reply += socket.inet_aton(local[0]) + struct.pack(">H", local[1])
                reply += addr + port[0]
            except socket.error:
                # Connection refused
                reply = '\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00'
            sock.send(reply)
            # 3. Transfering
            if reply[1] == '\x00':  # Success
                if mode == 1:  # 1. Tcp connect
                    self.handle_tcp(sock, remote)
        except socket.error:
            print 'socket error'


def main():
    server = ThreadingTCPServer(('0.0.0.0', 443), Socks5Server, "your.crt", "your.key")
    server.allow_reuse_address = True
    server.server_bind()
    server.server_activate()
    server.serve_forever()


if __name__ == '__main__':
    main()
