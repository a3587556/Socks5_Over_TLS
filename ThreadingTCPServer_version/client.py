import socket, select, SocketServer, ssl
from pprint import pprint

TIME_OUT = 30
BUF_SIZE = 4096

class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer): pass

class Rsocks(SocketServer.StreamRequestHandler):
    def close_sock_and_exit(sock, remote):
        if sock:
            if not sock.close():
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
        if remote:
            if not remote.close():
                remote.shutdown(socket.SHUT_RDWR)
                remote.close()

    def redirect_tcp(self, sock, remote):
        fdset = [sock, remote]
        while True:
            r, w, e = select.select(fdset, [], [], TIME_OUT)
            data = ''
            for readable in r:
                data = readable.recv(BUF_SIZE)
                if data:
                    if readable == sock:
                        remote.send(data)
                    else:
                        sock.send(data)
                else:
                    break

    def handle(self):
        try:
            print "socks connected from ", self.client_address
            ss = self.connection
            ds = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.check_hostname = True
            ctx.load_default_certs()
            ssl_ds = ctx.wrap_socket(ds, server_hostname="your cert domain")
            try:
                ssl_ds.connect((dhost, dport))
                self.redirect_tcp(ss, ssl_ds)
            except Exception as e:
                print 'Error when redirecting !\r\n'
                ss.shutdown(socket.SHUT_RDWR)
                ss.close()

        except socket.error:
            print "socket error!\r\n"
            self.request.sendall(b'\x05\x01')
            try:
                self.request.shutdown(socket.SHUT_RDWR)
            except:
                self.request.close()

def main():
    global dhost
    global dport
    lhost = "127.0.0.1"
    lport = 1080
    dhost = "your server ip"
    dport = 443
    server = ThreadingTCPServer((lhost, lport), Rsocks, False)
    server.allow_reuse_address = True
    server.server_bind()
    server.server_activate()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()

if __name__ == '__main__':
    main()