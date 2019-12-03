import socketserver
import socket
import threading 
import time
import random
import queue
from nacl.encoding import Base64Encoder as naclb64
from nacl.public import PublicKey, PrivateKey, Box, SealedBox

server_priv = PrivateKey.generate()
server_pub = server_priv.public_key


class ProtoHandler(socketserver.BaseRequestHandler):
    def qprint(self, message):
        self.request.sendall(bytes(message+'\n','ascii'))

    def handle(self):
        global server_priv
        try:
            enc = self.request.recv(1024).strip().decode('ascii')
            # client_pub = PublicKey(client_pub, encoder=naclb64) 
            self.request.sendall(server_pub.encode(encoder=naclb64)+b'\n')
            enc = self.request.recv(4096).strip()
            sbox = SealedBox(server_priv)
            p = sbox.decrypt(enc).decode('ascii')
            print(p)


        except Exception as e:
            print(e)


class ThreadProtoServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

if __name__ == '__main__':
    host = '0.0.0.0'
    port = 9999

    server = ThreadProtoServer((host,port), ProtoHandler)
    try:
        with server:
            server_thread = threading.Thread(target=server.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            while True:
                time.sleep(1)
    except:
        server.shutdown()