import socket
import nacl.utils
from nacl.encoding import Base64Encoder as naclb64
from nacl.public import PublicKey, PrivateKey, Box, SealedBox

client_priv = PrivateKey.generate()
client_pub = client_priv.public_key

if __name__ == '__main__':
    HOST = 'localhost'
    PORT = 9999

    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        # s.send(client_pub.encode(encoder=naclb64)+b'\n')
        s.send(b'\n')
        x = s.recv(4096).replace(b'\n',b'')
        serv_key = PublicKey(x, encoder=naclb64)

        sbox = SealedBox(serv_key)
        message = b'asdfasdftestfoobarhelloworld'
        enc = sbox.encrypt(message)
        s.send(bytes(enc) + b'\n')