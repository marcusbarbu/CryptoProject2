#!/usr/bin/env python3

import base64
import hashlib
import hmac
import socket
import sys
import uuid


class Client(object):
    def __init__(self, host, port, passphrase):
        self.passphrase = passphrase
        self.ack_phrase = 'ack'
        self.integrity = self.hmac(self.ack_phrase)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error as e:
            print('error creating socket', e)
            sys.exit(1)
        sock.connect((host, port))
        self.sock = sock

    def send(self, message):
        self.sock.sendall(bytes(message + '\n', 'ascii'))

    def sendto(self, to, message):
        self.send(':'.join((to, str(message))))

    def recv(self):
        return self.sock.recv(1024).strip().decode('ascii')

    def recvfrom(self, target):
        sender = ''
        data = ''
        while target != sender:
            sender, data = self.recv().split(':')
        return data

    def hmac(self, data):
        return hmac.new(self.passphrase.encode('UTF-8'),
                        msg=data.encode('UTF-8'),
                        digestmod=hashlib.sha256).digest()

    def connect(self):
        m = hashlib.sha256()
        m.update(self.passphrase.encode('UTF-8'))
        hashed_pword = str(base64.b64encode(m.digest()))
        random_nonce = uuid.uuid4().int & (1 << 64) - 1
        auth = '|'.join((hashed_pword, str(random_nonce)))
        self.send(auth)

        valid_hmac = self.hmac(str(random_nonce + 1))
        own_acks = set([])
        other_acks = set([])
        partner = None
        while True:
            new_msg = self.recv()
            print('msg', new_msg)
            sender, data = new_msg.split(':')
            try:
                new_nonce = int(data)
                if new_nonce != random_nonce:
                    self.sendto(sender, self.hmac(str(new_nonce + 1)))
            except ValueError:
                if data == valid_hmac:
                    ack = '|'.join((self.ack_phrase, self.integrity))
                    self.sendto(sender, ack)
                    own_acks.add(sender)
                elif 'ack|' in data:
                    _, recv_integrity = data.split('|')
                    if recv_integrity == self.integrity:
                        other_acks.add(sender)
            intersect = own_acks.intersection(other_acks)
            if len(intersect) > 0:
                partner = intersect[0]
                break

        self.sendto(partner, 'we cool')
        print(self.recvfrom(partner))


if __name__ == '__main__':
    client1 = Client('0.0.0.0', 1234, 'cookie')
    client1.connect()
