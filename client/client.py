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
        self.integrity = str(base64.b64encode(self.hmac(self.ack_phrase)))
        self.partner = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error as e:
            print('error creating socket', e)
            sys.exit(1)
        sock.connect((host, port))
        self.sock = sock

    def send(self, message):
        self.sock.sendall(bytes(message + '\n', 'ascii'))

    def sendto(self, to, type, message):
        self.send(':'.join([to, type, str(message)]))

    def sendmsg(self, message):
        self.sendto(self.partner, 'msg', message)

    def recv(self):
        msg = self.sock.recv(1024).strip().decode('ascii')
        return msg

    def recvmsg(self):
        sender = ''
        data = ''
        while sender != self.partner:
            try:
                sender, _, data = self.recv().split(':')
            except ValueError:
                continue
        return data

    def hmac(self, data):
        return hmac.new(self.passphrase.encode('ascii'),
                        msg=data.encode('ascii'),
                        digestmod=hashlib.sha256).digest()

    def connect(self):
        m = hashlib.sha256()
        m.update(self.passphrase.encode('ascii'))
        hashed_pword = str(base64.b64encode(m.digest()))
        self.send(hashed_pword)

        random_nonce = uuid.uuid4().int & (1 << 64) - 1
        self.sendto('0', 'nonce', random_nonce)

        valid_hmac = str(base64.b64encode(self.hmac(str(random_nonce + 1))))
        own_acks = set([])
        other_acks = set([])
        nonces_sent = []
        while self.partner is None:
            try:
                sender, type, data = self.recv().split(':')
            except ValueError:
                continue
            if type == 'nonce':
                try:
                    new_nonce = int(data)
                except ValueError:
                    continue
                if new_nonce != random_nonce:
                    gen_hmac = base64.b64encode(self.hmac(str(new_nonce + 1)))
                    self.sendto(sender, 'hmac', gen_hmac)
                    if sender not in nonces_sent:
                        self.sendto(sender, 'nonce', str(random_nonce))
            elif type == 'hmac':
                nonces_sent.append(sender)
                if data == valid_hmac:
                    self.sendto(sender, self.ack_phrase, self.integrity)
                    own_acks.add(sender)
            elif type == 'ack':
                if data == self.integrity:
                    other_acks.add(sender)
            intersect = own_acks.intersection(other_acks)
            if len(intersect) > 0:
                self.partner = list(intersect)[0]


if __name__ == '__main__':
    client1 = Client('0.0.0.0', 1234, 'cookie')
    client1.connect()
    client1.sendmsg('we cool')
    print(client1.recvmsg())
