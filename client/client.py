#!/usr/bin/env python3

import base64
import bcrypt
import click
import hashlib
import hmac
import logging
import select
import socket
import sys
import uuid

from nacl.public import PrivateKey, PublicKey, Box
from nacl.exceptions import CryptoError


class Client(object):
    def __init__(self, host, port, passphrase, salt):
        self.passphrase = bytes(passphrase, 'UTF-8')
        self.salt = bytes(salt, 'UTF-8')
        self.ack_phrase = b'ack'
        self.integrity = base64.b64encode(self.hmac(self.ack_phrase))
        self.partner = None
        self.box = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error as e:
            logging.error('error creating socket', e)
            sys.exit(1)
        sock.connect((host, port))
        self.sock = sock

    def send(self, message):
        self.sock.sendall(message + b'\n')

    def sendto(self, to, type, message):
        self.send(b':'.join([to, type, message]))

    def sendmsg(self, message):
        if not self.box:
            logging.error('not connected')
            self.abort()
        enc_msg = base64.b64encode(self.box.encrypt(message))
        self.sendto(self.partner, b'msg', enc_msg)

    def recv(self):
        msg = self.sock.recv(1024).strip()
        return msg

    def recvfrom(self, target):
        try:
            sender, data = self.recv().split(b':', 1)
        except ValueError:
            pass
        if sender == target:
            return data

    def recvmsg(self):
        if not self.box:
            logging.error('not connected')
            self.abort()
        data = self.recvfrom(self.partner)
        try:
            _, data = data.split(b':')
        except ValueError:
            logging.error('received bad msg')
            self.abort()

        try:
            decrypted = self.box.decrypt(base64.b64decode(data)).strip()
        except CryptoError:
            logging.error('tampered message')
            self.abort()

        return decrypted

    def hmac(self, data):
        return hmac.new(self.passphrase,
                        msg=data,
                        digestmod=hashlib.sha256).digest()

    def abort(self):
        self.sock.close()
        sys.exit(1)

    def connect(self):
        hashed_pword = base64.b64encode(
            bcrypt.hashpw(self.passphrase, self.salt))
        self.send(hashed_pword)

        secretkey = PrivateKey.generate()
        publickey = bytes(secretkey.public_key)
        b64_publickey = base64.b64encode(publickey)
        self.sendto(b'0', b'public', base64.b64encode(publickey))

        valid_hmac = base64.b64encode(self.hmac(publickey))
        own_acks = set([])
        other_acks = set([])
        pk_arrived = []
        public_recvd = {}
        while self.partner is None:
            try:
                sender, type, data = self.recv().split(b':')
            except ValueError:
                continue
            if type == b'public':
                if data != b64_publickey:
                    logging.info('recvieved public key')
                    decode_public = base64.b64decode(data)
                    public_recvd[sender] = decode_public
                    gen_hmac = base64.b64encode(self.hmac(decode_public))
                    self.sendto(sender, b'hmac', gen_hmac)
                    if sender not in pk_arrived:
                        self.sendto(sender, b'public', b64_publickey)
                else:
                    logging.warning(
                        'received own public key, possible attacker')
            elif type == b'hmac':
                pk_arrived.append(sender)
                if data == valid_hmac:
                    logging.info('received valid hmac of public key')
                    self.sendto(sender, self.ack_phrase, self.integrity)
                    own_acks.add(sender)
                else:
                    logging.warning('received invalid hmac of public key')
            elif type == b'ack':
                if data == self.integrity:
                    logging.info('partner received valid hmac of public key')
                    other_acks.add(sender)
                else:
                    logging.warning('received invalid ack, possible attacker')
            intersect = own_acks.intersection(other_acks)
            if len(intersect) > 0:
                logging.info('found valid partner')
                self.partner = list(intersect)[0]

        recv_pkey = PublicKey(public_recvd[self.partner])
        self.box = Box(secretkey, recv_pkey)


def create_screen(lines):
    print(chr(27) + "[2J")
    for line in lines:
        print(line)


@click.command()
@click.option('--host', required=True,
              default='0.0.0.0')
@click.option('--port', required=True,
              default=8000, type=int)
@click.option('--pass', 'password',
              help='passphrase for room attempting to connect to')
@click.option('--salt', default='$2b$12$SNu.m09jY.Qq5ya2WZiEc.',
              help='salt used in hashing password')
@click.option('--debug', is_flag=True, default=False,
              help='debug mode turns on more debug messages and stores all \
              test inputs to specified test folder')
def main(host, port, password, salt, debug):
    if debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if not password:
        password = str(uuid.uuid4())
        logging.info('did not receive password')
        logging.info('assigned password: %s', password)

    client = Client(host, port, password, salt)
    logging.info('attempting to connect')
    client.connect()
    logging.info('connected')
    socks = [sys.stdin, client.sock]
    lines = []
    create_screen(lines)
    try:
        while True:
            read_socks, _, _ = select.select(socks, [], [])
            for sock in read_socks:
                if sock == client.sock:
                    msg = client.recvmsg().decode('UTF-8')
                    lines.append('them: ' + msg)
                else:
                    msg = sys.stdin.readline()
                    lines.append('you: ' + msg.strip())
                    client.sendmsg(msg.encode('UTF-8'))
            create_screen(lines)
    except Exception:
        client.sock.close()


if __name__ == "__main__":
    main()
