#!/usr/bin/env python3

import click
import logging
import select
import socketserver
import threading
import time
import uuid

switchboard = {}


class ChatroomQueue(object):
    def __init__(self):
        self.msg_queues = {}

    def add_client(self):
        id = str(uuid.uuid4()).encode('ascii')
        self.msg_queues[id] = []
        return id

    def add_msg(self, id, to, msg):
        if to == b'0':
            for key, queue in self.msg_queues.items():
                if key != id:
                    queue.append((id, msg))
        elif to in self.msg_queues:
            self.msg_queues[to].append((id, msg))

    def get_msgs(self, id):
        msgs = self.msg_queues[id]
        self.msg_queues[id] = []
        return msgs


class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def send(self, message):
        self.request.sendall(message + b'\n')

    def recv(self):
        return self.request.recv(1024).strip()

    def data_present(self):
        present, _, _ = select.select([self.request], [], [], 1)
        return len(present) > 0

    def handle(self):
        logging.info('new connection')
        buffer = []
        hashed_pword = self.recv()
        logging.debug('hash: %s', hashed_pword)
        if b'\n' in hashed_pword:
            recvd_lines = hashed_pword.split(b'\n')
            hashed_pword = recvd_lines[0]
            buffer += recvd_lines[1:]
        if hashed_pword not in switchboard:
            switchboard[hashed_pword] = ChatroomQueue()

        room = switchboard[hashed_pword]
        id = room.add_client()

        while True:
            if buffer:
                for msg in buffer:
                    if b':' in msg:
                        logging.debug('recv from %s type %s: %s',
                                      *msg.split(b':'))
                        to, msg = msg.split(b':', 1)
                        room.add_msg(id, to, msg)
                buffer = []
            if self.data_present():
                data = self.recv()
                if data == b'':
                    logging.info('closed connection')
                    self.request.close()
                    return
                if b'\n' in data:
                    buffer += data.split(b'\n')
                else:
                    buffer.append(data)
            for sender, msg in room.get_msgs(id):
                msg = b':'.join((sender, msg))
                logging.debug('send to   %s type %s: %s', *msg.split(b':'))
                self.send(msg)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


@click.command()
@click.option('--host', required=True,
              default='0.0.0.0')
@click.option('--port', required=True,
              default=8000, type=int)
@click.option('--debug', is_flag=True, default=False,
              help='debug mode turns on more debug messages and stores all \
              test inputs to specified test folder')
def main(host, port, debug):
    if debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    server = ThreadedTCPServer((host, port), ThreadedTCPRequestHandler)
    try:
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        logging.info('ready to connect')
        while True:
            time.sleep(0.5)
    except Exception:
        server.shutdown()


if __name__ == "__main__":
    main()
