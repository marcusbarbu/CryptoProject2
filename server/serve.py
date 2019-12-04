#!/usr/bin/env python3

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
        id = str(uuid.uuid4())
        self.msg_queues[id] = []
        return id

    def add_msg(self, id, to, msg):
        if to == '0':
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
        logging.info('send: ' + message)
        self.request.sendall(bytes(message + '\n', 'UTF-8'))

    def recv(self):
        msg = self.request.recv(1024).strip().decode('UTF-8')
        logging.info('recv: ' + msg)
        return msg

    def data_present(self):
        present, _, _ = select.select([self.request], [], [], 1)
        return len(present) > 0

    def handle(self):
        buffer = []
        hashed_pword = self.recv()
        if '\n' in hashed_pword:
            recvd_lines = hashed_pword.split('\n')
            hashed_pword = recvd_lines[0]
            buffer += recvd_lines[1:]
        if hashed_pword not in switchboard:
            switchboard[hashed_pword] = ChatroomQueue()

        room = switchboard[hashed_pword]
        id = room.add_client()

        while True:
            if buffer:
                for msg in buffer:
                    if ':' in msg:
                        to, msg = msg.split(':', 1)
                        room.add_msg(id, to, msg)
                buffer = []
            if self.data_present():
                data = self.recv()
                if data == '':
                    self.request.close()
                    return
                if '\n' in data:
                    buffer += data.split('\n')
                else:
                    buffer.append(data)
            for sender, msg in room.get_msgs(id):
                msg = ':'.join((sender, msg))
                self.send(msg)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    host = '0.0.0.0'
    port = 1234

    server = ThreadedTCPServer((host, port), ThreadedTCPRequestHandler)
    try:
        server_thread = threading.Thread(target=server.serve_forever)
        # Exit the server thread when the main thread terminates
        server_thread.daemon = True
        server_thread.start()
        while True:
            time.sleep(0.5)
    except Exception:
        server.shutdown()
