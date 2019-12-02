import socketserver
import socket
import threading 
import time
import random
import queue


switchboard = {}

class ChatroomQueue:
    def __init__(self, name):
        self.a_queue = queue.Queue()
        self.b_queue = queue.Queue()
        self.user_set = 0
    

    def get_queue(self, index):
        l = [self.a_queue, self.b_queue]
        return l[index]

    def get_queues(self):
        l = [self.a_queue, self.b_queue]
        x = self.user_set
        self.user_set = (self.user_set + 1) % 2
        return l[x], l[(x+1)%2]

       

class ProtoHandler(socketserver.BaseRequestHandler):
    def qprint(self, message):
        self.request.sendall(bytes(message+'\n','ascii'))

    def handle(self):
        global switchboard
        try:
            self.data = self.request.recv(1024).strip().decode('ascii')
            if self.data not in switchboard.keys():
                switchboard[self.data] = ChatroomQueue(self.data)
            c_q = switchboard[self.data]
            rec_q, send_q = c_q.get_queues()

            while True:
                msg = []
                while True:
                    try:
                        m = self.request.recv(4096, socket.MSG_DONTWAIT).strip().decode('ascii')
                        if len(m) == 0:
                            print("killing thread {}".format(threading.current_thread().name))
                            return
                        msg.append(m)
                    except:
                        break
                msg = ''.join(msg)
                if len(msg) > 0:
                    send_q.put(msg)
                if not rec_q.empty():
                    msg = rec_q.get()
                    self.qprint(msg)
        except Exception as e:
            print(e)


class ThreadProtoServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

if __name__ == '__main__':
    host = '0.0.0.0'
    port = 1234

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