# -*- coding: utf-8 -*-

import sys
import time
import socket
import select
import logging
import threading
from SocketServer import TCPServer
from SocketServer import StreamRequestHandler
from struct import pack, unpack
from binascii import a2b_hex, b2a_hex
from pyapns import GatewayConnection, Notification, POLL_ERROR

PORT = 2195

def unpacked_uchar(num):
  return unpack('>B', num)[0]

def unpacked_ushort_big_endian(bytes):
  return unpack('>H', bytes)[0]

def packed_uint_big_endian(num):
  return pack('>I', num)

def unpacked_uint_big_endian(bytes):
  return unpack('>I', bytes)[0]

def gen_token():
  token_list = set()
  for i in range(0, 10):
    token_bin = packed_uint_big_endian(i)
    token = b2a_hex(token_bin)
    token_list.add(token)
  return token_list

TOKEN_LIST = gen_token()

class TestRequestHandler(StreamRequestHandler):
  
  def __init__(self, request, client_address, server):
    self._read_buffer = ""
    StreamRequestHandler.__init__(self, request, client_address, server)
  
  def _read_from_fd(self):
    rd, _, _ = select.select([self.connection], [], [])
    if rd:
      try:
        chunk = self.connection.recv(4096)
      except (socket.error, IOError, OSError) as ex:
        if ex.args[0] not in (errno.EWOULDBLOCK, errno.EAGAIN):
          raise
      else:
        if not chunk:
          raise IOError("closed")
        self._read_buffer += chunk
  
  def _read_from_buffer(self, size):
    if len(self._read_buffer) < size:
      return None
    data = self._read_buffer[:size]
    self._read_buffer = self._read_buffer[size:]
    return data
  
  def _read_chunk(self, size):
    buf = self._read_from_buffer(size)
    while not buf:
      self._read_from_fd()
      buf = self._read_from_buffer(size)
    return buf
  
  def handle(self):
    closed = False
    while not closed:
      command = unpacked_uchar(self._read_chunk(1))
      frame_length = unpacked_uint_big_endian(self._read_chunk(4))
      token = None
      payload = None
      identifier = 0
      expiry = 0
      priority = 0
      while frame_length > 0:
        item_id = unpacked_uchar(self._read_chunk(1))
        item_length = unpacked_ushort_big_endian(self._read_chunk(2))
        item_data = self._read_chunk(item_length)
        frame_length -= (item_length + 3)
        if item_id == 1:
          token = b2a_hex(item_data)
        elif item_id == 2:
          payload = item_data
        elif item_id == 3:
          identifier = unpacked_uint_big_endian(item_data)
        elif item_id == 4:
          expiry = unpacked_uint_big_endian(item_data)
        elif item_id == 5:
          priority = unpacked_uchar(item_data)
      
      closed = self._parse_data(command, token, payload, identifier, expiry, priority)
    
  def _parse_data(self, command, token, payload, identifier, expiry, priority):
    print 'Receive a message: command=%d, token=%s, payload=%s, identifier=%d, expiry=%d, priority=%d' % (
      command, token, payload, identifier, expiry, priority)
    if token in TOKEN_LIST:
      return False
    self._write_error_response(identifier, '08')
    return True

  def _write_error_response(self, identifier, status):
    print 'Send a error: identifier=%d, status=%s' % (identifier, status)
    identifier_bin = packed_uint_big_endian(identifier)
    status_bin = a2b_hex(status)
    data = a2b_hex('08') + status_bin + identifier_bin
    self.connection.sendall(data)
    self.connection.shutdown(socket.SHUT_RDWR)
    self.connection.close()

class TestTCPServer(TCPServer):
  allow_reuse_address = 1
  
  def __init__(self, host="localhost", port=PORT, handler=TestRequestHandler):
    TCPServer.__init__(self, (host, port), handler)
  
  def handle_error(self, request, client_address):
    TCPServer.handle_error(self, request, client_address)
    etype = sys.exc_info()[0]
    if not issubclass(etype, Exception):
      raise

class TestGatewayConnection(GatewayConnection):
  def __init__(self, *args, **kwargs):
    GatewayConnection.__init__(self, *args, **kwargs)
    self.server = "localhost"
    self.port = PORT

  def _connect(self):
    self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self._socket.connect((self.server, self.port))
    self._poll.register(self._socket.fileno(), self.POLL_EVENTS | POLL_ERROR)

def start_server(server):
  try:
    server.serve_forever()
  finally:
    server.server_close()

def test():
  logger = logging.getLogger()
  logger.addHandler(logging.StreamHandler(sys.stdout))
  logger.setLevel(logging.DEBUG)
  gw = TestGatewayConnection()
  gw.logger = logger
  
  gw.put(Notification(alert=u"テストです"), b2a_hex(packed_uint_big_endian(1)))
  gw.put(Notification(alert=u"こんにちは"), b2a_hex(packed_uint_big_endian(2)))
  gw.put(Notification(alert=u"エラーになる"), b2a_hex(packed_uint_big_endian(10)))
  gw.put(Notification(alert=u"リトライされる"), b2a_hex(packed_uint_big_endian(3)))
  time.sleep(1.0)
  gw.put(Notification(alert=u"リトライされる2"), b2a_hex(packed_uint_big_endian(4)))
  
  gw.join()

def main():
  server = TestTCPServer("localhost", PORT)
  thread = threading.Thread(target=start_server, args=(server,))
  thread.deamon = True
  thread.start()
  try:
    test()
  finally:
    server.shutdown()
    thread.join()

if __name__ == "__main__":
  main()
