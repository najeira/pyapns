# -*- coding: utf-8 -*-

# pyapns is distributed under the terms of the MIT license.
# 
# Copyright (c) 2014 najeira
# <https://github.com/najeira/pyapns>
# 
# Copyright (c) 2014, VOYAGE GROUP
# <https://github.com/voyagegroup/apns-proxy-server>
# 
# Copyright (c) 2011 Goo Software Ltd
# <https://github.com/djacobs/PyAPNs>
# 
# Copyright (c) 2010 Max Klymyshyn, Sonettic
# <https://pypi.python.org/pypi/APNSWrapper/>
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


import binascii
import datetime
import struct
import socket
import select
import ssl
import json
import logging
import collections
import threading
import Queue


MAX_NOTIFICATION_LENGTH = 256


def utf8(value):
  if value is None or isinstance(value, str):
    return value
  return value.encode("utf-8")


class Error(Exception):
  pass


class NotificationTooLargeError(Error):
  pass


class GatewayError(IOError):
  def __init__(self, data):
    command, status, identifier = struct.unpack("!BBL", data)
    self.command = command
    self.status = status
    self.identifier = identifier
  
  def __repr__(self):
    return "%s(command=%d, status=%d, identifier=%d)" % (
      self.__class__.__name__, self.command, self.status, self.identifier)


class APNs(object):
  def __init__(self, use_sandbox=False, cert_file=None, key_file=None):
    """
    Set use_sandbox to True to use the sandbox (test) APNs servers.
    Default is False.
    """
    super(APNs, self).__init__()
    self.use_sandbox = use_sandbox
    self.cert_file = cert_file
    self.key_file = key_file
    self._feedback_connection = None
    self._gateway_connection = None

  @property
  def feedback_server(self):
    if not self._feedback_connection:
      self._feedback_connection = FeedbackConnection(
        use_sandbox=self.use_sandbox,
        cert_file=self.cert_file,
        key_file=self.key_file
      )
    return self._feedback_connection

  @property
  def gateway_server(self):
    if not self._gateway_connection:
      self._gateway_connection = GatewayConnection(
        use_sandbox=self.use_sandbox,
        cert_file=self.cert_file,
        key_file=self.key_file
      )
    return self._gateway_connection


class APNsConnection(object):
  """
  A generic connection class for communicating with the APNs
  """

  def __init__(self, cert_file=None, key_file=None):
    super(APNsConnection, self).__init__()
    self.server = None
    self.port = None
    self.cert_file = cert_file
    self.key_file = key_file
    self._socket = None
    self._ssl = None
    self._read_buffer = []

  def __del__(self):
    self.disconnect()

  def _connect(self):
    assert self.server
    assert self.port
    self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self._socket.connect((self.server, self.port))
    self._ssl = ssl.wrap_socket(self._socket, self.key_file, self.cert_file)

  def disconnect(self):
    if self._socket:
      self._socket.close()
      self._socket = None
      self._ssl = None
      self._read_buffer = []
  
  def ensure_connect(self):
    if not self._socket:
      self._connect()
  
  def connection(self):
    self.ensure_connect()
    return self._ssl or self._socket
  
  def fileno(self):
    self.ensure_connect()
    return self._socket.fileno()
  
  def len_read_buffer(self):
    return sum(len(b) for b in self._read_buffer)

  def read(self):
    data = "".join(self._read_buffer)
    self._read_buffer = []
    return data
  
  def _recv(self, n=4096):
    self.ensure_connect()
    if self._ssl:
      return self._ssl.read(n)
    return self._socket.recv(n)

  def recv(self, n=4096):
    self._read_buffer.append(self._recv(n))

  def write(self, string):
    return self.connection().write(string)


class NotificationAlert(object):
  def __init__(self, body, action_loc_key=None, loc_key=None,
               loc_args=None, launch_image=None):
    super(NotificationAlert, self).__init__()
    self.body = body
    self.action_loc_key = action_loc_key
    self.loc_key = loc_key
    self.loc_args = loc_args
    self.launch_image = launch_image

  def dict(self):
    d = {"body": self.body}
    if self.action_loc_key:
      d["action-loc-key"] = self.action_loc_key
    if self.loc_key:
      d["loc-key"] = self.loc_key
    if self.loc_args:
      d["loc-args"] = self.loc_args
    if self.launch_image:
      d["launch-image"] = self.launch_image
    return d


class Notification(object):
  """A class representing an APNs message"""

  def __init__(self, alert=None, badge=None, sound=None, custom=None,
               identifier=None, expiration=None, priority=10):
    super(Notification, self).__init__()
    self.alert = alert
    self.badge = badge
    self.sound = sound
    self.custom = custom
    self.identifier = identifier
    self.expiration = expiration
    self.priority = priority
    self._check_size()

  def dict(self):
    """Returns the notification as a regular Python dictionary"""
    d = {}
    if self.alert:
      # Alert can be either a string or a NotificationAlert
      # object
      if isinstance(self.alert, NotificationAlert):
        d["alert"] = self.alert.dict()
      else:
        d["alert"] = self.alert
    if self.sound:
      d["sound"] = self.sound
    if self.badge is not None:
      d["badge"] = int(self.badge)

    d = {"aps": d}
    if self.custom:
      d.update(self.custom)
    return d

  def json(self):
    return json.dumps(self.dict(), separators=(",", ":"), ensure_ascii=False).encode("utf-8")

  def _check_size(self):
    if len(self.json()) > MAX_NOTIFICATION_LENGTH:
      raise NotificationTooLargeError()

  def __repr__(self):
    attrs = ("alert", "badge", "sound", "custom")
    args = ", ".join(["%s=%r" % (n, getattr(self, n)) for n in attrs])
    return "%s(%s)" % (self.__class__.__name__, args)
  
  def item_payload(self):
    payload_str = self.json()
    len_str = struct.pack(">H", len(payload_str)) # 2 bytes
    return "\2" + len_str + payload_str
  
  def item_identifier(self):
    if self.identifier is not None:
      value = struct.pack(">I", self.identifier) # 4 bytes
      len_str = struct.pack(">H", len(value)) # 2 bytes
      return "\3" + len_str + value
  
  def item_expiration(self):
    if self.expiration is not None:
      value = struct.pack(">I", self.expiration) # 4 bytes
      len_str = struct.pack(">H", len(value)) # 2 bytes
      return "\4" + len_str + value
  
  def item_priority(self):
    if self.priority is not None:
      value = struct.pack(">B", self.priority) # 1 bytes
      len_str = struct.pack(">H", len(value)) # 2 bytes
      return "\5" + len_str + value


class FeedbackConnection(APNsConnection):
  """
  A class representing a connection to the APNs Feedback server
  """

  def __init__(self, use_sandbox=False, **kwargs):
    super(FeedbackConnection, self).__init__(**kwargs)
    self.server = "feedback.sandbox.push.apple.com" if use_sandbox else "feedback.push.apple.com"
    self.port = 2196

  def items(self):
    """
    A generator that yields (token_hex, fail_time) pairs retrieved from
    the APNs feedback server
    """
    buff = ""
    fileno = self.fileno()
    rfds, wfds, efds = [fileno], [], [fileno]
    while True:
      ready_to_read, _, in_error = select.select(rfds, wfds, efds, 60)
      
      if len(in_error):
        raise IOError("error")
      
      if len(ready_to_read):
        self.recv()
        data = self.read()
        if not data or len(buff) < 6:
          break
        buff += data
        while len(buff) > 6:
          token_length = struct.unpack('>H', buff[4:6])[0]
          bytes_to_read = 6 + token_length
          if len(buff) >= bytes_to_read:
            fail_time_unix = struct.unpack('>I', buff[0:4])[0]
            fail_time = datetime.datetime.utcfromtimestamp(fail_time_unix)
            token = binascii.b2a_hex(buff[6:bytes_to_read])
            buff = buff[bytes_to_read:] # Remove data for current token from buffer
            yield (token, fail_time)
          else:
            break # break out of inner while loop


class GatewayConnection(APNsConnection):
  """
  A class that represents a connection to the APNs gateway server
  """

  def __init__(self, use_sandbox=False, **kwargs):
    super(GatewayConnection, self).__init__(**kwargs)
    self.server = "gateway.sandbox.push.apple.com" if use_sandbox else "gateway.push.apple.com"
    self.port = 2195
    self.logger = None
    self._identifiler = 1
    self._sent_items = {}
    self._queue = Queue.Queue()
    self._worker_thread = None
  
  def put(self, notification, tokens):
    self._queue.put((notification, tokens, ))
    self._log(logging.DEBUG, "put: %r, %r" % (notification, tokens, ))
    self._start()
  
  def join(self):
    self._queue.put(None)
    if self._worker_thread:
      self._worker_thread.join()
      self._worker_thread = None
  
  def _log(self, level, msg, *args, **kwargs):
    if self.logger:
      self.logger.log(level, msg, *args, **kwargs)
  
  def _start(self):
    if self._worker_thread:
      if not self._worker_thread.is_alive:
        self._worker_thread = None
    if not self._worker_thread:
      self._worker_thread = threading.Thread(target=self._run)
      self._worker_thread.daemon = True
      self._worker_thread.start()
      self._log(logging.DEBUG, "thread start")
  
  def _run(self):
    try:
      self._send_loop()
    finally:
      self.disconnect()

  def _send_loop(self):
    item = self._queue.get()
    while item:
      try:
        self._send(item[0], item[1])
      except GatewayError as gateway_error:
        self._handle_gateway_error(gateway_error)
      except (socket.error, IOError) as io_error:
        self._handle_ioerror(io_error)
      item = self._queue.get()
  
  def _handle_gateway_error(self, error):
    self.disconnect()
    if error.command == 8 and error.status != 10 and error.identifier != 0:
      invalid_item = self._sent_items.get(ge.identifier)
      if invalid_item:
        self._log(logging.INFO, "invalid token: %s" % invalid_item[1])
      self._retry_from(ge.identifier + 1)
    else:
      self._log(logging.WARN, "unknown error: %r" % error)

  def _handle_ioerror(self, error):
    self.disconnect()
    self._log(logging.WARN, error, exc_info=1)

  def _send(self, notification, token):
    fileno = self.fileno()
    rfds, wfds, efds = [fileno], [fileno], [fileno]
    while True:
      ready_to_read, ready_to_write, in_error = select.select(rfds, wfds, efds, 60)
      if in_error:
        raise IOError("error")
      elif ready_to_read:
        self._ready_to_read()
      elif ready_to_write:
        self._ready_to_write(notification, token)
        return
  
  def _put_sent_item(self, notification, token):
    self._sent_items[self._identifiler] = (notification, token, )
    if len(self._sent_items) > self.KEEP_SENT_ITEMS_MAX:
      self._sent_items.pop(self._identifiler - self.KEEP_SENT_ITEMS_MAX)

  def _retry_last_one(self, index):
    self._retry_from(self._identifiler)

  def _retry_from(self, index):
    while index <= self._identifiler:
      item = self._sent_items.get(index)
      if not item:
        break
      self.put(item[0], item[1])
      index += 1

  def _ready_to_write(self, notification, token):
    notification.identifier = self._identifiler
    self._put_sent_item(notification, token)
    self._identifiler += 1
    self._send_notification_to_token(notification, token)
    self._log(logging.DEBUG, "sent")
  
  def _ready_to_read(self):
    self.recv()
    if self.len_read_buffer() < 6:
      return
    data = self.read()
    assert len(data) >= 6
    raise GatewayError(data)
  
  def _send_notification_to_token(self, notification, token_hex):
    msg = self._build_message(notification, token_hex)
    self.write(msg)
  
  def _build_message(self, notification, token_hex):
    data = [self._item_device_token(utf8(token_hex)),
      notification.item_payload()]
    for f in (notification.item_identifier,
              notification.item_expiration,
              notification.item_priority):
      item = f()
      if item:
        data.append(item)
    data = "".join(data)
    len_str = struct.pack(">I", len(data)) # 4 bytes
    return "\2" + len_str + data
  
  def _item_device_token(self, token_hex):
    token_bin = binascii.a2b_hex(token_hex)
    len_str = struct.pack(">H", len(token_bin)) # 2 bytes
    return "\1" + len_str + token_bin
