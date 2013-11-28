# -*- coding: utf-8 -*-

# PyAPNs is distributed under the terms of the MIT license.
#
# Copyright (c) 2011 Goo Software Ltd
# Copyright (c) 2013 najeira
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import binascii
import datetime
import struct
import socket
import select
import ssl
import json


MAX_NOTIFICATION_LENGTH = 256


def utf8(value):
  if value is None or isinstance(value, str):
    return value
  return value.encode("utf-8")


class Error(Exception):
  pass


class GatewayError(Error):
  def __init__(self, data):
    command, status, identifier = struct.unpack("!BBL", data)
    self.command = command
    self.status = status
    self.identifier = identifier
  
  def __repr__(self):
    return "%s(command=%d, status=%d, identifier=%d)" % (
      self.__class__.__name__, self.command, self.status, self.identifier)


class NotificationTooLargeError(Error):
  pass


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
    if not self._ssl:
      self._connect()
  
  def connection(self):
    self.ensure_connect()
    return self._ssl
  
  def fileno(self):
    self.ensure_connect()
    return self._socket.fileno()
  
  def read(self):
    data = "".join(self._read_buffer)
    self._read_buffer = []
    return data
  
  def _recv(self, n=4096):
    return self.connection().read(n)
  
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
    rfds = [self.fileno()]
    wfds = []
    efds = [self.fileno()]
    while True:
      ready_to_read, ready_to_write, in_error = select.select(rfds, wfds, efds, 60)
      
      if len(in_error):
        break
      
      if len(ready_to_read):
        self.recv()
        data = self.read()
        if not data:
          break
        buff += data
        if len(buff) >= 6:
          while len(buff) > 6:
            token_length = struct.unpack('>H', buff[4:6])[0]
            bytes_to_read = 6 + token_length
            if len(buff) >= bytes_to_read:
              fail_time_unix = struct.unpack('>I', buff[0:4])[0]
              fail_time = datetime.datetime.utcfromtimestamp(fail_time_unix)
              token = binascii.b2a_hex(buff[6:bytes_to_read])
              buff = buff[bytes_to_read:]
              yield (token, fail_time)
      else:
        # no data
        break


class GatewayConnection(APNsConnection):
  """
  A class that represents a connection to the APNs gateway server
  """

  def __init__(self, use_sandbox=False, **kwargs):
    super(GatewayConnection, self).__init__(**kwargs)
    self.server = "gateway.sandbox.push.apple.com" if use_sandbox else "gateway.push.apple.com"
    self.port = 2195
    
  def send(self, notification, tokens):
    try:
      return self._send(notification, tokens)
    finally:
      try:
        self.disconnect()
      except Exception:
        pass
  
  def _send(self, notification, tokens):
    if isinstance(tokens, basestring):
      tokens = [tokens]
    
    rfds, wfds, efds = None, None, None
    cnt_tokens = len(tokens)
    index = 0

    while index < cnt_tokens:
      
      if not wfds:
        fileno = self.fileno()
        rfds, wfds, efds = [], [fileno], [fileno]
      
      _, ready_to_write, in_error = select.select(rfds, wfds, efds, 60)
      
      if len(in_error):
        break
      
      if len(ready_to_write):
        token_hex = tokens[index]
        notification.identifier = index
        self.send_notification_to_token(notification, token_hex)
        index += 1
      
      try:
        self.check_error()
      except GatewayError as ex:
        print repr(ex)
        self.disconnect()
        rfds, wfds, efds = None, None, None
    
    return index
  
  def check_error(self):
    ready_to_read, ready_to_write, in_error = select.select(
      [self.fileno()], [], [], 1)
    if len(ready_to_read):
      self.recv()
      data = self.read()
      if data and len(data) >= 6:
        raise GatewayError(data)
  
  def send_notification_to_token(self, notification, token_hex):
    msg = self.message(notification, token_hex)
    self.write(msg)
    print token_hex
  
  def message(self, notification, token_hex):
    data = [self.item_device_token(utf8(token_hex)),
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
  
  def item_device_token(self, token_hex):
    token_bin = binascii.a2b_hex(token_hex)
    len_str = struct.pack(">H", len(token_bin)) # 2 bytes
    return "\1" + len_str + token_bin