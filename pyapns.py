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
import threading
import Queue
import array


MAX_NOTIFICATION_LENGTH = 256
POLL_NONE  = 0
POLL_READ  = 0x001
POLL_WRITE = 0x004
POLL_ERROR = 0x008 | 0x010


def utf8(value):
  if value is None or isinstance(value, str):
    return value
  return value.encode("utf-8")


class Error(Exception):
  pass


class NotificationTooLargeError(Error):
  pass


class GatewayError(IOError):
  def __init__(self, command, status, identifier):
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
  POLL_EVENTS = 0

  def __init__(self, cert_file=None, key_file=None):
    super(APNsConnection, self).__init__()
    self.server = None
    self.port = None
    self.cert_file = cert_file
    self.key_file = key_file
    self._socket = None
    self._ssl = None
    self._read_buffer = []
    if hasattr(select, "epoll"):
      # Linux
      self._poll = select.epoll()
    elif hasattr(select, "kqueue"):
      # Python 2.6+ on BSD or Mac
      self._poll = _KQueue()
    else:
      self._poll = _Select()

  def poll(self, timeout):
    self.ensure_connect()
    return self._poll.poll(timeout)

  def poll_modify(self, events):
    self.ensure_connect()
    self._poll.modify(self._socket.fileno(), events | POLL_ERROR)

  def _connect(self):
    self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self._socket.connect((self.server, self.port))
    self._ssl = ssl.wrap_socket(self._socket, self.key_file, self.cert_file)
    self._poll.register(self._socket.fileno(), self.POLL_EVENTS | POLL_ERROR)

  def disconnect(self):
    if self._socket:
      try:
        self._poll.unregister(self._socket.fileno())
      except Exception as ex:
        pass
      self._socket.close()
      self._socket = None
      self._ssl = None
      self._read_buffer = []
  
  def ensure_connect(self):
    if not self._socket:
      self._connect()
  
  def len_read_buffer(self):
    return sum(len(b) for b in self._read_buffer)

  def read(self):
    data = "".join(self._read_buffer)
    self._read_buffer = []
    return data
  
  def recv(self, n=4096):
    if self._ssl:
      return self._ssl.read(n)
    return self._socket.recv(n)

  def recv_to_buffer(self, n=4096):
    chunk = self.recv(n)
    if not chunk:
      raise IOError("closed")
    self._read_buffer.append(chunk)

  def write(self, string):
    if self._ssl:
      return self._ssl.write(string)
    return self._socket.send(string)


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
    value = struct.pack(">I", self.identifier or 0) # 4 bytes
    len_str = struct.pack(">H", len(value)) # 2 bytes
    return "\3" + len_str + value
  
  def item_expiration(self):
    value = struct.pack(">I", self.expiration or 0) # 4 bytes
    len_str = struct.pack(">H", len(value)) # 2 bytes
    return "\4" + len_str + value
  
  def item_priority(self):
    value = struct.pack(">B", self.priority or 10) # 1 bytes
    len_str = struct.pack(">H", len(value)) # 2 bytes
    return "\5" + len_str + value


class FeedbackConnection(APNsConnection):
  """
  A class representing a connection to the APNs Feedback server
  """
  POLL_EVENTS = POLL_READ

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
    for (fd, events) in self.poll(60.0):
      if events & POLL_ERROR:
        raise IOError("error")
      elif events & POLL_READ:
        self.recv_to_buffer()
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
  POLL_EVENTS = POLL_READ | POLL_WRITE

  def __init__(self, use_sandbox=False, **kwargs):
    super(GatewayConnection, self).__init__(**kwargs)
    self.server = "gateway.sandbox.push.apple.com" if use_sandbox else "gateway.push.apple.com"
    self.port = 2195
    self.logger = None
    self.keep_sent_items_max = 1000
    self._identifier = 0
    self._sent_items = {}
    self._sent_identifiers = array.array("L")
    self._queue = Queue.Queue()
    self._worker_thread = threading.Thread(target=self._run)
    self._worker_thread.daemon = True
    self._worker_thread.start()
  
  def put(self, notification, token):
    if not self._worker_thread:
      raise Error("closed")
    self._queue.put((notification, token, ))
    self._log(logging.DEBUG, "put")
  
  def join(self):
    self._queue.put(None)
    if self._worker_thread:
      self._worker_thread.join()
      self._worker_thread = None

  @property
  def is_alive(self):
    return bool(self._worker_thread)
  
  def _log(self, level, msg, *args, **kwargs):
    if self.logger:
      self.logger.log(level, msg, *args, **kwargs)
  
  def _run(self):
    try:
      self._send_loop()
      while not self._queue.empty():
        self._log(logging.DEBUG, "loop")
        self._queue.put(None)
        self._send_loop()
    finally:
      self.disconnect()
      self._worker_thread = None

  def _send_loop(self):
    item = self._queue.get()
    while item:
      try:
        self._send(item[0], item[1])
      except GatewayError as gateway_error:
        self._handle_gateway_error(gateway_error)
      except (socket.error, IOError) as io_error:
        self._handle_ioerror(io_error)
      finally:
        self._queue.task_done()
      item = self._queue.get()
    self._queue.task_done()
    
    self.poll_modify(POLL_READ)
    try:
      self._check_error()
      self.poll_modify(self.POLL_EVENTS)
    except GatewayError as gateway_error:
      self._handle_gateway_error(gateway_error)
    except (socket.error, IOError) as io_error:
      self._handle_ioerror(io_error)
  
  def _handle_gateway_error(self, error):
    self.disconnect()
    if error.command == 8 and error.identifier != 0 and error.status in (8, 10):
      invalid_item = self._pop_sent_item(error.identifier)
      if invalid_item:
        self._log(logging.INFO, "invalid token: %s" % invalid_item[1])
      self._retry_from(error.identifier + 1)
    else:
      self._log(logging.WARN, "unknown error: %r" % error)
      raise

  def _handle_ioerror(self, error):
    self.disconnect()
    self._log(logging.WARN, error)
    self.ensure_connect()

  def _send(self, notification, token):
    self._identifier += 1
    notification.identifier = self._identifier
    self._put_sent_item(notification, token)
    msg = self._build_message(notification, token)
    while msg:
      for (fd, events) in self.poll(3600.0):
        if events & POLL_ERROR:
          raise IOError("error")
        elif events & POLL_READ:
          self._ready_to_read()
        elif events & POLL_WRITE:
          msg = self._ready_to_write(msg)
    self._log(logging.DEBUG, "sent")

  def _check_error(self):
    for (fd, events) in self.poll(0.5):
      if events & POLL_ERROR:
        raise IOError("error")
      elif events & POLL_READ:
        self._ready_to_read()
  
  def _put_sent_item(self, notification, token):
    self._sent_items[notification.identifier] = (notification, token, )
    self._sent_identifiers.append(notification.identifier)
    if len(self._sent_items) > self.keep_sent_items_max:
      self._pop_sent_item_min()

  def _pop_sent_item(self, index):
    item = self._sent_items.pop(index, None)
    if item:
      self._sent_identifiers.remove(index)
    return item

  def _pop_sent_item_min(self):
    index = self._sent_identifiers.pop(0)
    return self._sent_items.pop(index, None)

  def _retry_from(self, index):
    while index <= self._identifier:
      item = self._pop_sent_item(index)
      if item:
        self.put(item[0], item[1])
      index += 1

  def _ready_to_write(self, data):
    length = self.write(data)
    if length == len(data):
      return None
    return data[length:]
  
  def _ready_to_read(self):
    self.recv_to_buffer()
    length = self.len_read_buffer()
    if length < 6:
      return
    elif length > 6:
      raise IOError("unknown")
    data = self.read()
    command, status, identifier = struct.unpack("!BBL", data)
    raise GatewayError(command, status, identifier)
  
  def _build_message(self, notification, token_hex):
    data = [self._item_device_token(utf8(token_hex)),
      notification.item_payload(), notification.item_identifier(),
      notification.item_expiration(), notification.item_priority()]
    data = "".join(data)
    len_str = struct.pack(">I", len(data)) # 4 bytes
    return "\2" + len_str + data
  
  def _item_device_token(self, token_hex):
    token_bin = binascii.a2b_hex(token_hex)
    len_str = struct.pack(">H", len(token_bin)) # 2 bytes
    return "\1" + len_str + token_bin


class _KQueue(object):
  """A kqueue-based event loop for BSD/Mac systems."""

  def __init__(self):
    self._kqueue = select.kqueue()
    self._active = {}

  def fileno(self):
    return self._kqueue.fileno()

  def close(self):
    self._kqueue.close()

  def register(self, fd, events):
    if fd in self._active:
      raise IOError("fd %d already registered" % fd)
    self._control(fd, events, select.KQ_EV_ADD)
    self._active[fd] = events

  def modify(self, fd, events):
    self.unregister(fd)
    self.register(fd, events)

  def unregister(self, fd):
    events = self._active.pop(fd)
    self._control(fd, events, select.KQ_EV_DELETE)

  def _control(self, fd, events, flags):
    kevents = []
    if events & POLL_WRITE:
      kevents.append(select.kevent(
        fd, filter=select.KQ_FILTER_WRITE, flags=flags))
    if events & POLL_READ or not kevents:
      # Always read when there is not a write
      kevents.append(select.kevent(
        fd, filter=select.KQ_FILTER_READ, flags=flags))
    # Even though control() takes a list, it seems to return EINVAL
    # on Mac OS X (10.6) when there is more than one event in the list.
    for kevent in kevents:
      self._kqueue.control([kevent], 0)

  def poll(self, timeout):
    kevents = self._kqueue.control(None, 1000, timeout)
    events = {}
    for kevent in kevents:
      fd = kevent.ident
      if kevent.filter == select.KQ_FILTER_READ:
        events[fd] = events.get(fd, 0) | POLL_READ
      if kevent.filter == select.KQ_FILTER_WRITE:
        if kevent.flags & select.KQ_EV_EOF:
          # If an asynchronous connection is refused, kqueue
          # returns a write event with the EOF flag set.
          # Turn this into an error for consistency with the
          # other IOLoop implementations.
          # Note that for read events, EOF may be returned before
          # all data has been consumed from the socket buffer,
          # so we only check for EOF on write events.
          events[fd] = POLL_ERROR
        else:
          events[fd] = events.get(fd, 0) | POLL_WRITE
      if kevent.flags & select.KQ_EV_ERROR:
        events[fd] = events.get(fd, 0) | POLL_ERROR
    return events.items()


class _Select(object):
  """A simple, select()-based IOLoop implementation for non-Linux systems"""

  def __init__(self):
    self.read_fds = set()
    self.write_fds = set()
    self.error_fds = set()
    self.fd_sets = (self.read_fds, self.write_fds, self.error_fds)

  def close(self):
    pass

  def register(self, fd, events):
    if fd in self.read_fds or fd in self.write_fds or fd in self.error_fds:
      raise IOError("fd %d already registered" % fd)
    if events & POLL_READ:
      self.read_fds.add(fd)
    if events & POLL_WRITE:
      self.write_fds.add(fd)
    if events & POLL_ERROR:
      self.error_fds.add(fd)
      # Closed connections are reported as errors by epoll and kqueue,
      # but as zero-byte reads by select, so when errors are requested
      # we need to listen for both read and error.
      self.read_fds.add(fd)

  def modify(self, fd, events):
    self.unregister(fd)
    self.register(fd, events)

  def unregister(self, fd):
    self.read_fds.discard(fd)
    self.write_fds.discard(fd)
    self.error_fds.discard(fd)

  def poll(self, timeout):
    readable, writeable, errors = select.select(
      self.read_fds, self.write_fds, self.error_fds, timeout)
    events = {}
    for fd in readable:
      events[fd] = events.get(fd, 0) | POLL_READ
    for fd in writeable:
      events[fd] = events.get(fd, 0) | POLL_WRITE
    for fd in errors:
      events[fd] = events.get(fd, 0) | POLL_ERROR
    return events.items()
