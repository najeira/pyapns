# pyapns

A library for Apple Push Notification Services.

## Getting Started

### Sending notification

```python
# gets a connection
apns = APNs(use_sandbox=True, cert_file="your.cert", key_file="your.key")
server = apns.gateway_server

# sends a notification
notification = Notification(alert="This is APNs message!")
server.send(notification, device_tokens)
```

### Handling feedbacks

```python
# gets a connection
apns = APNs(use_sandbox=True, cert_file="your.cert", key_file="your.key")
server = apns.feedback_server

# gets feedbacks
for feedback_token, feedback_datetime in server.items():
  print feedback_token, feedback_datetime
```

## License

MIT license.
