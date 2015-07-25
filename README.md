# mruby-tls

Prerequisites
=============
libtls needs to be somewhere your compiler can find it.
By default libtls looks in /etc/ssl/cert.pem for ca certs.

Example
=======
```ruby
client = Tls::Client.new
client.connect('github.com:443').write("GET / HTTP/1.1\r\nHost: github.com\r\nConnection: close\r\n\r\n")
print client.read
client.close
```

Its also possible to connect via service descriptions.
```ruby
client.connect('github.com', 'https')
```

You can also use port numbers as the second Argument.
```ruby
client.connect('github.com', '443')
```

If your ca certs are in another path.

```ruby
client = Tls::Client.new(ca_file: '/usr/local/etc/libressl/cert.pem')
```

Server example
```ruby
tls_server = Tls::Server.new(key_file: 'privkey.pem', cert_file: 'cacert.pem')
tcp_server = TCPServer.new 5000 # requires mruby-socket
tcp_client = tcp_server.accept
tls_client = tls_server.accept_socket tcp_client.fileno
tls_client.write "hallo\n"
tls_client.close
```

If you later want to change a config setting
```ruby
client.config.ca_file = '/etc/ssl/cert.pem'
```

The following Errors can be thrown:
```ruby
Errno::*
Tls::ReadAgain # A read operation is necessary to continue.
Tls::WriteAgain # A write operation is necessary to continue.
```

This maps the C Api 1:1, to get a overview http://www.openbsd.org/cgi-bin/man.cgi/OpenBSD-current/man3/tls_accept_fds.3?query=tls%5finit&sec=3 is a good starting point.
