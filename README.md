# mruby-tls

Prerequisites
=============
libtls needs to be somewhere your compiler can find it.
By default libtls looks in /etc/ssl/cert.pem for ca certs.

Example
=======
```ruby
client = Tls::Client.new
print client.connect("github.com:443").write("GET / HTTP/1.1\r\nHost: github.com\r\nConnection: close\r\n\r\n").read
client.close
```

Its also possible to connect via service descriptions.

```ruby
client.connect("github.com", "https")
```

You can also use port numbers as the second Argument.


If your ca certs are in another path you have to create a config object.

```ruby
config = Tls::Config.new(ca_file: '/usr/local/etc/libressl/cert.pem')
client = Tls::Client.new config
```

You can also later change the config object.

```ruby
client.configure config
```

This maps the C Api 1:1, to get a overview http://www.openbsd.org/cgi-bin/man.cgi/OpenBSD-5.7/man3/tls_accept_socket.3?query=tls%5finit&sec=3&manpath=OpenBSD%2d5%2e7 is a good starting point.
