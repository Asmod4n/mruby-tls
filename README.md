# mruby-tls


Client example with blocking IO
================================
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
client = Tls::Client.new(ca_file: '/usr/local/etc/ssl/cert.pem')
```

If you later want to change a config setting
```ruby
client.config.ca_file = '/etc/ssl/cert.pem'
```

Client example with non blocking IO
====================================
requires mruby-poll gem
```ruby
tcp_socket = TCPSocket.new "github.com", 443
client = Tls::Client.new
client.connect_socket tcp_socket.fileno, "github.com"
tcp_socket._setnonblock(true)
poll = Poll.new
tcp_socket_pi = poll.add(tcp_socket, Poll::Out)

buf = "GET / HTTP/1.1\r\nHost: github.com\r\nConnection: close\r\n\r\n"
while buf
  unless poll.wait
    raise "Can't write to socket"
  end
  tmp = client.write_nonblock(buf)
  case tmp
    when :tls_want_pollin
      tcp_socket_pi.events = Poll::In
    when :tls_want_pollout
      tcp_socket_pi.events = Poll::Out
    when Fixnum
      buf = buf[tmp+1...-1]
  end
end

tcp_socket_pi.events = Poll::In
poll.wait
until (buf = client.read_nonblock()).is_a? String
  case buf
    when :tls_want_pollin
      tcp_socket_pi.events = Poll::In
    when :tls_want_pollout
      tcp_socket_pi.events = Poll::Out
  end
  unless poll.wait
    raise "Can't read from socket"
  end
end

puts buf

tcp_socket._setnonblock(false)
client.close
tcp_socket.close
```

Configuration Examples
======================
You can create a configuration object to share with several connections.
```ruby
config = Tls::Config.new # see https://github.com/Asmod4n/mruby-tls/blob/master/mrblib/config.rb for options.

client = Tls::Client.new config
```

You can later on change the configuration object
```ruby
client.config = config
```

Server example
==============
```sh
openssl ecparam -name secp256r1 -genkey -out private-key.pem
openssl req -new -x509 -key private-key.pem -out server.pem
```
```ruby
tls_server = Tls::Server.new(key_file: 'private-key.pem', cert_file: 'server.pem')
tcp_server = TCPServer.new 5000 # requires mruby-socket
tcp_client = tcp_server.accept
tls_client = tls_server.accept_socket tcp_client.fileno
tls_client.write "hallo\n"
tls_client.close
```

Client Connections don't have a configurable config at the moment

Client and server example with io_uring
========================================
requires the [mruby-io_uring](https://github.com/Asmod4n/mruby-io_uring) gem

`Tls::Context#read_nonblock`/`#write_nonblock` never block. On mbedTLS
returning `WANT_READ`/`WANT_WRITE` they return `:tls_want_pollin`/
`:tls_want_pollout` instead of raising, meaning "call me again once more
data can move". Internally, `mrb_tls_bio_send`/`_recv` dispatch straight
through the socket object's own `#send`/`#recv` -- if that's an
`IO::Uring`-backed socket, the actual read/write happens via io_uring, and a
completion (or lack of one yet) drives the very same `WANT_*` symbols. Your
loop needs no TLS-specific logic at all -- it's the same `while ring.wait`
pattern as any other io_uring I/O.

Client:
```ruby
ring = IO::Uring.new
IO::Uring.default_io_uring = ring

# A real io_uring-backed TCP socket -- #send/#recv submit via io_uring and
# return an in-flight Operation instead of completing synchronously.
sock = IO::Uring::TCPSocket.new('example.com', 443)
client = Tls::Client.new(ca_file: '/etc/ssl/cert.pem')
client.connect_socket(sock, 'example.com')

request = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
until request.empty?
  case (n = client.write_nonblock(request))
  when Integer then request = request[n..-1] || ''
  when Symbol  then ring.wait
  end
end

response = String.new
loop do
  case (chunk = client.read_nonblock(4096))
  when String
    break if chunk.empty? # peer sent close_notify
    response << chunk
  when Symbol
    ring.wait
  end
end
puts response

loop do
  r = client.close_nonblock
  break unless r.is_a?(Symbol)
  ring.wait
end
sock.close
```

Server:
```ruby
ring = IO::Uring.new
IO::Uring.default_io_uring = ring

tls_server = Tls::Server.new(key_file: 'private-key.pem', cert_file: 'server.pem')
listener = IO::Uring::TCPServer.new(5000)
listener.listen
ring.wait

accept_op = listener.accept
ring.wait until accept_op.res

# #sock is already a real IO::Uring::TCPSocket (async #send/#recv) once
# the accept has completed -- no manual wrapping needed.
sock = accept_op.sock
tls_client = tls_server.accept_socket(sock)

request = String.new
loop do
  case (chunk = tls_client.read_nonblock(4096))
  when String
    break if chunk.empty?
    request << chunk
    break if request.include?("\r\n\r\n")
  when Symbol
    ring.wait
  end
end

response = "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nhello\n"
until response.empty?
  case (n = tls_client.write_nonblock(response))
  when Integer then response = response[n..-1] || ''
  when Symbol  then ring.wait
  end
end

loop do
  r = tls_client.close_nonblock
  break unless r.is_a?(Symbol)
  ring.wait
end
sock.close
```

`ring.wait` can raise `Errno::EINTR` if a signal interrupts the underlying
`io_uring_submit_and_wait_timeout` syscall; wrap it in `begin/rescue
Errno::EINTR/retry` for anything that needs to survive that.

TLS backend
===========
This gem is implemented on top of [mbedTLS](https://github.com/Mbed-TLS/mbedtls)
4.1 (a git submodule under `deps/mbedtls`). It previously used mbedTLS 3.6.x,
and before that LibreSSL's `libtls`. The Ruby API is unchanged; the following
observable details differ because they are properties of the underlying
library rather than of this gem:

* **Cipher names.** `Tls::Context#cipher` returns mbedTLS' RFC style suite name
  (`TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256`), not OpenSSL's shorthand
  (`ECDHE-RSA-AES128-GCM-SHA256`).
* **`Tls::Config#ciphers=`.** mbedTLS has no OpenSSL cipher-string grammar.
  The libtls keywords (`secure`, `default`, `compat`, `legacy`, `insecure`,
  `all`) all mean "use mbedTLS' own default suite list"; anything else must be
  a `:`/`,` separated list of mbedTLS suite names. Unknown names raise
  `Tls::Config::Error`.
* **`Tls::Config#ecdhecurve=`.** Takes mbedTLS curve names; the common OpenSSL
  spellings (`prime256v1`, `P-256`, `X25519`, ...) are aliased. `auto` and
  `default` keep the library defaults. libtls' `none` is not supported.
  mbedTLS 4.0 dropped every curve under 250 bits (`secp192r1`, `secp192k1`,
  `secp224r1`, `secp224k1`), so those names (and their OpenSSL aliases) are no
  longer accepted at all; a name that is valid in principle but was not
  compiled into this particular build also raises.
* **TLS 1.0/1.1.** `Tls::Protocol::TLSv1_0` and `TLSv1_1` still exist and keep
  their values, but mbedTLS cannot negotiate those versions (RFC 8996), so
  selecting them clamps up to the lowest version the library supports (1.2).
  LibreSSL 4.0.0 documented and did exactly the same for these two bits, so
  this is not a change in behaviour.
* **`Tls.load_file(file, password)`.** Without a password the file's raw bytes
  are returned. With a password, only *private keys* can be decrypted (mbedTLS
  has no generic encrypted-PEM reader); anything else raises `Tls::Error`
  rather than silently returning undecrypted data.
* **Default trust store.** libtls defaulted to the `cert.pem` shipped with its
  own LibreSSL build. mbedTLS ships no trust store, so a fresh `Tls::Config`
  defaults to the platform's, honouring `SSL_CERT_FILE` / `SSL_CERT_DIR`.
* **`Tls::Config#ca_path=`** is implemented by scanning the directory; it is
  not available on Windows.
* **`Tls::Config#cert_mem=`/`#key_mem=`.** The exact `String` object passed in
  is adopted, not copied, and is wiped in place (zeroed) the moment it is
  replaced or `#clear_keys` is called -- including the caller's own reference
  to that same object, since it's the same object. Keep your own copy first
  if you need the bytes again afterwards.

License
=======
Copyright 2015,2016,2024 Hendrik Beskow

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this project except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
