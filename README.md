# mruby-tls

Prerequisites
=============
libtls needs to be somewhere your compiler can find it

Example
=======
```ruby
config = Tls::Config.new
client = Tls::Client.new config

client.connect("www.google.com:443")
client.write("GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n")
print client.read
client.close
```
