##
# mruby-tls -- SNI (Tls::Server.new(config) { |hostname| ... }) tests.
#
# Proves dispatch correctness purely through handshake outcome, the same way
# test/tls.rb already proves certificate verification: two independent,
# self-signed CA/leaf pairs, one per "virtual host". A client trusting only
# CA A can only complete a handshake if it actually receives leaf A back --
# if SNI dispatch served the wrong cert (or no cert at all), that client's
# own verification fails and the handshake never settles. No peer-certificate
# introspection API needed on either side.
#
# Reuses test/tls.rb's TLS_TEST_CA_PEM/TLS_TEST_CERT_PEM/TLS_TEST_KEY_PEM
# (the "localhost" fixture, already trusted by TLS_TEST_CA_FILE) as the
# server's *default* cert, and a second, independent fixture below
# ("sni-test.mruby-tls") as the one an sni block selects for a different
# hostname -- this file loads after tls.rb (alphabetical MRBC/test order),
# so its top-level helpers/constants are already defined.

TLS_SNI_CA_PEM = <<'PEM'
-----BEGIN CERTIFICATE-----
MIIBlzCCAT2gAwIBAgIUM6gx5Qd3kyFQAKPe5DuuOhLMMA0wCgYIKoZIzj0EAwIw
IDEeMBwGA1UEAwwVbXJ1YnktdGxzIHNuaS10ZXN0IENBMCAXDTI2MDgwMjE5NTAw
N1oYDzIwNTEwMzI0MTk1MDA3WjAgMR4wHAYDVQQDDBVtcnVieS10bHMgc25pLXRl
c3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQIDfwSD3vnkB5dP4keSOQU
g5GL0fbrVRy2zzF3u0AeUkrhJrrft2ejoOQNeoTHYQim8HfJEBzxGvVY2dzCj15Q
o1MwUTAdBgNVHQ4EFgQUUbaA88UzZ13/QGE4NzlDriFaf0owHwYDVR0jBBgwFoAU
UbaA88UzZ13/QGE4NzlDriFaf0owDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQD
AgNIADBFAiBAe3hYToFKAcCAVUDew7nSKThddxG5am0sGWsaZ92huwIhAMamj9g9
3MZZAGEutSbV5+pbcRSW84JD2TQz2zZRLKZU
-----END CERTIFICATE-----
PEM

TLS_SNI_LEAF_PEM = <<'PEM'
-----BEGIN CERTIFICATE-----
MIIBuzCCAWCgAwIBAgIUHBAsaaLezsiyhN0/cqGQUwdKIDQwCgYIKoZIzj0EAwIw
IDEeMBwGA1UEAwwVbXJ1YnktdGxzIHNuaS10ZXN0IENBMCAXDTI2MDgwMjE5NTAw
N1oYDzIwNTEwMzI0MTk1MDA3WjAdMRswGQYDVQQDDBJzbmktdGVzdC5tcnVieS10
bHMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS0Iyi8Pl6RFUiTiYOKPAfX7Sz2
YzyOFD+8O73lL3ECs28Ckoy3q1sXt/Oxmdwed8baGMgRjlcAMhYIjQAohNUzo3kw
dzAdBgNVHREEFjAUghJzbmktdGVzdC5tcnVieS10bHMwCQYDVR0TBAIwADALBgNV
HQ8EBAMCBaAwHQYDVR0OBBYEFKrEOt2nDv6QRA+4G6SLve2ZkNgaMB8GA1UdIwQY
MBaAFFG2gPPFM2dd/0BhODc5Q64hWn9KMAoGCCqGSM49BAMCA0kAMEYCIQCfSwQD
/kQmcCDui+HKMKXOXNHWA2NJH4SZkluFRoPr6QIhAI6nyAVT6yhrIvyquA+S/R7l
OCGA6RkXApJ0qNJzjosO
-----END CERTIFICATE-----
PEM

TLS_SNI_KEY_PEM = <<'PEM'
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKKS4NNM9JFKidAAm9x0ASoc1l3ijX0NLJMZF4lOHRk5oAoGCCqGSM49
AwEHoUQDQgAEtCMovD5ekRVIk4mDijwH1+0s9mM8jhQ/vDu95S9xArNvApKMt6tb
F7fzsZncHnfG2hjIEY5XADIWCI0AKITVMw==
-----END EC PRIVATE KEY-----
PEM

TLS_SNI_CA_FILE = '/tmp/mruby-tls-sni-test-ca.pem'
File.open(TLS_SNI_CA_FILE, 'w') { |f| f.write(TLS_SNI_CA_PEM) }

def tls_sni_config
  cfg = Tls::Config.new
  cfg.cert_mem = TLS_SNI_LEAF_PEM
  cfg.key_mem  = TLS_SNI_KEY_PEM
  cfg
end

def tls_sni_client_config(ca_file)
  cfg = Tls::Config.new
  cfg.ca_file = ca_file
  cfg
end

# Same shape as test/tls.rb's own tls_test_handshake, but builds the server's
# Tls::Server with an sni block instead of a bare accept_socket -- the one
# thing this file actually exercises. Returns [client_err, server_err]
# rather than just the client's, unlike tls_test_handshake: an sni block's
# own raised exception is only ever visible on the *server* side (the
# client, same as a real one, only ever sees a generic TLS alert - see the
# assertion below that actually checks this), so a test that wants to
# verify the exception itself surfaced (rather than merely that the
# handshake failed) needs access to both.
def tls_sni_test_handshake(default_cfg, client_cfg, hostname, &sni_block)
  listener = TCPServer.new('127.0.0.1', 0)
  csock = TCPSocket.new('127.0.0.1', listener.addr[1])
  ssock = listener.accept
  csock._setnonblock(true)
  ssock._setnonblock(true)

  server = sni_block ? Tls::Server.new(default_cfg, &sni_block) : Tls::Server.new(default_cfg)
  sconn  = server.accept_socket(ssock)
  client = Tls::Client.new(client_cfg)
  client.connect_socket(csock, hostname)

  client_err = nil
  server_err = nil
  cdone = false
  sdone = false

  1000.times do
    unless sdone
      begin
        sdone = !sconn.handshake_nonblock.is_a?(Symbol)
      rescue StandardError => e
        server_err = e
        sdone = true
      end
    end
    unless cdone
      begin
        cdone = !client.handshake_nonblock.is_a?(Symbol)
      rescue StandardError => e
        client_err = e
        cdone = true
      end
    end
    break if cdone && sdone
  end

  raise 'handshake did not settle' unless cdone
  [client_err, server_err]
ensure
  sconn.close rescue nil
  client.close rescue nil
  ssock.close rescue nil
  csock.close rescue nil
  listener.close rescue nil
end

assert('Tls::Server sni: a hostname the block matches gets that hostname\'s cert') do
  client_err, = tls_sni_test_handshake(tls_test_server_config(TLS_TEST_CERT_PEM),
                               tls_sni_client_config(TLS_SNI_CA_FILE),
                               'sni-test.mruby-tls') { |host| host == 'sni-test.mruby-tls' ? tls_sni_config : nil }
  assert_nil client_err
end

assert('Tls::Server sni: a client trusting only the default CA rejects the sni-selected cert') do
  # Same request as above, but the client only trusts TLS_SNI_CA_FILE's
  # *sibling*, not itself -- proves the wrong-CA case would have been
  # caught, i.e. that the acceptance above is actually meaningful and not
  # just noverify-style laxness somewhere.
  client_err, = tls_sni_test_handshake(tls_test_server_config(TLS_TEST_CERT_PEM),
                               tls_sni_client_config(TLS_TEST_CA_FILE),
                               'sni-test.mruby-tls') { |host| host == 'sni-test.mruby-tls' ? tls_sni_config : nil }
  assert_kind_of Tls::Error, client_err
end

assert('Tls::Server sni: the block returning nil keeps the connection\'s default cert') do
  client_err, = tls_sni_test_handshake(tls_test_server_config(TLS_TEST_CERT_PEM),
                               tls_test_client_config, 'localhost') { |host| nil }
  assert_nil client_err
end

assert('Tls::Server sni: a hostname the block does not recognize also keeps the default cert') do
  client_err, = tls_sni_test_handshake(tls_test_server_config(TLS_TEST_CERT_PEM),
                               tls_test_client_config, 'localhost') { |host| host == 'sni-test.mruby-tls' ? tls_sni_config : nil }
  assert_nil client_err
end

assert('Tls::Server sni: a Tls::Config reused across connections is only parsed once') do
  cfg = tls_sni_config
  3.times do
    client_err, = tls_sni_test_handshake(tls_test_server_config(TLS_TEST_CERT_PEM),
                                 tls_sni_client_config(TLS_SNI_CA_FILE),
                                 'sni-test.mruby-tls') { |host| cfg }
    assert_nil client_err
  end
end

assert('Tls::Server sni: an exception raised by the block surfaces as a real error, not a crash') do
  client_err, server_err = tls_sni_test_handshake(tls_test_server_config(TLS_TEST_CERT_PEM),
                               tls_test_client_config, 'localhost') { |host| raise 'sni lookup blew up' }
  # The client only ever sees a generic TLS alert -- it has no way to know
  # *why* the server aborted the handshake, same as talking to any real
  # TLS server. What actually has to carry the original exception through
  # is the server side (mrb_tls_sni_cb's own @pending_exception stash,
  # re-raised by mrb_tls_check_pending_exception once mbedtls_ssl_handshake
  # returns).
  assert_kind_of Tls::Error, client_err
  assert_kind_of RuntimeError, server_err
  assert_equal 'sni lookup blew up', server_err.message
end

assert('Tls::Server sni: the block returning something other than a Tls::Config or nil is rejected') do
  client_err, server_err = tls_sni_test_handshake(tls_test_server_config(TLS_TEST_CERT_PEM),
                               tls_test_client_config, 'localhost') { |host| 'not a config' }
  assert_kind_of Tls::Error, client_err
  assert_kind_of Tls::Error, server_err
end

assert('Tls::Server sni: a server with no sni block behaves exactly as before') do
  assert_true tls_test_accepts(tls_test_server_config(TLS_TEST_CERT_PEM),
                               tls_test_client_config, 'localhost')
end
