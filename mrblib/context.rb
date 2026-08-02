module Tls
  class Context
    attr_reader :config
    # Whatever a caller wants attached to this connection - opaque to
    # mruby-tls itself. Set once (e.g. right after #connect_socket/
    # #accept_socket) and mrb_tls_bio_send()/_recv() (src/mrb_tls.cpp)
    # copy it onto every IO::Uring::Operation they submit internally
    # through the underlying socket's own #send/#recv, so a caller
    # driving its own IO::Uring event loop can key off op.userdata for a
    # TLS connection's ciphertext I/O exactly the same way it already
    # does for a plain one's - no separate tracking needed on top of
    # whatever completion-dispatch mechanism it already has.
    attr_accessor :userdata
    alias :recv :read
    alias :send :write
    alias :config= :configure

    def self.new(config = nil)
      case config
      when Config
        super(config)
      when Enumerable
        super(Config.new(config))
      when NilClass
        super()
      else
        raise ArgumentError, "Cannot handle #{config.class.dump}"
      end
    end
  end

  class Client < Context
    # Splits a combined "host:port"/"[v6::addr]:port" string when no
    # separate port is given, then hands both to the C-level _connect.
    def connect(host, port = nil)
      if port.nil?
        if host[0] == '['
          close = host.index(']')
          raise Tls::Error, 'no port provided' unless close
          h = host[1...close]
          rest = host[close..-1]
        else
          h = nil
          rest = host
        end
        sep = rest.index(':')
        raise Tls::Error, 'no port provided' unless sep
        p = rest[(sep + 1)..-1]
        raise Tls::Error, 'no port provided' if p.include?(':')
        h = rest[0...sep] if h.nil?
        host, port = h, p
      end
      _connect(host, port)
    end
  end
end
