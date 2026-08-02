module Tls
  class Context
    attr_reader :config
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
