module Tls
  class Config
    PROTOCOL_ALIASES = {
      'all' => Protocol::All, 'legacy' => Protocol::All,
      'default' => Protocol::Default, 'secure' => Protocol::Default,
      'tlsv1' => Protocol::TLSv1,
      'tlsv1.0' => Protocol::TLSv1_0,
      'tlsv1.1' => Protocol::TLSv1_1,
      'tlsv1.2' => Protocol::TLSv1_2,
      'tlsv1.3' => Protocol::TLSv1_3,
    }.freeze

    CIPHER_KEYWORDS = %w[default secure compat legacy insecure all].freeze

    def ciphers=(spec)
      if CIPHER_KEYWORDS.include?(spec.downcase)
        @ciphersuites = nil
        return spec
      end
      names = spec.split(/[:,]/).map(&:strip).reject(&:empty?)
      raise Tls::Config::Error, 'no cipher suites selected' if names.empty?
      @ciphersuites = _pack_ciphersuites(names)
      spec
    end

    ECDHE_CURVE_ALIASES = {
      'prime256v1' => 'secp256r1', 'p-256' => 'secp256r1',
      'p-384' => 'secp384r1', 'p-521' => 'secp521r1',
      'x25519' => 'x25519', 'x448' => 'x448',
    }.freeze

    def ecdhecurve=(spec)
      down = spec.downcase
      if down == 'auto' || down == 'default'
        @groups = nil
        return spec
      end
      if down == 'none'
        raise Tls::Config::Error, "ecdhecurve 'none' is not supported"
      end
      names = spec.split(/[:,]/).map(&:strip).reject(&:empty?)
      raise Tls::Config::Error, 'no ecdhe curves selected' if names.empty?
      names = names.map { |n| ECDHE_CURVE_ALIASES[n.downcase] || n }
      @groups = _pack_groups(names)
      spec
    end

    def parse_protocols(protostr)
      protos = 0
      protostr.split(/[:,]/).each do |tok|
        tok = tok.strip
        negate = tok[0] == '!'
        tok = tok[1..-1] if negate
        protos = Protocol::All if negate && protos == 0
        proto = PROTOCOL_ALIASES[tok.downcase]
        raise Tls::Config::Error, 'invalid protocol string' unless proto
        if negate
          protos &= ~proto
        else
          protos |= proto
        end
      end
      protos
    end

    def self.new(options = {})
      instance = super()
      options.each do |k,v|
        case k
        when :ca_file
          instance.ca_file = v
        when :ca_path
          instance.ca_path = v
        when :cert_file
          instance.cert_file = v
        when :cert_mem
          instance.cert_mem = v
        when :ciphers
          instance.ciphers = v
        when :ecdhecurve
          instance.ecdhecurve = v
        when :key_file
          instance.key_file = v
        when :key_mem
          instance.key_mem = v
        when :protocols
          if v.is_a?(Numeric)
            instance.protocols = v
          else
            instance.protocols = instance.parse_protocols(v)
          end
        when :verify_depth
          instance.verify_depth = v
        when :noverify
          if v == true
            instance.noverify('cert')
          else
            instance.noverify(v)
          end
        else
          raise ArgumentError, "unknown option #{k.dump}"
        end
      end
      instance
    end
  end
end
