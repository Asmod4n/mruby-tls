module Tls
  class Config
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
