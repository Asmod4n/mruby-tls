module Tls
  class Config
    def self.new(options = {})
      instance = super()
      options.each do |k,v|
        case k
        when :ca_file
          instance.ca_file = v
        when :ca_path
          instance.ca_file = v
        when :cert_file
          instance.cert_file = v
        when :cert_mem
          instance.cert_mem = v
        when :ciphers
          instance.cipers = v
        when :ecdhecurve
          instance.ecdhecurve = v
        when :key_file
          instance.key_file = v
        when :key_mem
          instance.key_mem = v
        when :protocols
          instance.protocols = instance.parse_protocols(v)
        when :verify_depth
          instance.verify_depth = v
        else
          raise ArgumentError, "unknown option #{k}"
        end
      end
      instance
    end
  end
end
