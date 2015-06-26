module Tls
  class Config
    def initialize(options = {})
      super()
      options.each do |k,v|
        case k
        when :ca_file
          self.ca_file = v
        when :ca_path
          self.ca_file = v
        when :cert_file
          self.cert_file = v
        when :cert_mem
          self.cert_mem = v
        when :ciphers
          self.cipers = v
        when :ecdhecurve
          self.ecdhecurve = v
        when :key_file
          self.key_file = v
        when :key_mem
          self.key_mem = v
        when :protocols
          self.protocols = v
        when :verify_depth
          self.verify_depth = v
        else
          raise ArgumentError, "unknown option #{k}"
        end
      end
    end
  end
end
