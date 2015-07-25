module Tls
  class Context
    attr_reader :config
    alias :recv :read
    alias :send :write

    def self.new(config = nil)
      case config
      when Config
        super(config)
      when Hash
        super(Config.new(config))
      when NilClass
        super()
      else
        raise ArgumentError, "Cannot handle #{config.class}"
      end
    end
  end
end
