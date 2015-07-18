module Tls
  class Context
    alias :recv :read
    alias :send :write
  end
end
