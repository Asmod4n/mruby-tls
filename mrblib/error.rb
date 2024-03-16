module Tls
  class Error < RuntimeError; end
  class Config
    class Error < Tls::Error; end
  end
end
