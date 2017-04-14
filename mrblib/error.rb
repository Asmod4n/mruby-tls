module Tls
  class Error < RuntimeError; end
  class WantPollin < Error; end
  class WantPollout < Error; end
  class Config
    class Error < Tls::Error; end
  end
end
