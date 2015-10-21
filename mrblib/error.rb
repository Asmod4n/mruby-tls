module Tls
  class Error < RuntimeError; end
  class WantPollin < Error; end
  class WantPollout < Error; end
end
