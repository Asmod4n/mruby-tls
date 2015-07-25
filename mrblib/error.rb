module Tls
  class Error < RuntimeError; end
  class ReadAgain < Error; end
  class WriteAgain < Error; end
end
