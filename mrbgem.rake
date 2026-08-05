require 'rbconfig'

# Rake loads every mrbgem.rake to build its task graph, whatever task was
# asked for, so anything with side effects has to know when the point of
# the run is to remove things rather than build them.
cleaning = Rake.application.top_level_tasks.any? { |t| t =~ /\Aclean|deep_clean\z/ }

MRuby::Gem::Specification.new('mruby-tls') do |spec|
  spec.license = 'Apache-2'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'mruby bindings to OpenSSL'

  # Declared before the `cleaning` bail-out: the gem graph must look the
  # same whatever task is running, or a clean and a build disagree about
  # which gems exist.
  #
  # mruby-secure-wipe-memory is gone with mbedTLS - OpenSSL owns its key
  # material and wipes it in SSL_CTX_free, so there is nothing here left to
  # scrub by hand.
  spec.add_test_dependency 'mruby-io', :core => 'mruby-io'
  spec.add_test_dependency 'mruby-socket', :core => 'mruby-socket'

  next if cleaning

  # The system OpenSSL, found through pkg-config, and nothing vendored.
  #
  # Linking the system library rather than bundling one is not only about
  # build simplicity: it is what lets a program use this gem *and* another
  # library that links OpenSSL - libpq, libcurl, another mrbgem - in the
  # same process. Two copies of a crypto library answering to the same
  # symbol names is undefined behaviour that surfaces as a corrupted
  # SSL_CTX rather than as a link error, and vendoring is how you get
  # there. It also means CVEs arrive from the distribution instead of from
  # someone here remembering to bump a pin.
  #
  # 3.0 is the floor. Below it the API is different enough to be a separate
  # port, and SSL_OP_ENABLE_KTLS - one of the two reasons to be on OpenSSL
  # at all - does not exist before 3.0.
  #
  # Homebrew's openssl@3 is keg-only: deliberately not symlinked into the
  # prefix, because macOS ships its own TLS and Homebrew will not shadow
  # it. pkg-config therefore cannot see it unless told, and `brew --prefix`
  # is asked rather than a path hardcoded - Apple Silicon is /opt/homebrew,
  # Intel is /usr/local, and either can be relocated.
  if RbConfig::CONFIG['host_os'] =~ /darwin/
    brew = `brew --prefix openssl@3 2>/dev/null`.strip
    if $?.success? && !brew.empty? && File.directory?("#{brew}/lib/pkgconfig")
      ENV['PKG_CONFIG_PATH'] =
        ["#{brew}/lib/pkgconfig", ENV['PKG_CONFIG_PATH']]
          .compact.reject(&:empty?).join(File::PATH_SEPARATOR)
    end
  end

  unless system('pkg-config --atleast-version=3.0 libssl', out: File::NULL, err: File::NULL)
    have = `pkg-config --modversion libssl 2>/dev/null`.strip
    hint =
      case RbConfig::CONFIG['host_os']
      when /darwin/ then 'brew install openssl@3'
      when /linux/  then "install your distribution's OpenSSL development package " \
                         '(libssl-dev, openssl-devel, libopenssl-devel)'
      else 'install OpenSSL 3.0 or newer and put its .pc files on PKG_CONFIG_PATH'
      end
    found = have.empty? ? ' (pkg-config found none)' : ", found #{have}"
    raise "mruby-tls needs OpenSSL >= 3.0#{found}. Try: #{hint}"
  end

  # Both, in this order: libssl needs libcrypto, and search_package does not
  # pass --static, so Requires.private is never expanded for us.
  unless spec.search_package('libssl') && spec.search_package('libcrypto')
    raise 'mruby-tls: pkg-config reported OpenSSL >= 3.0 but could not report its flags'
  end
end
