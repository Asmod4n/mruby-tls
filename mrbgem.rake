require 'rbconfig'

# Rake loads every mrbgem.rake to build its task graph, whatever task was
# asked for, so anything with side effects has to know when the point of
# the run is to remove things rather than build them.
cleaning = Rake.application.top_level_tasks.any? { |t| t =~ /\Aclean|deep_clean\z/ }

MRuby::Gem::Specification.new('mruby-tls') do |spec|
  spec.license = 'Apache-2'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'TLS for mruby - OpenSSL, or Schannel on Windows'

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

  # Everything below is OpenSSL detection, and OpenSSL is not the Windows
  # backend - src/mrb_tls.cpp selects backend_schannel.hpp there, which
  # needs secur32/crypt32 and no pkg-config at all. Probing for libssl on
  # a Windows target would fail the build over a library that target does
  # not use.
  if spec.for_windows?
    spec.linker.libraries += %w[secur32 crypt32 ws2_32]
    next
  end

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

  # LibreSSL answers to `libssl.pc` too, and its own release numbering
  # passed 3.0 years ago - so the `--atleast-version=3.0 libssl` check
  # above, written to mean "OpenSSL 3.0 or newer", is satisfied by any
  # LibreSSL from 3.0 on. The build then gets hundreds of files in before
  # failing on SSL_get1_peer_certificate, an OpenSSL 3.0 rename that
  # LibreSSL still spells SSL_get_peer_certificate. A compile error in a
  # file nobody was editing is a terrible way to find out which TLS
  # library you are building against.
  #
  # The vendor is not something pkg-config reports, so the header is
  # asked instead: an opensslv.h defines LIBRESSL_VERSION_NUMBER if and
  # only if it is LibreSSL's.
  #
  # This rejects rather than shimming. Supporting LibreSSL is a port, not
  # one symbol - SSL_OP_ENABLE_KTLS, one of the two reasons this gem is
  # on OpenSSL at all, does not exist there either.
  incdirs = `pkg-config --cflags-only-I libssl 2>/dev/null`.split
                                                           .grep(/\A-I/) { |f| f[2..] }
  incdirs += ['/usr/local/include', '/usr/include']
  header = incdirs.map { |d| File.join(d, 'openssl', 'opensslv.h') }.find { |f| File.readable?(f) }
  if header && File.read(header).include?('LIBRESSL_VERSION_NUMBER')
    prefix = File.dirname(File.dirname(File.dirname(header)))
    modver = `pkg-config --modversion libssl 2>/dev/null`.strip
    raise <<~MSG
      mruby-tls found LibreSSL, not OpenSSL: #{header}

      pkg-config reports libssl #{modver}, which passes this gem's ">= 3.0"
      check because LibreSSL numbers its own releases 3.x and 4.x. It is a
      different library, and this gem needs OpenSSL 3.0+.

      Something has put a LibreSSL prefix (#{prefix}) ahead of the system
      OpenSSL in pkg-config's search order. To build against the system one
      without removing anything:

        PKG_CONFIG_PATH=$(pkg-config --variable=pcfiledir openssl) rake

      To see what is being picked up and where it came from:

        pkg-config --variable=prefix libssl
        pkg-config --debug libssl 2>&1 | grep -i 'looking\\|found'
    MSG
  end

  # Both, in this order: libssl needs libcrypto, and search_package does not
  # pass --static, so Requires.private is never expanded for us.
  unless spec.search_package('libssl') && spec.search_package('libcrypto')
    raise 'mruby-tls: pkg-config reported OpenSSL >= 3.0 but could not report its flags'
  end
end
