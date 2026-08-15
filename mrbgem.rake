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

  # WHICH LIBRARY, BEFORE WHICH VERSION - because the version alone cannot
  # tell them apart. LibreSSL answers to libssl.pc as well and numbers its
  # own releases 3.x and 4.x, so a plain `--atleast-version=3.0 libssl` is
  # satisfied by either one while meaning something different about each.
  #
  # pkg-config does not report a vendor, so the header is asked instead:
  # opensslv.h defines LIBRESSL_VERSION_NUMBER if and only if it is
  # LibreSSL's.
  incdirs = `pkg-config --cflags-only-I libssl 2>/dev/null`.split
                                                           .grep(/\A-I/) { |f| f[2..] }
  incdirs += ['/usr/local/include', '/usr/include']
  header = incdirs.map { |d| File.join(d, 'openssl', 'opensslv.h') }.find { |f| File.readable?(f) }
  libressl = header && File.read(header).include?('LIBRESSL_VERSION_NUMBER')
  modver = `pkg-config --modversion libssl 2>/dev/null`.strip

  if libressl
    # ACCEPTED, where it used to be refused. The old text here said
    # "supporting LibreSSL is a port, not one symbol". That was wrong, and
    # measuring it rather than assuming is what settled it: of the 89
    # OpenSSL names this gem uses, LibreSSL 4.3.2 is missing three, and two
    # of those are only mentioned in comments. The single real gap is
    # SSL_get1_peer_certificate, aliased in backend_openssl.hpp.
    #
    # The reason to accept rather than to keep refusing is not the size of
    # the diff. A distribution that ships LibreSSL as its system TLS makes
    # this every user's first build, and telling them to replace their
    # distribution's TLS package to compile a gem is not an answer.
    #
    # 4.0 is the floor because 4.3.2 is what the symbol survey was run
    # against. Older LibreSSL may well work - nobody has checked, and a
    # named floor is a better failure than a compile error in a file the
    # user was not editing.
    unless system('pkg-config --atleast-version=4.0 libssl', out: File::NULL, err: File::NULL)
      raise <<~MSG
        mruby-tls found LibreSSL #{modver}, and needs >= 4.0.

        Header: #{header}

        LibreSSL is supported, but only 4.x has been verified against this
        gem's symbol requirements. If you need an older one, run the symbol
        survey and report what is missing rather than lowering this floor
        blindly.
      MSG
    end
  else
    unless system('pkg-config --atleast-version=3.0 libssl', out: File::NULL, err: File::NULL)
      hint =
        case RbConfig::CONFIG['host_os']
        when /darwin/ then 'brew install openssl@3'
        when /linux/  then "install your distribution's OpenSSL development package " \
                           '(libssl-dev, openssl-devel, libopenssl-devel)'
        else 'install OpenSSL 3.0 or newer and put its .pc files on PKG_CONFIG_PATH'
        end
      found = modver.empty? ? ' (pkg-config found none)' : ", found #{modver}"
      raise "mruby-tls needs OpenSSL >= 3.0#{found}. Try: #{hint}"
    end
  end

  # kTLS is a CAPABILITY, not a baseline. SSL_OP_ENABLE_KTLS does not exist
  # in LibreSSL, and backend_openssl.hpp already guards it with #ifdef - so
  # a LibreSSL build simply does not ask OpenSSL to install kTLS itself.
  #
  # That costs less than it sounds: the option only ever did anything on the
  # socket-BIO path, and the memory-BIO path this gem exists for extracts key
  # material through mrb_tls_ktls_tx_params and installs kTLS itself. Every
  # symbol that path needs is present in LibreSSL.
  spec.cc.defines << 'MRUBY_TLS_LIBRESSL' if libressl

  # Both, in this order: libssl needs libcrypto, and search_package does not
  # pass --static, so Requires.private is never expanded for us.
  unless spec.search_package('libssl') && spec.search_package('libcrypto')
    raise "mruby-tls: pkg-config reported #{libressl ? 'LibreSSL' : 'OpenSSL'} " \
          "#{modver} but could not report its flags"
  end
end
