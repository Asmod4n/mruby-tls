require 'rbconfig'
require 'fileutils'

# Array form only -- no shell, so no injection via paths or env vars.
def run!(*args)
  puts ">> #{args.join(' ')}"
  system(*args) or raise "command failed: #{args.join(' ')}"
end

MRuby::Gem::Specification.new('mruby-tls') do |spec|
  spec.license = 'Apache-2'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'mruby bindings to mbedTLS'

  build_dir   = "#{spec.build_dir}/build/"
  # Real git submodule (mbedTLS 4.x nests its own TF-PSA-Crypto submodule) --
  # pinned past v4.1.1 for fixes on the mbedtls-4.1 branch with no tag yet.
  mbedtls_dir = "#{spec.dir}/deps/mbedtls"
  mbedtls_pin = 'aff01855637364760efdeb02c5674b6fedbb0e0f' # mbedtls-4.1 branch tip as of this pin

  # Runs from the superproject root first: on a fresh clone (no
  # --recurse-submodules) deps/mbedtls has no .git of its own yet, and
  # `git rev-parse HEAD` inside it would resolve through the superproject.
  Dir.chdir(spec.dir) do
    run!('git', 'submodule', 'update', '--init', '--recursive', '--', 'deps/mbedtls')
  end

  # Re-verified on every build (not just when CMakeLists.txt is missing) so
  # bumping mbedtls_pin can't become a silent no-op on an already-built tree.
  mbedtls_pin_ok = Dir.chdir(mbedtls_dir) { `git rev-parse HEAD`.strip == mbedtls_pin }
  unless mbedtls_pin_ok
    Dir.chdir(mbedtls_dir) do
      run!('git', 'checkout', mbedtls_pin)
      run!('git', 'submodule', 'update', '--init', '--recursive')
    end
    FileUtils.rm_rf(build_dir)
  end

  unless File.file?("#{mbedtls_dir}/CMakeLists.txt")
    raise "mruby-tls: #{mbedtls_dir}/CMakeLists.txt missing after submodule update -- " \
          "is deps/mbedtls initialized?"
  end

  # mbedTLS 4.x's CMake build needs Python 3 + jsonschema; checked up front
  # for a clear message instead of a mid-build traceback.
  python3 = ENV['PYTHON3'] || 'python3'
  unless system(python3, '-c', 'import jsonschema', :err => File::NULL)
    raise "mruby-tls: #{python3} with the 'jsonschema' package is required to build mbedTLS 4.x " \
          "(pip install jsonschema), or set PYTHON3 to an interpreter that has it"
  end

  # Real MSVC only -- MinGW/Cygwin fall through to the else branch below.
  is_msvc = RbConfig::CONFIG['host_os'] =~ /mswin/

  if is_msvc
    libext  = '.lib'
    libpath = "#{build_dir}/lib"
    libtls  = "#{libpath}/mbedtls#{libext}"
    libnames = %w[mbedtls mbedx509 mbedcrypto everest p256m]
  else
    libext  = '.a'
    libpath = "#{build_dir}/lib"
    libtls  = "#{libpath}/libmbedtls#{libext}"
    libnames = %w[libmbedtls libmbedx509 libmbedcrypto libeverest libp256m]
  end

  unless File.file?(libtls)
    FileUtils.mkdir_p(build_dir)
    Dir.chdir(build_dir) do
      cmake_args = [
        mbedtls_dir,
        "-DCMAKE_INSTALL_PREFIX=#{build_dir}",
        '-DCMAKE_BUILD_TYPE=Release',
        '-DCMAKE_POSITION_INDEPENDENT_CODE=ON',
        # Test suites/sample programs need the "framework" submodule; skip.
        '-DENABLE_TESTING=OFF',
        '-DENABLE_PROGRAMS=OFF',
        '-DUSE_STATIC_MBEDTLS_LIBRARY=ON',
        '-DUSE_SHARED_MBEDTLS_LIBRARY=OFF',
        '-DMBEDTLS_FATAL_WARNINGS=OFF'
      ]
      if is_msvc
        # mruby compiles /MD; mbedTLS defaults to /MT on MSVC, which would
        # LNK2038-mismatch. CMP0091=NEW is needed for the runtime-library
        # setting to take effect at all.
        cmake_args += [
          '-DCMAKE_POLICY_DEFAULT_CMP0091=NEW',
          '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL'
        ]
      end
      run!('cmake', *cmake_args)
      if is_msvc
        run!('cmake', '--build', '.', '--config', 'Release', '--target', 'install')
      else
        jobs = Integer(ENV['MRUBY_TLS_JOBS'] || `nproc`.strip)
        run!('make', "-j#{jobs}")
        run!('make', 'install')
      end
    end
  end

  [spec.cc, spec.cxx].each do |cmd|
    cmd.include_paths << "#{build_dir}/include"
  end

  # mbedTLS splits into three static libraries; mbedtls depends on mbedx509
  # which depends on mbedcrypto, so they have to be listed in that order.
  # libeverest/libp256m are the optional bundled Curve25519/P-256 backends and
  # are only present (and only referenced) for some build configurations.
  spec.linker.flags_before_libraries += libnames.map { |n|
    "#{libpath}/#{n}#{libext}"
  }.select { |p| File.file?(p) }

  if is_msvc
    # ws2_32: Winsock (mbedtls_net_connect() and our own send()/recv()/
    # closesocket() in src/mrb_tls.cpp). crypt32: CertOpenStore() and friends,
    # used to seed Config's default trust store from the Windows "ROOT"
    # certificate store -- see mrb_tls_load_ca_system_store_win32().
    spec.linker.flags_before_libraries += %w[ws2_32.lib crypt32.lib]
  else
    # What this gem is actually being built *for* -- host_target on a
    # MRuby::CrossBuild, the same thing mruby's own Gem::Specification#
    # for_windows? checks -- not RbConfig::CONFIG['host_os'], which only
    # ever describes the Ruby interpreter running this Rakefile and says
    # nothing about a cross build's target.
    target_os = if spec.build.kind_of?(MRuby::CrossBuild) && spec.build.host_target
                  spec.build.host_target
                else
                  RbConfig::CONFIG['host_os']
                end
    if target_os =~ /linux/
      # pthread_atfork() (mrb_tls_atfork_child(), src/mrb_tls.cpp) needs
      # libpthread explicitly on some Linux libcs (glibc < 2.34, musl);
      # macOS/BSD ship it as part of libc and need no extra flag, and
      # mrb_tls_atfork_child() is itself compiled out on Windows.
      spec.linker.flags_before_libraries += %w[-lpthread]
    end
  end

  spec.add_dependency 'mruby-errno'
  # Sensitive key material (Config#cert_mem=/#key_mem=, Tls.load_file's
  # password-protected key path) is wiped via this gem's mrb_secure_wipe_memory()
  # rather than a hand-rolled memset -- the same volatile-function-pointer /
  # SecureZeroMemory / explicit_bzero / memset_s dance every other gem in
  # this ecosystem that needs to securely erase memory already shares.
  spec.add_dependency 'mruby-secure-wipe-memory', :github => 'Asmod4n/mruby-secure-wipe-memory'

  # test/tls.rb drives a real handshake between an in-process Tls::Server and
  # Tls::Client over a loopback socket, and needs a file to point ca_file= at.
  spec.add_test_dependency 'mruby-io', :core => 'mruby-io'
  spec.add_test_dependency 'mruby-socket', :core => 'mruby-socket'
end
