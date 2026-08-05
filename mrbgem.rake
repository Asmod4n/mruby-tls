require 'rbconfig'
require 'fileutils'

# Array form only -- no shell, so no injection via paths or env vars.
def run!(*args)
  puts ">> #{args.join(' ')}"
  system(*args) or raise "command failed: #{args.join(' ')}"
end

# Rake loads every mrbgem.rake to build its task graph, whatever task was
# asked for - so the work below used to run for `rake clean` and
# `deep_clean` too: a git submodule fetch and a full cmake build of
# mbedTLS, immediately before deleting the result. Skip it when the point
# of the run is to remove things.
cleaning = Rake.application.top_level_tasks.any? { |t| t =~ /\Aclean|deep_clean\z/ }

MRuby::Gem::Specification.new('mruby-tls') do |spec|
  spec.license = 'Apache-2'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'mruby bindings to mbedTLS'

  build_dir   = "#{spec.build_dir}/build/"
  # Real git submodule (mbedTLS 4.x nests its own TF-PSA-Crypto submodule) --
  # pinned past v4.1.1 for fixes on the mbedtls-4.1 branch with no tag yet.
  mbedtls_dir = "#{spec.dir}/deps/mbedtls"
  mbedtls_pin = 'aff01855637364760efdeb02c5674b6fedbb0e0f' # mbedtls-4.1 branch tip as of this pin

  unless cleaning
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

    # mbedTLS 4.x's CMake build needs Python 3 + a handful of packages
    # (jsonschema, Jinja2, ...) for code generation - deps/mbedtls's own
    # scripts/basic.requirements.txt is the authoritative list (it pulls in
    # scripts/driver.requirements.txt in turn), used directly below rather
    # than hand-copied here where it would silently drift out of date -
    # missing a single package from it (jinja2, say) fails a `make` deep
    # inside tf-psa-crypto's code generation with nothing pointing back at
    # "your Python environment is incomplete".
    #
    # ENV['PYTHON3'] is an explicit escape hatch - set it and whatever
    # interpreter it names is trusted as-is, requirements included, no venv
    # involved. Otherwise, everything goes into a small venv scoped to this
    # gem's own build directory rather than assuming (or worse, pip-
    # installing into) whatever Python the system happens to have - many
    # distros (openSUSE included) refuse a bare `pip install` outside a venv
    # at all (PEP 668's "externally managed environment"), and even where
    # it's allowed, there's no reason for a one-off build dependency to end
    # up on the system interpreter's global site-packages.
    #
    # Lives outside build_dir (not under it) so bumping mbedtls_pin's own
    # FileUtils.rm_rf(build_dir) above doesn't force recreating the venv and
    # reinstalling every package each time the pin moves - the venv has
    # nothing to do with which mbedTLS commit is checked out.
    mbedtls_requirements = "#{mbedtls_dir}/scripts/basic.requirements.txt"
    if ENV['PYTHON3']
      python3 = ENV['PYTHON3']
    else
      pyenv_dir = "#{spec.build_dir}/pyenv"
      python3 = RbConfig::CONFIG['host_os'] =~ /mswin|mingw/ ?
        "#{pyenv_dir}/Scripts/python.exe" : "#{pyenv_dir}/bin/python3"
      unless File.file?(python3)
        run!('python3', '-m', 'venv', pyenv_dir)
      end
      unless system(python3, '-c', 'import jsonschema, jinja2', :err => File::NULL)
        run!(python3, '-m', 'pip', 'install', '--quiet', '-r', mbedtls_requirements)
      end
    end
    unless system(python3, '-c', 'import jsonschema, jinja2', :err => File::NULL)
      raise "mruby-tls: #{python3} needs the packages listed in #{mbedtls_requirements} " \
            "to build mbedTLS 4.x (pip install -r #{mbedtls_requirements}), " \
            "or set PYTHON3 to an interpreter that already has them"
    end

    # Real MSVC only -- MinGW/Cygwin fall through to the else branch below.
    is_msvc = RbConfig::CONFIG['host_os'] =~ /mswin/

    if is_msvc
      libext   = '.lib'
      prefix   = ''
    else
      libext   = '.a'
      prefix   = 'lib'
    end
    # mbedtls/mbedx509/mbedcrypto are load-bearing -- mrb_tls.cpp links
    # against all three directly (see the flags_before_libraries call below)
    # and nothing here works without them. everest/p256m are optional bundled
    # Curve25519/P-256 backends, only present for some build configurations,
    # and never required for a link to succeed.
    required_libnames = %w[mbedtls mbedx509 mbedcrypto]
    optional_libnames = %w[everest p256m]
    libnames = required_libnames + optional_libnames

    # Where the archives land is CMake's decision, so ask CMake instead of
    # guessing: GNUInstallDirs picks lib64 on 64-bit openSUSE/Fedora/RHEL
    # and lib on Debian/Ubuntu, and it records what it chose in the build
    # tree's CMakeCache.txt as CMAKE_INSTALL_LIBDIR. Hardcoding either name
    # builds fine on half the distros and then reports a perfectly good
    # build's libraries "missing" on the other half - with cmake and make
    # both having exited 0, which sends you hunting an OOM that never
    # happened.
    #
    # The invocation below pins CMAKE_INSTALL_LIBDIR=lib so fresh builds
    # agree everywhere, but a tree configured before that pin still says
    # what it actually did, and this reads that rather than assuming it.
    #
    # No cache means nothing has been configured yet, so nothing is built
    # either - any answer works there, since it only has to fail the
    # existence check below and trigger the build.
    resolve_libpath = lambda do
      cache = "#{build_dir}/CMakeCache.txt"
      dir = 'lib'
      if File.file?(cache)
        line = File.foreach(cache).find { |l| l.start_with?('CMAKE_INSTALL_LIBDIR:') }
        dir = line.split('=', 2).last.strip if line
      end
      # CMAKE_INSTALL_LIBDIR is normally relative to the install prefix,
      # but it is allowed to be absolute.
      dir =~ %r{\A(/|[A-Za-z]:[\\/])} ? dir : "#{build_dir}/#{dir}"
    end
    libpath = resolve_libpath.call
    required_libpaths = required_libnames.map { |n| "#{libpath}/#{prefix}#{n}#{libext}" }

    # All three required libs, not just one -- a build interrupted partway
    # through (OOM, disk full, Ctrl-C) can leave libmbedtls.a sitting there
    # without libmbedcrypto.a/libmbedx509.a ever having been produced, and
    # checking only the first of them would treat that as "already built"
    # forever after, silently linking short every time - a mystifying wall of
    # "undefined reference" from mrb_tls.cpp instead of a rebuild.
    unless required_libpaths.all? { |p| File.file?(p) }
      FileUtils.mkdir_p(build_dir)
      Dir.chdir(build_dir) do
        cmake_args = [
          mbedtls_dir,
          "-DCMAKE_INSTALL_PREFIX=#{build_dir}",
          # Without this GNUInstallDirs installs to lib64 on 64-bit
          # openSUSE/Fedora/RHEL and to lib on Debian/Ubuntu. Pin it so
          # every distro puts the archives in the same place.
          '-DCMAKE_INSTALL_LIBDIR=lib',
          '-DCMAKE_BUILD_TYPE=Release',
          '-DCMAKE_POSITION_INDEPENDENT_CODE=ON',
          # Test suites/sample programs need the "framework" submodule; skip.
          '-DENABLE_TESTING=OFF',
          '-DENABLE_PROGRAMS=OFF',
          '-DUSE_STATIC_MBEDTLS_LIBRARY=ON',
          '-DUSE_SHARED_MBEDTLS_LIBRARY=OFF',
          '-DMBEDTLS_FATAL_WARNINGS=OFF',
          # Pins CMake's own FindPython3 to the exact interpreter jsonschema
          # was just confirmed importable on above (our venv, unless
          # PYTHON3 overrides it) - without this, CMake resolves Python3
          # from PATH on its own and code generation can end up running
          # under a *different*, jsonschema-less interpreter than the one
          # this script just checked.
          "-DPython3_EXECUTABLE=#{python3}"
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

      # cmake/make/make install can all exit 0 (nothing above raises) and
      # still not have produced every required library - e.g. a dependency
      # CMake silently skips a subdirectory on a `find_package` miss, or
      # `make` genuinely finished building everything it was asked to but a
      # prior partial build's now-stale object files short-circuited part of
      # the dependency graph. Either way, catch it *here*, loudly, with the
      # exact missing path named - not as a wall of "undefined reference to
      # mbedtls_ssl_*" out of the final mrbtest/mruby link, several build
      # steps and zero useful context later.
      # Ask again now that cmake has actually configured: before this ran
      # there was no cache to read, so the paths above were a placeholder.
      # libpath feeds the linker flags further down as well as the check
      # below, so this updates it rather than just the check.
      libpath = resolve_libpath.call
      required_libpaths = required_libnames.map { |n| "#{libpath}/#{prefix}#{n}#{libext}" }

      missing = required_libpaths.reject { |p| File.file?(p) }
      unless missing.empty?
        raise "mruby-tls: mbedTLS build finished without producing:\n" \
              "#{missing.map { |p| "  #{p}" }.join("\n")}\n" \
              "cmake/make reported success above, so this is a partial/interrupted build " \
              "(OOM, disk full, a skipped CMake subdirectory, ...), not a compile error - " \
              "delete #{build_dir} and rebuild with more memory/disk, or re-run cmake by " \
              "hand from #{build_dir} to see what it actually configured.\n" \
              "(CMAKE_INSTALL_LIBDIR in #{build_dir}/CMakeCache.txt puts them in #{libpath}.)"
      end
    end
  end

  # Take cflags and ldflags from mbedTLS's own pkg-config files rather than
  # reconstructing them here. CMake writes .pc files describing exactly what
  # it built and where it put it, so this stops being our guess about
  # lib-vs-lib64, archive naming, and which libraries a given configuration
  # actually produced.
  #
  # Both pkgconfig directories, because they differ: the installed set under
  # CMAKE_INSTALL_LIBDIR is complete, while the build-tree copy is missing
  # mbedcrypto.pc - tf-psa-crypto configures its own in a subdirectory.
  # Installed first so it wins.
  #
  # Named individually and in dependency order, because these are static
  # archives and search_package does not pass --static, so Requires.private
  # is never expanded for us. mbedtls, mbedx509, mbedcrypto resolves to
  # -lmbedtls -lmbedx509 -ltfpsacrypto, which is exactly the chain
  # MbedTLSTargets.cmake declares - there is no mbedcrypto target in 4.x at
  # all, and mbedcrypto.pc is a compatibility alias for tfpsacrypto.
  #
  # Guarded on `cleaning` because libpath/libnames are assigned inside the
  # block above and are nil on a clean run - libnames.map would raise
  # NoMethodError before rake deleted anything. A clean needs no flags.
  unless cleaning
    pkgconfig_dirs = ["#{libpath}/pkgconfig", "#{build_dir}/pkgconfig"].select { |d| File.directory?(d) }
    found_via_pkgconfig = false
    unless pkgconfig_dirs.empty?
      ENV['PKG_CONFIG_PATH'] =
        (pkgconfig_dirs + [ENV['PKG_CONFIG_PATH']]).compact.reject(&:empty?).join(File::PATH_SEPARATOR)
      found_via_pkgconfig = %w[mbedtls mbedx509 mbedcrypto].map { |pkg| spec.search_package(pkg) }.all?
    end

    unless found_via_pkgconfig
      # No pkg-config on this host (MSVC especially), or a build predating
      # the .pc files. What this gem did before.
      [spec.cc, spec.cxx].each do |cmd|
        cmd.include_paths << "#{build_dir}/include"
      end
    end
  end

  # Expose mbedTLS's own headers to dependent gems, the same way
  # mruby-io-uring exposes liburing's and mruby-wslay exposes wslay's:
  # the include_paths just above only ever reach *this* gem's own
  # compilation, but every mrbgem's include/ directory is on every other
  # gem's search path unconditionally. Copying them there is what lets a
  # dependent gem call mbedtls_*/psa_* directly from its own C/C++ - an
  # adapter terminating TLS inside its own event loop, say, driving the
  # handshake through a memory BIO instead of this gem's Ruby API.
  #
  # Taken from the install prefix rather than deps/mbedtls's source tree
  # because mbedTLS 4.x generates a good part of its public headers at
  # build time (tf-psa-crypto's especially); only what `make install`
  # actually put there is the real, configured set. Copied rather than
  # symlinked so what lands here is a snapshot of this build.
  #
  # Only the three header trees: the same prefix also holds CMake's own
  # leftovers (CMakeFiles/, Makefile, cmake_install.cmake), which are not
  # headers and have no business on anyone's include path.
  #
  # Build output, regenerated every build - not tracked source, and this
  # gem's own public header (include/mruby/tls.h) stays tracked. See
  # .gitignore.
  exposed_include = "#{spec.dir}/include"
  unless cleaning
    FileUtils.mkdir_p(exposed_include)
    %w[mbedtls psa tf-psa-crypto].each do |header_dir|
      src = "#{build_dir}/include/#{header_dir}"
      FileUtils.cp_r(src, exposed_include) if File.directory?(src)
    end
  end

  # mbedTLS splits into three static libraries; mbedtls depends on mbedx509
  # which depends on mbedcrypto, so they have to be listed in that order.
  # everest/p256m are the optional bundled Curve25519/P-256 backends and are
  # only present (and only referenced) for some build configurations - the
  # `select` here is fine for those precisely because they're optional;
  # mbedtls/mbedx509/mbedcrypto themselves are already guaranteed present
  # by the check above, every time, not just on a from-scratch build.
  # Only when pkg-config did not already supply them (see above).
  if !cleaning && !found_via_pkgconfig
    spec.linker.flags_before_libraries += libnames.map { |n|
      "#{libpath}/#{prefix}#{n}#{libext}"
    }.select { |p| File.file?(p) }
  end

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
