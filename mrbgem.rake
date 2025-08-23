require 'rbconfig'
require 'fileutils'

def run!(cmd)
  puts ">> #{cmd}"
  system(cmd) or raise "command failed: #{cmd}"
end

MRuby::Gem::Specification.new('mruby-tls') do |spec|
  spec.license = 'Apache-2'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'mruby bindings to libtls'

  build_dir    = "#{spec.build_dir}/build/"
  libressl_dir = "#{spec.dir}/deps/libressl-4.0.0"

  is_windows = RbConfig::CONFIG['host_os'] =~ /mswin|mingw|cygwin/

  if is_windows
    libext  = ".lib"
    libpath = "#{build_dir}/lib"
    libtls  = "#{libpath}/tls#{libext}"
  else
    libext  = ".a"
    libpath = "#{build_dir}/lib64"
    libtls  = "#{libpath}/libtls#{libext}"
  end

  unless File.file?(libtls)
    FileUtils.mkdir_p(build_dir)
    Dir.chdir(build_dir) do
      run! "cmake \"#{libressl_dir}\" -DCMAKE_INSTALL_PREFIX=\"#{build_dir}\""
      if is_windows
        run! "cmake --build . --config Release --target install"
      else
        run! "make -j$(nproc)"
        run! "make test"
        run! "make install"
      end
    end
  end

  unless is_windows
    ENV['PKG_CONFIG_PATH'] = "#{build_dir}/pkgconfig:" + (ENV['PKG_CONFIG_PATH'] || '')
    spec.cxx.flags += [`pkg-config --static --cflags libtls`.strip]
    spec.linker.flags += [`pkg-config --static --libs-only-L libtls`.strip]
  end

  spec.linker.flags_before_libraries += [
    "#{libpath}/libtls#{libext}",
    "#{libpath}/libssl#{libext}",
    "#{libpath}/libcrypto#{libext}"
  ]

  spec.add_dependency 'mruby-errno'
end
