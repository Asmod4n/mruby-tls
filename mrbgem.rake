MRuby::Gem::Specification.new('mruby-tls') do |spec|
  spec.license = 'Apache-2'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'mruby bindings to libtls'

  unless File.file? "#{spec.build_dir}/build/lib/libtls.a"
    command = "mkdir -p #{spec.build_dir}/build && cd #{spec.dir}/deps/libressl-4.0.0/ &&"
    command << " ./configure --prefix=\"#{spec.build_dir}/build\" "
    command << "--enable-shared=no && make -j$(nproc) check && make -j$(nproc) install && make -j$(nproc) distclean"
    sh command
  end

  ENV['PKG_CONFIG_PATH'] = "#{spec.build_dir}/build/lib/pkgconfig:" + (ENV['PKG_CONFIG_PATH'] || '')

  spec.cc.flags += [`pkg-config --static --cflags libtls`.strip]
  spec.linker.flags += [`pkg-config --static --libs-only-L libtls`.strip]
  spec.linker.flags_before_libraries += [
    "#{spec.build_dir}/build/lib/libtls.a",
    "#{spec.build_dir}/build/lib/libssl.a",
    "#{spec.build_dir}/build/lib/libcrypto.a"
  ]
  spec.add_dependency 'mruby-errno'
end
