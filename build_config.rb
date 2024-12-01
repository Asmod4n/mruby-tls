MRuby::Build.new do |conf|
    toolchain :gcc
    conf.enable_sanitizer "address,undefined,leak"
    conf.cc.flags << '-fno-omit-frame-pointer' << '-g' << '-ggdb' << '-Og'
    conf.linker.flags_before_libraries << '-static-libasan'
    #conf.cc.flags << '-Os' << '-march=native'
    conf.enable_debug
    conf.enable_test
    #conf.enable_bintest
    conf.gembox 'full-core'
    conf.gem File.expand_path(File.dirname(__FILE__))
    conf.gem :core => 'mruby-errno'
end
