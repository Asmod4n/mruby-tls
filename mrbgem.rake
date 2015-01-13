MRuby::Gem::Specification.new('tls') do |spec|
  spec.license = 'Apache-2'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'mruby bindings to libtls'
  spec.linker.libraries << 'tls' << 'ssl' << 'crypto'
end
