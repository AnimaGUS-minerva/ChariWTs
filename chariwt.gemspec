Gem::Specification.new do |s|
  s.name        = 'chariwt'
  s.version     = '0.5.0'
  s.date        = '2017-11-02'
  s.summary     = "Chariot provides a ruby library for managing CWT and JWT base vouchers"
  s.description = "A basic CWT library"
  s.authors     = ["Michael Richardson"]
  s.email       = 'mcr@sandelman.ca'
  s.files       = ["lib/chariwt.rb"]
  s.homepage    = 'https://minerva.sandelman.ca/chariwt/'
  s.license       = 'MIT'
  s.add_dependency('cbor',  '~> 0.5.0')
  s.add_dependency('ecdsa', '~> 1.2.0')
end
