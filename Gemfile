source 'https://rubygems.org'

gem "cbor",  "~> 0.5.9.2"
gem 'cbor-diag', :git => 'https://github.com/AnimaGUS-minerva/cbor-diag', :branch => 'put-pretty-extract-into-library'
gem "json"
gem 'jwt'
#gem 'openssl', :git => 'https://github.com/mcr/ruby-openssl.git'
gem 'openssl', :path => '../minerva/ruby-openssl'

gem 'ecdsa',   :git => 'https://github.com/AnimaGUS-minerva/ruby_ecdsa.git', :branch => 'ecdsa_interface_openssl'
#gem 'ecdsa',   :path => '../minerva/ruby_ecdsa'
#gem 'ecdsa', "~> 1.3.0"
gem 'rbnacl-libsodium'
gem 'rbnacl', "<5.0.0"
gem 'rake'

# dependabot reports
gem 'tzinfo', "~> 2.0"

# for acts_like?
gem 'activesupport', "~> 6.1.7.1"

group :test do
  gem 'byebug'
  gem "rspec"
  gem "rspec-core"
  gem "rspec_junit_formatter"
end
