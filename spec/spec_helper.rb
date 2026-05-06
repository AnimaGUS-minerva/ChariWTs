$: << '../lib'
$: << '..'
require "logger" # Fix concurrent-ruby removing logger dependency which Rails itself does not have
require "active_support"

RSpec.configure do |config|
  config.autoload_paths << Rails.root.join('lib')
end
