$: << '../lib'
$: << '..'
require "active_support"

RSpec.configure do |config|
  config.autoload_paths << Rails.root.join('lib')
end
