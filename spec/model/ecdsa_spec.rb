require 'lib/c_hex'
require 'lib/chariwt'
require 'cbor'
require 'base64'
require 'ecdsa'
require 'byebug'
require 'json'
require 'spec/model/test_keys'

RSpec.describe CHex do

  include Testkeys
  describe "converting" do

    def x509pubkey
      File.open(File.join('spec','files', 'jrc_prime256v1.crt'),'r') do |f|
        OpenSSL::X509::Certificate.new(f)
      end
    end

    it "should load a PEM format ECDSA key, and convert to ECDSA library key" do
      bx = x509pubkey.public_key.public_key.to_bn
      grp= x509pubkey.public_key.public_key.group
      point = ECDSA::Format::PointOctetString.decode_from_ssl(bx, grp)
      byebug
      expect(thing).to be big

      pending "it shold be simple to convert, but it is not obvious"
    end
  end

end
