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

    def x509privkey
      @x509privkey ||= File.open(File.join('spec','files', 'jrc_prime256v1.key'),'r') do |f|
        OpenSSL::PKey.read(f)
      end
    end

    def x509pubkey
      @x509pubkey ||= File.open(File.join('spec','files', 'jrc_prime256v1.crt'),'r') do |f|
        OpenSSL::X509::Certificate.new(f)
      end
    end

    it "should load a PEM format public ECDSA key, and convert to ECDSA library format key" do
      bx = x509pubkey.public_key.public_key.to_bn
      grp= x509pubkey.public_key.public_key.group
      point = ECDSA::Format::PointOctetString.decode_from_ssl(bx, grp)
      expect(point.x).to eq(24149367853196172407516369164818134874115917319726245901277420101925932861939)
      expect(point.y).to eq(24301566557813834627157509343720702610696899744154898312596647260394512104626)
    end

    it "should load a PEM format private ECDSA key, and convert to ECDSA library format key" do
      bx = x509privkey.private_key
      grp= x509privkey.group
      point = ECDSA::Format::PointOctetString.decode_priv_from_ssl(bx, grp)
      expect(point).to eq(43267311109421873114136538554130841682863264975574020465662202951949662337431)
    end

  end

end
