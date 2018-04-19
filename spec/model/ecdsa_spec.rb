require 'c_hex'
require 'chariwt'
require 'cbor'
require 'base64'
require 'ecdsa'
require 'byebug'
require 'json'
require 'model/test_keys'

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
      point = ECDSA::Format::PubKey.decode(x509pubkey)
      expect(point.class).to eq(ECDSA::Point)
      expect(point.x).to eq(24149367853196172407516369164818134874115917319726245901277420101925932861939)
      expect(point.y).to eq(24301566557813834627157509343720702610696899744154898312596647260394512104626)
    end

    it "should load a PEM format private ECDSA key, and convert to ECDSA library format key" do
      (privkey,group) = ECDSA::Format::PrivateKey.decode(x509privkey)
      expect(privkey).to eq(43267311109421873114136538554130841682863264975574020465662202951949662337431)
    end

    def coseobject02_digest
      "846a5369676e61747572653143a101264074546869732069732074686520636f6e74656e742e"
    end

    def coseobject02_sha256
      "c85fec6f6115d030389f87c76e7712dcc695a9227d2bfc371b6685caa638c7ca"
    end

    it "should sign object with ECDSA key from PEM" do
      signed = Chariwt::CoseSign1.new

      signed.content = "This is the content."
      signed.protected_bucket[1] = -7

      (privkey,group) = ECDSA::Format::PrivateKey.decode(x509privkey)
      signed.generate_signature(group, privkey, temporary_key)

      expect(signed.digested.unpack("H*")[0]).to eq(coseobject02_digest)
      expect(signed.digest.unpack("H*")[0]).to   eq(coseobject02_sha256)
      expect(signed.signature_bytes.length).to eq(64)

      FileUtils::mkdir_p("tmp")
      File.open("tmp/coseobject02.bin", "wb") do |f| f.write signed.binary end
      system("cbor2pretty.rb <tmp/coseobject02.bin >tmp/coseobject02.ctxt")
      expect(system("diff tmp/coseobject02.ctxt spec/outputs/coseobject02.ctxt")).to be true
    end

    it "should validate an object with ECDSA key from PEM" do
      bin = CHex.parse(File.open("spec/inputs/coseobject02.ctxt", "rb").read)

      cs1 = Chariwt::CoseSign0.create(bin)
      cs1.parse
      expect(cs1.parsed).to be true
      validated = cs1.validate(x509pubkey)

      File.open("spec/outputs/coseobject02-digest1.bin", "w") do |f|
        f.write cs1.digest
      end
      File.open("spec/outputs/coseobject02-digest0.ctxt", "w") do |f|
        f.write CHex.parse(coseobject02_digest)
      end
      expect(cs1.sha256.unpack("H*")[0]).to eq(coseobject02_sha256)
      expect(cs1.digest.unpack("H*")[0]).to eq(coseobject02_digest)

      expect(validated).to be true
    end

  end

end
