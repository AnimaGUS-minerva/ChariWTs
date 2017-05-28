require 'lib/chariwt/voucher'
require 'date'
require 'json'
require 'openssl'
require 'byebug'
require 'jwt'

RSpec.describe Chariwt::Voucher do

  describe "properties" do
    it "should have empty properties" do
      voucher1 = Chariwt::Voucher.new
      expect(voucher1.assertion).to be_nil
      expect(voucher1.serialNumber).to be_nil
      expect(voucher1.createdOn).to be_nil
      expect(voucher1.voucherType).to eq(:unknown)
    end
  end

  describe "loading" do
    it "should load values from a JSON string" do
      filen = "spec/files/json_voucher1.json"
      file = File.open(filen, "r:UTF-8")
      voucher1 = Chariwt::Voucher.new.load_file(file)
      expect(voucher1).to_not be_nil

      expect(voucher1.assertion).to be(:verified)
      expect(voucher1.serialNumber).to eq('JADA123456789')
      expect(voucher1.createdOn).to  eq(DateTime.parse('2016-10-07T19:31:42Z'))
      expect(voucher1.voucherType).to eq(:time_based)
    end

    it "should not barf on invalid date in JSON string" do
      voucher1 = Chariwt::Voucher.new

      voucher1.createdOn = 'foobar'
      expect(voucher1.createdOn).to be_nil
    end
  end

  describe "json voucher" do
    def sig01_key_base64
      {
        kty:"EC",
        kid:"11",
        crv:"P-256",
        x:"usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
        y:"IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
        d:"V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM"
      }
    end
    def sig01_rng_stream
      [
         "20DB1328B01EBB78122CE86D5B1A3A097EC44EAC603FD5F60108EDF98EA81393"
      ]
    end
    def sig01_decode_private_key
      bd=ECDSA::Format::IntegerOctetString.decode(Base64.urlsafe_decode64(sig01_key_base64[:d]))
    end

    it "should generate a simple signed voucher, using JOSE with JSON format" do
      cv = Chariwt::Voucher.new
      cv.assertion = ''
      cv.serialNumber = 'JADA123456789'
      cv.voucherType = :time_based
      cv.nonce = 'abcd12345'
      cv.createdOn = DateTime.parse('2016-10-07T19:31:42Z')
      cv.expiresOn = DateTime.parse('2017-10-01T00:00:00Z')
      cv.idevidIssuer     = "00112233445566".unpack("H*")
      cv.pinnedDomainCert = "99001122334455".unpack("H*")

      jv = cv.json_voucher
      expect(jv.class).to eq(Hash)
      expect(jv['ietf-voucher:voucher'].class).to eq(Hash)

      ecdsa_key = OpenSSL::PKey::EC.new 'prime256v1'
      ecdsa_key.generate_key
      ecdsa_public = OpenSSL::PKey::EC.new ecdsa_key
      ecdsa_public.private_key = nil


      token = JWT.encode jv, ecdsa_key, 'ES256'
      expect(token).to_not be_nil

    end
  end

end
