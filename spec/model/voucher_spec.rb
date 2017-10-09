require 'chariwt/voucher'
require 'date'
require 'json'
require 'openssl'
require 'ecdsa'
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

  describe "pkcs voucher" do
    def pubkey99
      @pubkey99 ||= OpenSSL::X509::Certificate.new(File.read("spec/files/jrc_prime256v1.crt"))
    end

    def privkey99
      @privkey99 ||= OpenSSL::PKey.read(File.read("spec/files/jrc_prime256v1.key"))
    end

    it "should sign a voucher with an owner public key" do
      cv = Chariwt::Voucher.new
      cv.assertion    = 'logged'
      cv.serialNumber = 'JADA_f2-01-99'
      cv.voucherType  = :time_based
      cv.nonce        = '62a2e7693d82fcda2624de58fb6722e5'
      cv.createdOn    = '2016-01-01'.to_date
      cv.expiresOn    = '2099-01-01'.to_date


      cv.signing_cert     = pubkey99
      cv.pinnedPublicKey  = pubkey99.public_key
      smime = cv.pkcs_sign(privkey99)

      expect(Chariwt.cmp_pkcs_file(smime, "thing_f2-01-99")).to be true
    end

    it "should sign a voucher with an owner certificate" do
      cv = Chariwt::Voucher.new
      cv.assertion    = 'logged'
      cv.serialNumber = 'JADA_f2-00-99'
      cv.voucherType  = :time_based
      cv.nonce        = '62a2e7693d82fcda2624de58fb6722e5'
      cv.createdOn    = '2016-01-01'.to_date
      cv.expiresOn    = '2099-01-01'.to_date


      cv.signing_cert     = pubkey99
      cv.pinnedDomainCert = pubkey99
      smime = cv.pkcs_sign(privkey99)

      expect(Chariwt.cmp_pkcs_file(smime, "thing_f2-00-99")).to be true
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
      ecdsa_key = OpenSSL::PKey::EC.new 'prime256v1'
      ecdsa_key.generate_key
      ecdsa_public = OpenSSL::PKey::EC.new ecdsa_key
      ecdsa_public.private_key = nil

      cv = Chariwt::Voucher.new
      cv.assertion = ''
      cv.serialNumber = 'JADA123456789'
      cv.voucherType = :time_based
      cv.nonce = 'abcd12345'
      cv.createdOn = DateTime.parse('2016-10-07T19:31:42Z')
      cv.expiresOn = DateTime.parse('2017-10-01T00:00:00Z')
      cv.pinnedDomainCert = ecdsa_public

      jv = cv.json_voucher
      expect(jv.class).to eq(Hash)
      expect(jv['ietf-voucher:voucher'].class).to eq(Hash)

      token = JWT.encode jv, ecdsa_key, 'ES256'
      File.open("tmp/jada_abcd.jwt","w") do |f|
        f.write token
      end
      (part1,part2,part3) = token.split(/\./)
      part1js = JSON.parse(Base64.urlsafe_decode64(part1))
      part2js = JSON.parse(Base64.urlsafe_decode64(part2))
      part3bin = Base64.urlsafe_decode64(part3)

      expect(part1js['typ']).to eq('JWT')
      expect(part2js['ietf-voucher:voucher']).to_not be_nil
    end
  end

  describe "parsing an EC key" do
    it "should read a private key from a file and sign using ECDSA" do
      base64 = ''
      start = false
      File.open("spec/inputs/key1.pem", "r").each_line { |line|
        if line =~ /-----BEGIN EC PRIVATE KEY-----/
          start=true
          next
        end
        if line =~ /-----END EC PRIVATE KEY-----/
          break
        end
        if start
          base64 += line.chomp
        end
      }
      expect(base64).to_not be_nil
      expect(base64.length).to be > 1
      bin  = Base64.decode64(base64)
      asn1 = OpenSSL::ASN1.decode(bin)

      # described in rfc5915
      #  ECPrivateKey ::= SEQUENCE {
      # version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
      # privateKey     OCTET STRING,
      # parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
      # publicKey  [1] BIT STRING OPTIONAL
      #}

      # we care about the algorithm ID and the value
      expect(asn1.tag).to eq(16)  # a sequence
      expect(asn1.value[0].value).to eq(1)
      expect(asn1.value.length).to eq(4)

      # should really process the array of parameters
      expect(asn1.value[2].value[0].value).to eq("prime256v1")

      # grab the private key
      dvalue = asn1.value[1].value
      bd=ECDSA::Format::IntegerOctetString.decode(dvalue)
      expect(bd).to eq(62155652909192118641450531910530083020008790680669046461814889750607491156729)
    end
  end

end
