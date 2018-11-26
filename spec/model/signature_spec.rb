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
  describe "parsing" do
    it "should parse hex into binary" do
      string = "41"
      expect(CHex.parse(string)).to eq('A')
    end

    it "should parse an example file" do
      File.open("spec/inputs/signature1.ctxt", "rb") do |f|
        str=f.read
        cbor = CHex.parse(str)
        expect(cbor.length).to eq(194)
      end
    end

    it "should parse a simple file" do
      File.open("spec/inputs/a1.ctxt", "rb") do |f|
        str=f.read
        cbor = CHex.parse(str)
        n = cbor.unpack("C*")
        expect(n[0]).to eq(162)
        expect(n[1]).to eq(3)
        expect(n[2]).to eq(0x78)
        expect(n[3]).to eq(0x18)
        expect(cbor.length).to eq(45)
      end
    end

    #{
    # 3: "coap://light.example.com",
    # 8:
    # [
    #   {
    #     1: 4,
    #     -1: "loremipsum"
    #   }
    # ]
    #}
    it "should parse A.1 cbor into structure" do
      bin = CHex.parse(File.open("spec/inputs/a1.ctxt", "rb").read)
      unpacker = CBOR::Unpacker.new(StringIO.new(bin))
      unpacker.each { |req|
        #puts "first is: #{req}"
        expect(req.class).to eq(Hash)
        expect(req[3]).to eq("coap://light.example.com")
        expect(req[8].first[1]).to eq(4)
        expect(req[8].first[-1]).to eq("loremipsum")
      }
    end

    # pseudo-JSON:
    #{
    #  "aud": "coap://light.example.com",
    #  "cks":
    #    [                       // COSE_Key is a CBOR map with an array of keys
    #      {
    #        "kty": "EC",
    #        "kid": "11",
    #        "crv": 1, // using P-384
    #        "x": h'bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff',
    #        "y": h'20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e'
    #      }
    #    ]
    #}
    #
    # CBOR version:
    #{
    #  3: "coap://light.example.com",
    #  8:
    #  [
    #    {
    #      1: 2,
    #      2: "11",
    #      -1: 1,
    #      -2: h'bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff',
    #      -3: h'20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e'
    #    }
    #  ]
    #}
    it "should parse cbor A.2 example into structure" do
      bin = CHex.parse(File.open("spec/inputs/a2.ctxt", "rb").read)
      unpacker = CBOR::Unpacker.new(StringIO.new(bin))
      unpacker.each { |req|
        #puts "first is: #{req}"
        expect(req.class).to eq(Hash)
        expect(req[3]).to eq("coap://light.example.com")
        expect(req[8].first[1]).to eq(2)
        expect(req[8].first[2]).to eq('11')
        expect(req[8].first[-1]).to eq(1)
        expect(req[8].first[-2]).to_not be_nil
        expect(req[8].first[-3]).to_not be_nil
      }
    end

    def pub_key_base64
      {
        x: "kTJyP2KSsBBhnb4kjWmMF7WHVsY55xUPgb7k64rDcjatChoZ1nvjKmYmPh5STRKc",
        y: "mM0weMVU2DKsYDxDJkEP9hZiRZtB8fPfXbzINZj_fF7YQRynNWedHEyzAJOX2e8s"
      }
    end
    def decode_pub_key
      bx=ECDSA::Format::IntegerOctetString.decode(Base64.urlsafe_decode64(pub_key_base64[:x]))
      by=ECDSA::Format::IntegerOctetString.decode(Base64.urlsafe_decode64(pub_key_base64[:y]))
      ECDSA::Group::Secp384r1.new_point([bx, by])
    end
    def pub_key
      @pub_key ||= decode_pub_key
    end

    def empty_bstr
      @empty_bstr ||= "".force_encoding('ASCII-8BIT')
    end

    def ECDSA_decodesignature(binary, len)
      binary = binary.dup.force_encoding('BINARY')
      r_str = binary[0..(len-1)]
      s_str = binary[len..(len*2)]
      r = ECDSA::Format::IntegerOctetString.decode(r_str)
      s = ECDSA::Format::IntegerOctetString.decode(s_str)
      ECDSA::Signature.new(r,s)
    end

    it "should parse ecdsa-sig-01 into object" do
      bin = CHex.parse(File.open("spec/inputs/sig-01.ctxt", "rb").read)

      ccs1 = Chariwt::CoseSign0.create(bin)
      ccs1.parse

      expect(ccs1.protected_bucket[3]).to eq(0)  # 0 is cbor empty.
      validated = ccs1.validate(sig01_pub_key)
      expect(validated).to be true

    end
    it "should parse ecdsa-sig-01 into object" do
      bin = CHex.parse(File.open("spec/inputs/sig-01.ctxt", "rb").read)

      ccs1 = Chariwt::CoseSign0.create(bin)
      ccs1.parse

      expect(ccs1.protected_bucket[3]).to eq(0)   # zero means cbor null.
      validated = ccs1.validate(sig01_pub_key)
      expect(validated).to be true
    end

    it "should validate ecdsa-sig-02 example from json" do
      testdesc = JSON.parse(File.open("spec/examples/ecdsa-examples/ecdsa-01.json", "rb").read)

      bin  = CHex.parse(testdesc['output']['cbor'])
      ccs1 = Chariwt::CoseSign0.create(bin)
      ccs1.parse

      key0 = testdesc['input']['sign']['signers'][0]['key']
      pubkey = decode_pub_key_from_example(key0)
      validated = ccs1.validate(pubkey)
      expect(validated).to be true

    end

    it "should have a temporary key, which is a constant for testing" do
      # it's all Integer in 2.4+
      expect(temporary_key.class).to be(Integer)
    end

    def coseobject01_digest
      "846a5369676e61747572653143a101264074546869732069732074686520636f6e74656e742e"
    end

    def coseobject01_sha256
      "c85fec6f6115d030389f87c76e7712dcc695a9227d2bfc371b6685caa638c7ca"
    end

    it "should create a signature for cose object -01" do
      signed = Chariwt::CoseSign1.new

      signed.content = "This is the content."
      signed.protected_bucket[1] = -7

      group       = ECDSA::Group::Nistp256
      signed.generate_signature(group, sig01_priv_key, temporary_key)

      expect(signed.digested.unpack("H*")[0]).to eq(coseobject01_digest)
      expect(signed.digest.unpack("H*")[0]).to   eq(coseobject01_sha256)
      expect(signed.signature_bytes.length).to eq(64)

      FileUtils::mkdir_p("tmp")
      File.open("tmp/coseobject01.bin", "wb") do |f| f.write signed.binary end
      system("cbor2pretty.rb <tmp/coseobject01.bin >tmp/coseobject01.ctxt")
      expect(system("diff tmp/coseobject01.ctxt spec/outputs/coseobject01.ctxt")).to be true
    end

    it "should validate public key was created from private key" do
      private_key = sig01_priv_key
      group       = ECDSA::Group::Nistp256
      public_key  = group.generator.multiply_by_scalar(private_key)

      public_key_string = ECDSA::Format::PointOctetString.encode(public_key, compression: true)

      expect(public_key.x).to eq(sig01_pub_key.x)
      expect(public_key.y).to eq(sig01_pub_key.y)
    end

    it "should parse signed coseobject and verify contents" do
      bin = CHex.parse(File.open("spec/inputs/coseobject01.ctxt", "rb").read)

      cs1 = Chariwt::CoseSign0.create(bin)
      cs1.parse
      expect(cs1.parsed).to be true
      validated = cs1.validate(sig01_pub_key)

      File.open("spec/outputs/coseobject01-digest1.bin", "w") do |f|
        f.write cs1.digest
      end
      File.open("spec/outputs/coseobject01-digest0.bin", "w") do |f|
        f.write CHex.parse(coseobject01_digest)
      end
      expect(cs1.sha256.unpack("H*")[0]).to eq(coseobject01_sha256)
      expect(cs1.digest.unpack("H*")[0]).to eq(coseobject01_digest)

      expect(validated).to be true
    end

    def sig02_key_base64
      {
        kty:"EC",
        kid:"P384",
        crv:"P-384",
        x:"kTJyP2KSsBBhnb4kjWmMF7WHVsY55xUPgb7k64rDcjatChoZ1nvjKmYmPh5STRKc",
        y:"mM0weMVU2DKsYDxDJkEP9hZiRZtB8fPfXbzINZj_fF7YQRynNWedHEyzAJOX2e8s",
        d:"ok3Nq97AXlpEusO7jIy1FZATlBP9PNReMU7DWbkLQ5dU90snHuuHVDjEPmtV0fTo"
      }
    end

    def sig02_rng_stream
      [
         "20DB1328B01EBB78122CE86D5B1A3A097EC44EAC603FD5F60108EDF98EA81393"
      ]
    end
    def sig02_decode_private_key
      bd=ECDSA::Format::IntegerOctetString.decode(Base64.urlsafe_decode64(sig02_key_base64[:d]))
    end
    def sig02_priv_key
      @priv_key ||= sig02_decode_private_key
    end
    def sig02_pub_key
      @pub_key ||= decode_pub_key_from_example(sig02_key_base64)
    end

    it "should validate 384-bit public key was created from private key" do
      private_key = sig02_priv_key
      group       = ECDSA::Group::Nistp384
      public_key  = group.generator.multiply_by_scalar(private_key)

      expect(public_key.x).to eq(sig02_pub_key.x)
      expect(public_key.y).to eq(sig02_pub_key.y)
    end

    it "should parse cbor A.3 data into structure" do
      bin = CHex.parse(File.open("spec/inputs/a3.ctxt", "rb").read)
      unpacker = CBOR::Unpacker.new(StringIO.new(bin))
      unpacker.each { |req|
        expect(req.class).to eq(Hash)
        expect(req[1]).to eq("coap://as.example.com")
        expect(req[3]).to eq("coap://light.example.com")
        expect(req[2]).to eq("erikw")

        expect(req[4].utc).to eq(Time.utc(2015,10,5,17,9,4))
        expect(req[5].utc).to eq(Time.utc(2015,10,4,7,49,4))
        expect(req[6].utc).to eq(Time.utc(2015,10,4,7,49,4))
        expect(req[7]).to eq(2929)
        expect(req[8].first[1]).to eq(2)
        expect(req[8].first[2]).to eq('11')
        expect(req[8].first[-1]).to eq(1)
        expect(req[8].first[-2]).to_not be_nil
        expect(req[8].first[-3]).to_not be_nil
        expect(req[9][0][0]).to eq("/s/light")
        expect(req[9][0][1]).to eq(1)
        expect(req[9][1][0]).to eq("/a/led")
        expect(req[9][1][1]).to eq(5)
        expect(req[9][2][0]).to eq("/dtls")
        expect(req[9][2][1]).to eq(2)
      }
    end

    it "should parse cbor A.3 data into cwt object" do
      bin = CHex.parse(File.open("spec/inputs/a3.ctxt", "rb").read)
      assertion = Chariwt::Assertion.new(StringIO.new(bin))
      expect(assertion.iss).to eq("coap://as.example.com")
      expect(assertion.aud).to eq("coap://light.example.com")
      expect(assertion.exp.utc).to eq(Time.utc(2015,10,5,17,9,4))
      expect(assertion.nbf.utc).to eq(Time.utc(2015,10,4,7,49,4))
      expect(assertion.iat.utc).to eq(Time.utc(2015,10,4,7,49,4))
      expect(assertion.sub).to eq("erikw")
      expect(assertion.cti).to eq(2929)

      expect(assertion.sigs[0].keytype).to eq("EC")
      expect(assertion.sigs[0].kid).to     eq('11')
      expect(assertion.sigs[0].crv).to     eq(:p384)
      expect(assertion.sigs[0].x).to_not be_nil
      expect(assertion.sigs[0].y).to_not be_nil

      expect(assertion.aif[0][0]).to eq("/s/light")
      expect(assertion.aif[0][1]).to eq(1)
      expect(assertion.aif[1][0]).to eq("/a/led")
      expect(assertion.aif[1][1]).to eq(5)
      expect(assertion.aif[2][0]).to eq("/dtls")
      expect(assertion.aif[2][1]).to eq(2)
    end
  end

end
