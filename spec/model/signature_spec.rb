require 'lib/c_hex'
require 'lib/chariwt/signature'
require 'lib/chariwt/signatures'
require 'lib/chariwt/assertion'
require 'cbor'
require 'base64'
require 'ecdsa'
require 'byebug'

RSpec.describe CHex do

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
      bx=ECDSA::Format::IntegerOctetString.decode(Base64.decode64(pub_key_base64[:x]))
      by=ECDSA::Format::IntegerOctetString.decode(Base64.decode64(pub_key_base64[:y]))
      ECDSA::Group::Secp384r1.new_point([bx, by])
    end
    def pub_key
      @pub_key ||= decode_pub_key
    end

    def empty_bstr
      @empty_bstr ||= ["40"].pack("H*")
    end

    it "should parse cose example C.2.1 into object" do
      bin = CHex.parse(File.open("spec/inputs/cose2.ctxt", "rb").read)
      unpacker = CBOR::Unpacker.new(StringIO.new(bin))
      unpacker.each { |req|
        expect(req.class).to eq(CBOR::Tagged)
        expect(req.value.class).to eq(Array)
        expect(req.value.length).to eq(4)

        # protected hash
        protected_bucket = Hash.new
        CBOR::Unpacker.new(StringIO.new(req.value[0])).each { |thing|
          protected_bucket = thing
        }
        expect(protected_bucket[1]).to eq(-7)  # ECDSA with SHA-256

        expect(req.value[1].class).to eq(Hash)
        expect(req.value[1][4]).to eq("11")

        # here we need to validate the signature contained in req.value[3]
        # compared to the content in req.value[2], which needs to be hashed
        # appropriately.

        sig_struct = ["Signature1", req.value[0], empty_bstr, req.value[2]]
        digest     = sig_struct.to_cbor
        byebug
        signature  = req.value[3]
        valid = ECDSA.valid_signature?(pub_key, digest, signature)
        byebug
        #unpack2.each { |req2|
        #  byebug
        #  expect(req2.class).to eq(Hash)
        #}
      }
    end

    it "should parse ecdsa-sig-01 into object" do
      bin = CHex.parse(File.open("spec/inputs/sig-01.ctxt", "rb").read)
      unpacker = CBOR::Unpacker.new(StringIO.new(bin))
      unpacker.each { |req|
        expect(req.class).to eq(CBOR::Tagged)
        expect(req.value.class).to eq(Array)
        expect(req.value.length).to eq(4)

        # protected hash
        protected_bucket = Hash.new
        CBOR::Unpacker.new(StringIO.new(req.value[0])).each { |thing|
          protected_bucket = thing
        }
        expect(protected_bucket[1]).to eq(-7)  # ECDSA with SHA-256
        siglen = 32

        expect(req.value[1].class).to eq(Hash)
        expect(req.value[1][4]).to eq("11")

        # here we need to validate the signature contained in req.value[3]
        # compared to the content in req.value[2], which needs to be hashed
        # appropriately.

        sig_struct = ["Signature1", req.value[0], nil, req.value[2]]
        digest     = sig_struct.to_cbor
        signature  = ECDSA::Signature.new(ECDSA::Format::IntegerOctetString.decode(req.value[3][0..31]),
                                          ECDSA::Format::IntegerOctetString.decode(req.value[3][32..63]))
        byebug
        valid = ECDSA.valid_signature?(pub_key, digest, signature)
        byebug
        #unpack2.each { |req2|
        #  byebug
        #  expect(req2.class).to eq(Hash)
        #}
      }
    end

    it "should verify signature from pub_key" do
      expect(pub_key.x).to_not be_nil
      expect(pub_key.y).to_not be_nil
      byebug
      signature = ECDSA::Format::SignatureDerString.decode(signature_der_string)
      puts "kara"
    end

    it "should parse cbor A.3 data into structure" do
      bin = CHex.parse(File.open("spec/inputs/a3.ctxt", "rb").read)
      unpacker = CBOR::Unpacker.new(StringIO.new(bin))
      unpacker.each { |req|
        expect(req.class).to eq(Hash)
        expect(req[1]).to eq("coap://as.example.com")
        expect(req[3]).to eq("coap://light.example.com")
        expect(req[2]).to eq("erikw")

        expect(req[4]).to eq(Time.new(2015,10,5,13,9,4))
        expect(req[5]).to eq(Time.new(2015,10,4,3,49,4))
        expect(req[6]).to eq(Time.new(2015,10,4,3,49,4))
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
      expect(assertion.exp).to eq(Time.new(2015,10,5,13,9,4))
      expect(assertion.nbf).to eq(Time.new(2015,10,4,3,49,4))
      expect(assertion.iat).to eq(Time.new(2015,10,4,3,49,4))
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
