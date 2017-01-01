require 'lib/c_hex'
require 'cbor'
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
        puts "first is: #{req}"
        expect(req.class).to eq(Hash)
        expect(req[3]).to eq("coap://light.example.com")
        expect(req[8].first[1]).to eq(2)
        expect(req[8].first[2]).to eq('11')
        expect(req[8].first[-1]).to eq(1)
        expect(req[8].first[-2]).to_not be_nil
        expect(req[8].first[-3]).to_not be_nil
      }
    end
  end

end
