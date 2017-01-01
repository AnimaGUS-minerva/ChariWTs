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

    it "should parse cbor into structure" do
      pending "XXX"
    end
  end

end
