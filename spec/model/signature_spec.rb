require 'lib/c_hex'

RSpec.describe CHex do

  describe "parsing" do
    it "should parse hex into binary" do
      string = "41"
      expect(CHex.parse(string)).to eq('A')
    end
  end

end
