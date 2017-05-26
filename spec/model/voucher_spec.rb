require 'lib/chariwt/voucher'
require 'date'
require 'json'
require 'byebug'

RSpec.describe Chariwt::Voucher do

  describe "properties" do
    it "should have empty properties" do
      voucher1 = Chariwt::Voucher.new
      expect(voucher1.assertion).to be_nil
      expect(voucher1.deviceIdentifier).to be_nil
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
      expect(voucher1.deviceIdentifier).to eq('JADA123456789')
      expect(voucher1.createdOn).to  eq(DateTime.parse('2016-10-07T19:31:42Z'))
      expect(voucher1.voucherType).to eq(:time_based)
    end

    it "should not barf on invalid date in JSON string" do
      voucher1 = Chariwt::Voucher.new

      voucher1.createdOn = 'foobar'
      expect(voucher1.createdOn).to be_nil
    end
  end

  describe "jwt voucher" do
    it "should generate a simple signed voucher in JWT format" do
      cv = Chariwt::Voucher.new
      cv.assertion = ''
      cv.deviceIdentifier = 'JADA123456789'
      cv.voucherType = :time_based
      cv.nonce = 'abcd12345'
      cv.createdOn = DateTime.parse('2016-10-07T19:31:42Z')
      cv.expiredOn = DateTime.parse('2017-10-01T00:00:00Z')
      cv.serialNumber = 23
      cv.idevidIssuer     = "00112233445566".unpack("H*")
      cv.pinnedDomainCert = "99001122334455".unpack("H*")

      jv = cv.jwt_voucher
      expect(jv.class).to eq(Hash)
      expect(jv['ietf-voucher:voucher'].class).to eq(Hash)
    end
  end

end
