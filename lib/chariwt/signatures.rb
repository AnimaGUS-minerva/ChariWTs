module Chariwt
  class Signatures
    attr_accessor :aud, :sigs

    def initialize(cbor)
      @unpacker = CBOR::Unpacker.new(cbor)
      self.sigs = []
      @unpacker.each { |item|
        self.aud = item[3]
        cks = item[8]
        cks.each { |key|
          sigs << Chariwt::Signature.new(key)
        }
        self.decode_item(item)
      }
    end

    def decode_item(item)
      true
    end
  end
end
