module Chariwt
  class Principal
    attr_accessor :aud, :keys

    def initialize(cbor)
      @unpacker = CBOR::Unpacker.new(cbor)
      self.keys = []
      @unpacker.each { |item|
        self.aud = item[3]
        cks = item[8]
        cks.each { |key|
          keys << Chariwt::Key.new(key)
        }
        self.decode_item(item)
      }
    end

    def decode_item(item)
      true
    end
  end
end
