module Chariwt
  class Assertion < Principal
    attr_accessor :iss, :sub, :exp, :nbf, :iat, :cti, :aif

    def initialize(cbor)
      super(cbor)
    end
    def decode_item(item)
      self.iss = item[1]
      self.sub = item[2]
      self.exp = item[4]
      self.nbf = item[5]
      self.iat = item[6]
      self.cti = item[7]
      self.aif = item[9]
    end
  end
end
