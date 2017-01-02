module Chariwt
  class Key
    attr_accessor :keytype, :kid, :crv, :x, :y

    def initialize(cbormap)
      case cbormap[1]
      when 2
        self.keytype = 'EC'
      end
      self.kid     = cbormap[2]

      case cbormap[-1]
      when 1
        self.crv   = :p384
      end

      self.x = cbormap[-2]
      self.y = cbormap[-3]
    end
  end
end
