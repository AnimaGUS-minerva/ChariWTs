module Chariwt
  class Voucher
    attr_accessor :assertion, :deviceIdentifier, :created_on, :voucherType

    def initialize
      @voucherType = :unknown
    end

    def load_json(jhash)
      thing = jhash['ietf-voucher:voucher']
      self.assertion = thing['assertion']
      self.deviceIdentifier = thing['device-identifier']
      self.created_on = thing['created-on']
    end

    def assertion=(x)
      if x
        @assertion = x.to_sym
      end
    end

    def created_on=(x)
      if x
        begin
          @created_on = DateTime.parse(x)
          @voucherType = :time_based
        rescue ArgumentError
          @created_on = nil
          nil
        end
      end
    end

    def load_file(io)
      json = JSON.parse(io.read)
      load_json(json)
      self
    end
  end
end
