module Chariwt
  class Voucher
    attr_accessor :assertion, :deviceIdentifier, :createdOn, :voucherType
    attr_accessor :expiredOn, :serialNumber, :idevidIssuer, :pinnedDomainCert
    attr_accessor :nonce

    def initialize
      @voucherType = :unknown
    end

    def load_json(jhash)
      thing = jhash['ietf-voucher:voucher']
      self.assertion = thing['assertion']
      self.deviceIdentifier = thing['device-identifier']
      self.createdOn = thing['created-on']
    end

    def assertion=(x)
      if x
        @assertion = x.to_sym
      end
    end

    def createdOn=(x)
      if x
        if x.instance_of? DateTime
          @createdOn = x
        else
          begin
            @createdOn = DateTime.parse(x)
            @voucherType = :time_based
          rescue ArgumentError
            @createdOn = nil
            nil
          end
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
