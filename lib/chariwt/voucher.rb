module Chariwt
  class Voucher
    attr_accessor :assertion, :createdOn, :voucherType
    attr_accessor :expiresOn, :serialNumber, :idevidIssuer, :pinnedDomainCert
    attr_accessor :nonce

    def initialize
      @voucherType = :unknown
    end

    def load_json(jhash)
      thing = jhash['ietf-voucher:voucher']
      self.assertion    = thing['assertion']
      self.serialNumber = thing['serial-number']
      self.createdOn    = thing['created-on']
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

    def jwt_voucher
      case voucherType
      when :time_based
      end

      vattr = Hash.new
      vattr['assertion'] = nil
      vattr['device-identifier'] = nil
      vattr['created-on'] = nil
      vattr['expired-on'] = nil
      vattr['serial-umber'] = nil
      vattr['devid-issuer'] = nil
      vattr['pinned-domain-cert'] = nil
      vattr['nonce'] = nil

      result = Hash.new
      result['ietf-voucher:voucher'] = vattr
      result
    end
  end
end
