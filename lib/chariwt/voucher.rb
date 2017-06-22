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
        if x.acts_like?(:time)
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

    def json_voucher
      case voucherType
      when :time_based
      end

      vattr = Hash.new
      add_attr_unless_nil(vattr, 'assertion',  @assertion)
      add_attr_unless_nil(vattr, 'created-on', @createdOn)

      add_attr_unless_nil(vattr, 'expires-on', @expiresOn)
      add_attr_unless_nil(vattr, 'serial-number', @serialNumber)
      add_attr_unless_nil(vattr, 'devid-issuer',  @devidIssuer)
      add_base64_attr_unless_nil(vattr, 'pinned-domain-cert', @pinnedDomainCert)
      add_attr_unless_nil(vattr, 'nonce', @nonce)

      result = Hash.new
      result['ietf-voucher:voucher'] = vattr
      result
    end

    private
    def add_attr_unless_nil(hash, name, value)
      if value
        hash[name] = value
      end
    end

    def add_base64_attr_unless_nil(hash, name, value)
      if value
        hash[name] = Base64.urlsafe_decode64(value)
      end
    end

  end
end
