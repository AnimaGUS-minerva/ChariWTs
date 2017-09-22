module Chariwt
  class VoucherRequest < Voucher
    class InvalidVoucherRequest < Exception; end

    OBJECT_TOP_LEVEL = 'ietf-voucher-request:voucher'
    def object_top_level
      OBJECT_TOP_LEVEL
    end
    def self.object_top_level
      OBJECT_TOP_LEVEL
    end
    def self.voucher_type
      :request
    end

    # mark a voucher as unsigned, generating the attributes into a hash
    def unsigned!
      @token = vrhash.to_json
    end

    def jose_sign(privkey)
      @token = JWT.encode vrhash, privkey, 'ES256'
    end

    def owner_cert_file(file)
      self.owner_cert = OpenSSL::X509::Certificate.new(IO::read(file))
    end

    def jose_sign_file(file)
      privkey = OpenSSL::PKey.read(IO::read(file))
      jose_sign(privkey)
    end

    def pkcs_sign_file(file)
      privkey = OpenSSL::PKey.read(IO::read(file))
      pkcs_sign(privkey)
    end

  end
end
