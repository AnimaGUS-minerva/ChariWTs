module Chariwt
  class VoucherRequest < Voucher
    attr_accessor :owner_cert
    attr_accessor :token

    class InvalidVoucherRequest < Exception; end

    def self.object_top_level
      'ietf-voucher-request:voucher'
    end
    def self.voucher_type
      :request
    end

    def inner_attributes
      update_attributes
      if @owner_cert
        pinned = { 'pinned-domain-cert' => Base64.encode64(@owner_cert.to_der) }
        attributes.merge!(pinned)
      end
      attributes
    end

    def vrhash
      @vrhash ||= { 'ietf-voucher-request:voucher' => inner_attributes }
    end

    def pkcs_sign(privkey)
      digest = OpenSSL::Digest::SHA256.new
      smime  = OpenSSL::PKCS7.sign(@owner_cert, privkey, vrhash.to_json)
      @token = Base64.encode64(smime.to_der)
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
