module Chariwt
  class VoucherRequest < Voucher
    attr_accessor :attributes
    attr_accessor :owner_cert

    def self.from_json_jose(token)
      # first extract the public key so that it can be used to verify things.
      begin
        unverified_token = JWT.decode token, nil, false
      rescue JWT::DecodeError
        # probably not a JWT object
        return nil
      end
      json0 = unverified_token[0]
      pkey  = nil
      if json0['ietf-voucher-request:voucher']
        voucher=json0['ietf-voucher-request:voucher']
        if voucher["pinned-domain-cert"]
          pkey_der = Base64.decode64(voucher["pinned-domain-cert"])
          pkey = OpenSSL::PKey::EC.new(pkey_der)
        end
      end
      raise VoucherRequest::MissingPublicKey unless pkey

      begin
        decoded_token = JWT.decode token, pkey, true, { :algorithm => 'ES256' }
      rescue
        return nil
      end
      json = decoded_token[0]
      load_attributes(json)
      json
    end

    def inner_attributes
      attributes.merge!({ 'pinned-domain-cert' => Base64.encode64(@owner_cert.to_der) })
    end

    def vrhash
      @vrhash ||= { 'ietf-voucher-request:voucher' => inner_attributes }
    end

    def jose_sign(privkey)
      byebug
      @token = JWT.encode vrhash, privkey, 'ES256'
    end

  end
end
