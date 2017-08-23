module Chariwt
  class VoucherRequest < Voucher

    def self.from_json_jose(token)
      # first extract the public key so that it can be used to verify things.
      unverified_token = JWT.decode token, nil, false
      json0 = unverified_token[0]
      pkey  = nil
      if json0['ietf-voucher:voucher']
        voucher=json0['ietf-voucher:voucher']
        if voucher["pinned-domain-cert"]
          pkey_der = Base64.urlsafe_decode64(voucher["pinned-domain-cert"])
          pkey = OpenSSL::PKey::EC.new(pkey_der)
        end
      end
      raise VoucherRequest::MissingPublicKey unless pkey

      decoded_token = JWT.decode token, pkey, true, { :algorithm => 'ES256' }
      json = decoded_token[0]
    end
  end
end
