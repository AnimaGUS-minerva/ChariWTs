module Chariwt
  class VoucherRequest < Voucher
    attr_accessor :owner_cert
    attr_accessor :token

    class InvalidVoucherRequest < Exception; end
    class MissingPublicKey < Exception; end
    class RequestFailedValidation < Exception; end

    def self.from_json_jose(token)
      # first extract the public key so that it can be used to verify things.

      unverified_token = OpenSSL::PKCS7.new(token)
      sign0 = unverified_token.certificates.first

      cert_store = OpenSSL::X509::Store.new
      # leave it empty!

      # the data will be checked, but the certificate will not be validates.
      unless unverified_token.verify([sign0], cert_store, nil, OpenSSL::PKCS7::NOCHAIN|OpenSSL::PKCS7::NOVERIFY)
        raise VoucherRequest::RequestFailedValidation
      end

      json_txt = unverified_token.data
      json0 = JSON.parse(json_txt)

      pkey  = nil
      if json0['ietf-voucher-request:voucher']
        voucher=json0['ietf-voucher-request:voucher']
        if voucher["pinned-domain-cert"]
          pubkey_der = Base64.decode64(voucher["pinned-domain-cert"])
          pubkey = OpenSSL::X509::Certificate.new(pubkey_der)
        end
      end
      raise VoucherRequest::MissingPublicKey unless pubkey

      verified_token = OpenSSL::PKCS7.new(token)
      unless unverified_token.verify([pubkey], cert_store, nil, OpenSSL::PKCS7::NOCHAIN|OpenSSL::PKCS7::NOVERIFY)
        raise VoucherRequest::RequestFailedValidation
      end

      json = verified_token.data
      json0 = JSON.parse(json_txt)
      json1 = json0['ietf-voucher-request:voucher']

      vr = new
      vr.voucherType = :request
      vr.load_attributes(json1)
      vr
    end

    def self.from_jwt(token)
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
      update_attributes
      if @owner_cert
        pinned = { 'pinned-domain-cert' => Base64.encode64(@owner_cert.to_der) }
      end
      attributes.merge!(pinned)
    end

    def vrhash
      @vrhash ||= { 'ietf-voucher-request:voucher' => inner_attributes }
    end

    def jose_sign(privkey)
      digest = OpenSSL::Digest::SHA256.new
      smime  = OpenSSL::PKCS7.sign(@owner_cert, privkey, vrhash.to_json)
      @token = Base64.encode64(smime.to_der)
    end

    def jwt_sign(privkey)
      @token = JWT.encode vrhash, privkey, 'ES256'
    end

  end
end
