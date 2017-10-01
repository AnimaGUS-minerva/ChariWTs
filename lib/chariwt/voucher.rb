require "active_support/all"

module Chariwt
  class Voucher
    attr_accessor :signing_cert
    attr_accessor :assertion, :createdOn, :voucherType
    attr_accessor :expiresOn, :serialNumber, :pinnedDomainCert
    attr_accessor :idevidIssuer, :domainCertRevocationChecks
    attr_accessor :lastRenewalDate, :priorSignedVoucherRequest
    attr_accessor :proximityRegistrarCert
    attr_accessor :pinnedPublicKey
    attr_accessor :nonce
    attr_accessor :attributes
    attr_accessor :token

    class RequestFailedValidation < Exception; end
    class MissingPublicKey < Exception; end
    class MalformedJSON < Exception; end

    OBJECT_TOP_LEVEL = 'ietf-voucher:voucher'
    def self.object_top_level
      OBJECT_TOP_LEVEL
    end
    def object_top_level
      OBJECT_TOP_LEVEL
    end

    def self.decode_pem(pemstuff)
      base64stuff = ""
      pemstuff.lines.each { |line|
        next if line =~ /^-----BEGIN CERTIFICATE-----/
        next if line =~ /^-----END CERTIFICATE-----/
        base64stuff += line
      }
      begin
        pkey_der = Base64.urlsafe_decode64(base64stuff)
      rescue ArgumentError
        pkey_der = Base64.decode64(base64stuff)
      end
    end

    def self.voucher_type
      :voucher
    end

    def self.cert_from_json1(json1)
      if data = json1["pinned-domain-cert"]
        pubkey_der = Base64.decode64(data)
        pubkey = OpenSSL::X509::Certificate.new(pubkey_der)
      end
    end

    def self.cert_from_json(json0)
      if json0[object_top_level]
        cert_from_json1(json0[object_top_level])
      end
    end

    def self.object_from_verified_json(json1, pubkey)
      vr = new
      vr.voucherType = voucher_type
      vr.load_attributes(json1)
      vr.signing_cert = pubkey
      vr
    end

    def self.from_pkcs7(token)
      # first extract the public key so that it can be used to verify things.

      unverified_token = OpenSSL::PKCS7.new(token)
      sign0 = unverified_token.certificates.first

      cert_store = OpenSSL::X509::Store.new
      # leave it empty!

      # the data will be checked, but the certificate will not be validates.
      unless unverified_token.verify([sign0], cert_store, nil, OpenSSL::PKCS7::NOCHAIN|OpenSSL::PKCS7::NOVERIFY)
        raise Voucher::RequestFailedValidation
      end

      json_txt = unverified_token.data
      json0 = JSON.parse(json_txt)

      pkey  = nil
      pubkey = cert_from_json(json0)
      raise Voucher::MissingPublicKey unless pubkey

      verified_token = OpenSSL::PKCS7.new(token)
      unless unverified_token.verify([pubkey], cert_store, nil, OpenSSL::PKCS7::NOCHAIN|OpenSSL::PKCS7::NOVERIFY)
        raise Voucher::RequestFailedValidation
      end

      json = verified_token.data
      json0 = JSON.parse(json_txt)
      json1 = json0[object_top_level]

      object_from_verified_json(json1, pubkey)
    end

    def self.from_jose_json(token)
      # first extract the public key so that it can be used to verify things.
      begin
        unverified_token = JWT.decode token, nil, false
      rescue JWT::DecodeError
        # probably not a JWT object
        return nil
      end
      json0 = unverified_token[0]
      pkey  = nil
      pubkey = cert_from_json(json0)
      raise Voucher::MissingPublicKey unless pubkey

      begin
        decoded_token = JWT.decode token, pubkey.public_key, true, { :algorithm => 'ES256' }
      rescue
        return nil
      end

      json0 = unverified_token[0]
      pkey  = nil
      unless voucher=json0[object_top_level]
        raise Voucher::MalformedJSON
      end

      object_from_verified_json(voucher, pubkey)
    end

    def initialize
      @attributes = Hash.new
      @voucherType = :unknown
    end

    def load_json(jhash)
      thing = jhash['ietf-voucher:voucher']
      load_attributes(thing)
    end
    def load_attributes(thing)
      #   +---- voucher
      #      +---- created-on?                      yang:date-and-time
      #      +---- expires-on?                      yang:date-and-time
      #      +---- assertion                        enumeration
      #      +---- serial-number                    string
      #      +---- idevid-issuer?                   binary
      #      +---- pinned-domain-cert?              binary
      #      +---- domain-cert-revocation-checks?   boolean
      #      +---- nonce?                           binary
      #      +---- last-renewal-date?               yang:date-and-time
      #      +---- prior-signed-voucher-request?    binary
      #      +---- proximity-registrar-cert?        binary
      @attributes   = thing
      @nonce        = thing['nonce']
      self.assertion     = thing['assertion']
      @serialNumber = thing['serial-number']
      self.createdOn     = thing['created-on']
      self.expiresOn    = thing['expires-on']
      @idevidIssuer = thing['idevid-issuer']
      self.pinnedDomainCert = thing['pinned-domain-cert']
      @domainCertRevocationChecks = thing['domain-cert-revocation-checks']
      @lastRenewalDate  = thing['last-renewal-date']
      @priorSignedVoucherRequest = thing['prior-signed-voucher-request']
      @proximityRegistrarCert    = thing['proximity-registrar-cert']
    end

    def generate_nonce
      @nonce = SecureRandom.urlsafe_base64
    end

    def update_attributes
      @attributes['assertion']     = @assertion
      @attributes['serial-number'] = @serialNumber
      @attributes['created-on']    = @createdOn
      @attributes['nonce']         = @nonce
      @attributes['expires-on']    = @expiresOn
      @attributes['idevid-issuer'] = @idevidIssuer
      @attributes['pinned-domain-cert'] = @pinnedDomainCert
      @attributes['domain-cert-revocation-checks']=@domainCertRevocationChecks
      @attributes['last-renewal-date']  = @lastRenewalDate
      @attributes['prior-signed-voucher-request']=@priorSignedVoucherRequest
      @attributes['proximity-registrar-cert']=@proximityRegistrarCert
    end

    def assertion=(x)
      if x
        @assertion = x.to_sym
      end
    end

    def createdOn=(x)
      if x
        if !x.is_a? String
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

    def expiresOn=(x)
      if x
        if !x.is_a? String
          @expiresOn = x
        else
          begin
            @expiresOn = DateTime.parse(x)
            @voucherType = :time_based
          rescue ArgumentError
            @expiresOn = nil
            nil
          end
        end
      end
    end

    def pinnedDomainCert=(x)
      if x
        if x.is_a? OpenSSL::X509::Certificate
          @pinnedDomainCert = x
        elsif x.is_a? OpenSSL::PKey::PKey
          @pinnedDomainCert = x
        else
          begin
            @pinnedDomainCert = OpenSSL::X509::Certificate.new(x)
          rescue OpenSSL::X509::CertificateError
            decoded = Chariwt::Voucher.decode_pem(x)
            @pinnedDomainCert = OpenSSL::X509::Certificate.new(decoded)
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
      #add_base64_attr_unless_nil(vattr, 'idevid-issuer',  @idevidIssuer)
      add_der_attr_unless_nil(vattr, 'pinned-domain-cert', @pinnedDomainCert)
      add_base64_attr_unless_nil(vattr, 'pinned-public-key', @pinnedPublicKey)
      add_attr_unless_nil(vattr, 'nonce', @nonce)

      result = Hash.new
      result[object_top_level] = vattr
      result
    end

    def inner_attributes
      update_attributes
      if pinnedDomainCert
        attributes['pinned-domain-cert'] = Base64.strict_encode64(pinnedDomainCert.to_der)
      end
      if pinnedPublicKey
        attributes['pinned-domain-subject-public-key-info'] = Base64.strict_encode64(pinnedPublicKey.to_der)
      end
      attributes
    end

    def vrhash
      @vrhash ||= { object_top_level => inner_attributes }
    end

    def pkcs_sign(privkey)
      digest = OpenSSL::Digest::SHA256.new
      smime  = OpenSSL::PKCS7.sign(signing_cert, privkey, vrhash.to_json)
      @token = Base64.strict_encode64(smime.to_der)
    end

    private
    def add_attr_unless_nil(hash, name, value)
      if value
        hash[name] = value
      end
    end

    def add_base64_attr_unless_nil(hash, name, value)
      unless value.blank?
        hash[name] = Base64.urlsafe_encode64(value)
      end
    end

    def add_der_attr_unless_nil(hash, name, value)
      unless value.blank?
        hash[name] = Base64.encode64(value.to_der)
      end
    end

  end
end
