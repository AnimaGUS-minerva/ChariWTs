require "active_support"
require 'active_support/core_ext/class/attribute_accessors'
require "cbor"
require 'ecdsa'

require 'cose/msg'
require 'date'

DateTime.class_eval do
  def to_cbor(n = nil)
    to_time.to_cbor(n)
  end
end
Date.class_eval do
  def to_cbor(n = nil)
    to_time.to_cbor(n)
  end
end

module Chariwt
  class MalformedCBOR < Exception; end
  class InvalidVoucherPriorType < Exception; end
  class UnsupportedCOSEAlgorithm <Exception; end

  class Voucher
    cattr_accessor :debug
    attr_accessor :token_format

    attr_accessor :signing_cert
    attr_accessor :assertion, :createdOn, :voucherType
    attr_accessor :expiresOn, :serialNumber, :pinnedDomainCert
    attr_accessor :idevidIssuer, :domainCertRevocationChecks
    attr_accessor :lastRenewalDate, :priorSignedVoucherRequest
    attr_accessor :proximityRegistrarCert, :proximityRegistrarPublicKey
    attr_accessor :priorSignedType
    attr_accessor :pinnedPublicKey
    attr_accessor :nonce
    attr_accessor :attributes
    attr_accessor :token
    attr_accessor :valid
    attr_accessor :pubkey
    attr_accessor :cert_chain
    attr_accessor :signing_object
    attr_accessor :alg, :kid

    class RequestFailedValidation < Exception; end
    class MissingPublicKey < Exception
      def initialize(msg, keyvalue = nil)
        @keyvalue = keyvalue
        super(msg)
      end
    end
    class MalformedJSON < Exception; end
    class InvalidKeyType < Exception; end

    OBJECT_TOP_LEVEL = 'ietf-voucher:voucher'
    def self.object_top_level
      OBJECT_TOP_LEVEL
    end
    def object_top_level
      OBJECT_TOP_LEVEL
    end

    def self.decode_pem(pemstuff)
      return "" if pemstuff.blank?
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
      else
        nil
      end
    end

    def self.object_from_verified_cbor(signedobject, pubkey)
      vr = object_from_cbor_contents(signedobject, signedobject.contents, pubkey)
      vr
    end

    def self.object_from_cbor_contents(object, contents, pubkey)
      vr = new
      vr.coseSignedPriorVoucherRequest!
      vr.voucherType = voucher_type
      vr.token_format= :cose_cbor
      vr.load_sid_attributes_hash(contents)
      vr.token       = object

      if object.unprotected_bucket
        if object.unprotected_bucket[Cose::Msg::ALG]
          vr.alg = Cose::Msg.alg_from_int(object.unprotected_bucket[Cose::Msg::ALG])
        end
        if object.unprotected_bucket[Cose::Msg::KID]
          vr.kid = object.unprotected_bucket[Cose::Msg::KID]
          vr.pubkey    = object.pubkey
        end
      end
      if object.protected_bucket
        if object.protected_bucket[Cose::Msg::ALG]
          vr.alg = Cose::Msg.alg_from_int(object.protected_bucket[Cose::Msg::ALG])
        end
      end

      if pubkey
        vr.pubkey       = pubkey
        vr.signing_cert = pubkey
      end

      vr
    end

    def self.object_from_unverified_cbor(unverifiedobject, pubkey)
      object_from_cbor_contents(unverifiedobject, unverifiedobject.contents, pubkey)
    end

    def self.object_from_verified_json(json1, store0, signed_object = nil)
      vr = new
      vr.voucherType = voucher_type
      if store0
        vr.cert_chain = store0
      end
      if json1
        vr.load_json_attributes(json1)
      end

      pubkey = (store0 && store0.chain.try(:last))
      if pubkey
        vr.signing_cert = pubkey
      end
      if signed_object
        vr.token        = signed_object
      end
      vr
    end

    def self.object_from_unsigned_json(json0)
      if json0 and json0[object_top_level]
        object_from_verified_json(json0[object_top_level], nil, nil)
      end
    end

    def self.json0_from_pkcs7(token, extracert = nil)
      # set things up and then see if there a certificate that can verify the signature
      begin
        unverified_token = OpenSSL::CMS::ContentInfo.new(token)
      rescue ArgumentError
        raise RequestFailedValidation.new("request did not decode properly")
      end

      # the cert_store is the list of trusted anchors
      cert_store = OpenSSL::X509::Store.new

      # walk through the certificate list and look for any self-signed certificates
      # and put them into the cert_store.
      certs = unverified_token.certificates
      certlist = []
      if extracert
        cert_store.add_cert(extracert)
        certlist << extracert
      end
      certs.each { |cert|
        if cert.issuer == cert.subject
          cert_store.add_cert(cert)
        else
          certlist << cert
        end
      }

      # the data will be checked. The certificates are allowed to be trusted at this point, as
      # we are essentially just calculating a checksum on the contents in order to be able to
      # take look inside.  However, the certificate is not checked at this point.
      unless unverified_token.verify(certlist, cert_store, nil, OpenSSL::CMS::NOINTERN|OpenSSL::CMS::NO_SIGNER_CERT_VERIFY)
        raise RequestFailedValidation.new(unverified_token.error_string)
      end

      json_txt = unverified_token.data
      return json_txt,unverified_token,cert_store
    end

    def self.voucher_from_verified_data(json_txt, store0, pkcs7object)
      json0 = JSON.parse(json_txt)
      json1 = json0[object_top_level]

      object_from_verified_json(json1, store0, pkcs7object)
    end

    def self.from_pkcs7(token, extracert = nil)
      json_txt,unverified_token,store0 = json0_from_pkcs7(token, extracert)
      voucher_from_verified_data(unverified_token.data, store0, unverified_token)
    end

    def self.from_pkcs7_withoutkey(token)
      json0,unverified_token,store0 = json0_from_pkcs7(token)
      voucher_from_verified_data(json0, store0, unverified_token)
    end

    def self.from_cose_withoutkey_io(tokenio)
      # raises MalformedCBOR if processing fails
      unverified                   = Chariwt::CoseSign0.create_io(tokenio)
      unverified.parse

      # because there was no key, must decode the signed content into content
      # directly here.
      unverified.parse_signed_contents

      object_from_unverified_cbor(unverified, nil)
    end

    def self.from_cose_withoutkey(token)
      from_cose_withoutkey_io(StringIO.new(token))
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
      raise MissingPublicKey.new("json did not find a key") unless pubkey

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

    def self.from_cbor_cose(token, pubkey = nil)
      from_cbor_cose_io(StringIO.new(token), pubkey)
    end

    def self.validate_from_chariwt(unverified, pubkey)
      begin
        valid = unverified.validate(pubkey)
      rescue Chariwt::CoseSign1::InvalidKeyType
        raise InvalidKeyType
      end
      raise RequestFailedValidation.new(format("with key %s", pubkey.subject)) unless valid
      object = object_from_verified_cbor(unverified, pubkey)
      object.valid = valid
      object.coseSignedPriorVoucherRequest!
      return object
    end

    def self.from_cbor_cose_io(tokenio, pubkey = nil)
      unverified = Chariwt::CoseSign0.create_io(tokenio)
      unverified.parse
      pubkey ||= unverified.pubkey

      # unclear if this should be an exception.
      raise MissingPublicKey.new("cose unprotected did not include a key") unless pubkey
      return validate_from_chariwt(unverified, pubkey)
    end

    def unsignedPriorVoucherRequest!
      @priorSignedType = :unsigned
    end
    def unsignedPriorVoucherRequest?
      @priorSignedType == :unsigned
    end

    def cmsSignedPriorVoucherRequest!
      @priorSignedType = :cmsSigned
    end
    def cmsSignedPriorVoucherRequest?
      @priorSignedType == :cmsSigned
    end

    def coseSignedPriorVoucherRequest!
      @priorSignedType = :coseSigned
    end
    def coseSignedPriorVoucherRequest?
      @priorSignedType == :coseSigned
    end

    def verify_with_key(pubkey)
      case @token_format
      when :pkcs
        certlist = [pubkey]
        # leave it empty!
        cert_store = OpenSSL::X509::Store.new

        # the data will be checked, but the certificate will be trusted, and not be validated.
        return @token.verify(certlist, cert_store, nil, OpenSSL::CMS::NOINTERN|OpenSSL::CMS::NO_SIGNER_CERT_VERIFY)

      when :cose_cbor, :cms_cbor
        return @token.validate(pubkey)
      end
    end


    def initialize(options = Hash.new)
      # setup defaults to be pkcs/cms format.
      #  other options are:  cms_cbor
      #                and:  cose_cbor
      #
      options = {:format => :pkcs}.merge!(options)

      @token_format = options[:format]
      @attributes = Hash.new
      @voucherType = :unknown
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

      # assignments are used whenever there are actually additional processing possible
      # for the assignment due to different formats.
      #byebug if thing.nil?
      return nil unless thing.kind_of? Hash

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
      self.proximityRegistrarCert        = thing['proximity-registrar-cert']
      self.proximityRegistrarPublicKey   = thing['proximity-registrar-subject-public-key-info']

    end

    def yangsid2hash(contents)
      VoucherSID.yangsid2hash(contents)
    end

    # this takes a CoseSign1 object
    def load_sid_attributes(cose1)
      load_sig_attributes_hash(cose1.signed_contents)
    end
    def load_sid_attributes_hash(contents)
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

      # assignments are used whenever there are actually additional processing possible
      # for the assignment due to different formats.

      thing = yangsid2hash(contents)
      load_attributes(thing)
      if thing
        self.priorSignedVoucherRequest = thing['prior-signed-voucher-request']
      end
    end

    # note, that *voucher* does not have a priorSignedVoucherRequest, so none is set.
    # the subclass VoucherRequest overrides this method.
    def load_json_attributes(jhash)
      load_attributes(jhash)
    end

    def load_json(jhash)
      thing = jhash[object_top_level]
      load_json_attributes(thing)
    end

    def generate_nonce
      @nonce = SecureRandom.urlsafe_base64
    end

    def update_attributes
      add_attr_unless_nil(@attributes, 'assertion',  @assertion)
      add_attr_unless_nil(@attributes, 'created-on', @createdOn)

      add_attr_unless_nil(@attributes, 'expires-on', @expiresOn)
      add_attr_unless_nil(@attributes, 'serial-number', @serialNumber)

      add_attr_unless_nil(@attributes, 'nonce', @nonce)
      add_attr_unless_nil(@attributes, 'idevid-issuer', @idevidIssuer)

      add_der_attr_unless_nil(@attributes,
                              'pinned-domain-cert', @pinnedDomainCert)

      case @pinnedPublicKey
      when ECDSA::Point
        add_attr_unless_nil(@attributes,
                            'pinned-domain-subject-public-key-info',
                            ECDSA::Format::PointOctetString.encode(@pinnedPublicKey, compression: true))

      else
        add_der_attr_unless_nil(@attributes,
                                'pinned-domain-subject-public-key-info',
                                @pinnedPublicKey)
      end

      case @pinnedPublicKey
      when ECDSA::Point
        add_attr_unless_nil(@attributes,
                            'pinned-domain-subject-public-key-info',
                            ECDSA::Format::PointOctetString.encode(@pinnedPublicKey, compression: true))

      else
        add_der_attr_unless_nil(@attributes,
                                'pinned-domain-subject-public-key-info',
                                @pinnedPublicKey)
      end

      add_attr_unless_nil(@attributes,
                          'domain-cert-revocation-checks',
                          @domainCertRevocationChecks)

      add_attr_unless_nil(@attributes, 'last-renewal-date', @lastRenewalDate)

      unless @priorSignedVoucherRequest.is_a? Hash
        add_binary_attr_unless_nil(@attributes,
                                   'prior-signed-voucher-request',
                                   @priorSignedVoucherRequest)
      end

      add_der_attr_unless_nil(@attributes,
                              'proximity-registrar-cert',
                              @proximityRegistrarCert)

      case @proximityRegistrarPublicKey
      when ECDSA::Point
        add_attr_unless_nil(@attributes,
                            'proximity-registrar-subject-public-key-info',
                            ECDSA::Format::PointOctetString.encode(@proximityRegistrarPublicKey, compression: true))

      else
        add_der_attr_unless_nil(@attributes,
                                'proximity-registrar-subject-public-key-info',
                                @proximityRegistrarPublicKey)
      end
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

    def decode_unknown_public_key(x)
      case x
      when OpenSSL::PKey::PKey
        x
      when ECDSA::Point
        # also a kind of public key
        x
      when String
        # try to decode it as a public key.
        begin
          OpenSSL::X509::Certificate.new(x)
        rescue OpenSSL::X509::CertificateError
          decoded = Chariwt::Voucher.decode_pem(x)
          OpenSSL::X509::Certificate.new(decoded)
        end
      when OpenSSL::X509::Certificate
        x
      else
        byebug if @@debug
        raise MissingPublicKey.new("unknown public key of class #{x.class}", x)
      end
    end

    def pinnedPublicKey=(x)
      if x
        @pinnedPublicKey = decode_unknown_public_key(x)
      end
    end

    def proximityRegistrarCert=(x)
      if x
        @proximityRegistrarCert = decode_unknown_public_key(x)
      end
    end

    def proximityRegistrarPublicKey=(x)
      if x
        @proximityRegistrarPublicKey = decode_unknown_public_key(x).try(:public_key)
      end
    end

    def priorSignedVoucherRequest=(x)
      case
      when unsignedPriorVoucherRequest?
        @priorSignedVoucherRequest = x

      when cmsSignedPriorVoucherRequest?
        @priorSignedVoucherRequest = x

      when coseSignedPriorVoucherRequest?
        @priorSignedVoucherRequest = x
      else
        byebug if @@debug
        raise InvalidVoucherPriorType if x
      end
    end

    def priorSignedVoucherRequest_base64=(x)
      if x
        @priorSignedVoucherRequest = Base64.decode64(x)
      else
        @priorSignedVoucherRequest = nil
      end
    end

    def priorSignedVoucherRequest_hash=(x)
      @priorSignedVoucherRequest = x
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
      attributes
    end

    def vrhash
      @vrhash ||= { object_top_level => inner_attributes }
    end

    CBOR_BINARY_FIELDS = {
      'prior-signed-voucher-request' => true
    }

    def calc_sanitized_hash
      n = Hash.new
      inner_attributes.each {|k,v|
        if CBOR_BINARY_FIELDS[k]
          n[k]= Base64.encode64(v)
        else
          n[k]=v
        end
      }
      n
    end

    def sanitized_hash
      @sanitized_hash ||= calc_sanitized_hash
    end

    def pkcs_sign_bin(privkey, needcerts = true, extracerts = [])
      flags = OpenSSL::CMS::NOSMIMECAP
      unless needcerts
        flags = OpenSSL::CMS::NOCERTS
      end
      digest = OpenSSL::Digest::SHA256.new
      smime  = OpenSSL::CMS.sign(signing_cert, privkey, vrhash.to_json, extracerts, flags )
      @token = smime.to_der
    end

    #
    # CBOR routines
    #

    def hash2yangsid(vrhash)
      VoucherSID.hash2yangsid(vrhash)
    end

    def cose_sign(privkey, group = ECDSA::Group::Nistp256, temporary_key = nil)
      @sidhash = hash2yangsid(vrhash)
      @signing_object = Chariwt::CoseSign1.new
      @signing_object.content = @sidhash.to_cbor

      case group
      when ECDSA::Group::Nistp256
        @signing_object.set_msg_alg_es256!
      else
        raise UnsupportedCOSEAlgorithm
      end

      # this is wrong, because pubkey is not necessary a PKIX certificate
      if pubkey
        case pubkey
        when OpenSSL::X509::Certificate
          @signing_object.unprotected_bucket[Cose::Msg::X5BAG] = pubkey.to_wireformat
        end
      end
      @signing_object.alg = group

      case privkey
      when OpenSSL::PKey::EC
        (privkey,group) = ECDSA::Format::PrivateKey.decode(privkey)

      # ECDSA private keys are just integers
      when Integer
        # nothing else to do.
      end

      @token = @signing_object.generate_signature(group, privkey, temporary_key)

      @token
    end

    private
    def add_attr_unless_nil(hash, name, value)
      if value
        hash[name] = value
      end
    end

    def add_base64_attr_unless_nil(hash, name, value)
      if value
        hash[name] = Base64.strict_encode64(value)
      end
    end

    def add_der_attr_unless_nil(hash, name, value)
      if value
        case @token_format
        when :pkcs
          hash[name] = Base64.strict_encode64(value.to_der)
        when :cose_cbor, :cms_cbor
          hash[name] = value.to_der
        end
      end
    end

    def add_binary_attr_unless_nil(hash, name, value)
      if value
        case @token_format
        when :pkcs
          hash[name] = Base64.strict_encode64(value)
        when :cose_cbor, :cms_cbor
          hash[name] = value
        end
      end
    end


  end
end
