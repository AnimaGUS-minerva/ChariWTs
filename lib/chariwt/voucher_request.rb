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

    def self.from_json(json0)
      vr = new
      vr.load_json(json0)
      return vr
    end

    def yangsid2hash(contents)
      VoucherRequestSID.yangsid2hash(contents)
    end

    def hash2yangsid(vrhash)
      VoucherRequestSID.hash2yangsid(vrhash)
    end

    # mark a voucher as unsigned, generating the attributes into a hash
    def unsigned!
      @token = vrhash
    end
    def token_json
      token.to_json
    end

    def jose_sign(privkey)
      @token = JWT.encode vrhash, privkey, 'ES256'
    end

    def signing_cert_file(file)
      self.signing_cert = OpenSSL::X509::Certificate.new(IO::read(file))
    end

    def jose_sign_file(file)
      privkey = OpenSSL::PKey.read(IO::read(file))
      jose_sign(privkey)
    end

    def pkcs_sign_file(file)
      privkey = OpenSSL::PKey.read(IO::read(file))
      pkcs_sign(privkey)
    end

    # this failes because ruby-openssl renders the "value" string as being
    # "otherName:<unsupported>", which does not get us access to the value!
    def broken_eui64_from_cert(cert = signing_cert)
      eui64 = nil
      certificate.extensions.each { |ext|
        if ext.oid == "1.3.6.1.4.1.46930.1"
          eui64 = ext.value
        end
      }
      eui64
    end

    def eui64_from_cert(cert = signing_cert)
      eui64 = nil
      num = 0
      cert.extensions.each { |ext|
        num += 1
        # need to translate to DER, and then feed it to ASN1PARSE.
        extparsed = OpenSSL::ASN1.decode(ext.to_der)
        oid   = extparsed.value[0]
        value = extparsed.value[1]
        if oid.value == "subjectAltName"
          sanparsed = OpenSSL::ASN1.decode(value.value)
          sanparsed.value.each { |san|
            case san.value[0].value
            when "1.3.6.1.4.1.46930.1"
              eui64 = san.value[1].value[0].value
            end
            #puts "#{num} #{oid} #{sanparsed}"
          }
        end
      }
      return eui64
    end

    def load_json_attributes(jhash)
      load_attributes(jhash)

      priorSigned = jhash['prior-signed-voucher-request']
      case priorSigned
      when String
        cmsSignedPriorVoucherRequest!
        self.priorSignedVoucherRequest_base64 = jhash['prior-signed-voucher-request']
      when Hash
        unsignedPriorVoucherRequest!
        self.priorSignedVoucherRequest = jhash['prior-signed-voucher-request']
      end
    end

  end
end
