#
# this class presents a COSE (RFCXXXX) signature1 object.
# more complex objects are possible, but in Ownership Voucher's use of CWT,
# only Signature1 objects are interesting.
#
# Initialize with an array from a CBOR decode, or nil if constructing.
#

require 'chariwt/cose_sign0'

module Chariwt
  class CoseSign1 < CoseSign0
    attr_accessor :binary, :sha256, :digest, :digested, :raw_cbor
    attr_accessor :parsed, :validated, :valid, :signature, :signature_bytes
    attr_accessor :protected_bucket, :encoded_protected_bucket
    attr_accessor :unprotected_bucket, :contents, :signed_contents
    attr_accessor :signature_record

    class InvalidKeyType < Exception; end

    #
    # This creats a new signature object from a binary blob.  It does not
    # validate it until it is told to.
    #
    # @param binary (A CBOR encoded object)
    def initialize(req = nil)
      @raw_cbor = req
      @protected_bucket   ||= Hash.new
      @unprotected_bucket ||= Hash.new
    end

    def signature_record
      @signature_record ||= SignatureRecord.new
    end

    def basic_validation
      # verify that it is ECDSA with SHA-256.
      @protected_bucket[Cose::Msg::ALG] == Cose::Msg::ES256
    end

    def set_msg_alg_es256!
      @protected_bucket[Cose::Msg::ALG] = Cose::Msg::ES256
    end

    def kid
      @unprotected_bucket[Cose::Msg::KID]
    end

    # the group should be taken from another attribute
    def pubkey(group = ECDSA::Group::Nistp256)
      if @unprotected_bucket[Cose::Msg::VOUCHER_PUBKEY]
        @pubkey ||= ECDSA::Format::PointOctetString.decode(@unprotected_bucket[Cose::Msg::VOUCHER_PUBKEY], group)
      end
    end

    #
    # PARSING AND VALIDATION ROUTINES
    #
    #
    def parse
      return if @parsed
      return unless @raw_cbor

      return unless @raw_cbor.value.length==4

      # protected hash
      @protected_bucket = nil
      @encoded_protected_bucket = @raw_cbor.value[0]
      CBOR::Unpacker.new(StringIO.new(@encoded_protected_bucket)).each { |thing|
        @protected_bucket = thing
      }

      if(@raw_cbor.value[1].class == Hash)
        @unprotected_bucket = @raw_cbor.value[1]
      end

      @signed_contents = @raw_cbor.value[2]
      @signature_bytes = @raw_cbor.value[3]
      @parsed = true
    end

    def empty_bstr
      self.class.empty_bstr
    end
    def self.empty_bstr
      @empty_bstr ||= "".force_encoding('ASCII-8BIT')
    end

    def extract_signature
      r = ECDSA::Format::IntegerOctetString.decode(@signature_bytes[0..31])
      s = ECDSA::Format::IntegerOctetString.decode(@signature_bytes[32..63])
      ECDSA::Signature.new(r, s)
    end

    def signature
      @signature ||= extract_signature
    end

    def parse_signed_contents
      if @signed_contents.kind_of? String
        CBOR::Unpacker.new(StringIO.new(@signed_contents)).each { |thing|
          @contents = thing
        }
      end
    end

    def validate(pubkey)
      case pubkey
      when String    # key is not decoded yet.
        cert        = OpenSSL::X509::Certificate.new(pubkey)
        pubkey_point= ECDSA::Format::PubKey.decode(cert)
      when OpenSSL::X509::Certificate
        pubkey_point = ECDSA::Format::PubKey.decode(pubkey)
      when OpenSSL::PKey::EC
        pubkey_point = ECDSA::Format::PubKey.decode(pubkey)
      when ECDSA::Point
        pubkey_point = pubkey
      else
        raise InvalidKeyType
      end

      sig_struct = ["Signature1", @encoded_protected_bucket, empty_bstr, @signed_contents]
      @digest     = sig_struct.to_cbor
      signature_record.tobe_signed = @digest

      @sha256 = Digest::SHA256.digest(@digest)
      @valid = ECDSA.valid_signature?(pubkey_point, sha256, signature)

      if @valid
        parse_signed_contents
      end
      @valid
    end

    def ecdsa_signed_bytes
      sig_r_bytes = ECDSA::Format::IntegerOctetString.encode(@signature.r, @group.byte_length)
      sig_s_bytes = ECDSA::Format::IntegerOctetString.encode(@signature.s, @group.byte_length)
      @signature_bytes  = (sig_r_bytes + sig_s_bytes)
    end

    def setup_signature_buckets
      @encoded_protected_bucket = @protected_bucket.to_cbor
      sig_struct = ["Signature1", encoded_protected_bucket, Chariwt::CoseSign.empty_bstr, @content]
      @digested   = sig_struct.to_cbor
      signature_record.plaintext = digested
      @digest     = Digest::SHA256.digest(digested)
      signature_record.tobe_signed = @digest
    end

    def concat_signed_buckets(sig_bytes)
      # protected, unprotected, payload, signature
      sign1 = [ @encoded_protected_bucket, @unprotected_bucket, @content, sig_bytes ]
      @binary = CBOR::Tagged.new(18, sign1).to_cbor
      signature_record.output_cbor = @binary
    end

    def generate_openssl_signature(private_key)
      setup_signature_buckets

      # XXX this should use RFC6979 rather than temporary_key
      #puts "group: #{group} pk: #{private_key}"
      #puts "digest: #{digest.unpack("H*")}"; puts "tk: #{temporary_key}"
      @signature= ECDSA.sign(group, private_key, digest, temporary_key)

      concat_signed_buckets(openssl_signed_bytes)
    end

    def generate_signature(group, private_key, temporary_key = nil)
      @group = group

      if @pubkey
        @unprotected_bucket[Cose::Msg::VOUCHER_PUBKEY] = @pubkey.to_wireformat
      end

      unless temporary_key
        temporary_key = ECDSA::Format::IntegerOctetString.decode(SecureRandom.random_bytes(group.byte_length))
      end

      setup_signature_buckets

      #puts "group: #{group} pk: #{private_key}"
      #puts "digest: #{digest.unpack("H*")}"; puts "tk: #{temporary_key}"
      @signature= ECDSA.sign(group, private_key, digest, temporary_key)

      concat_signed_buckets(ecdsa_signed_bytes)
    end
  end

end
