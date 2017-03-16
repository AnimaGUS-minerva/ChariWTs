#
# this class presents a COSE (RFCXXXX) signature1 object.
# more complex objects are possible, but in Ownership Voucher's use of CWT,
# only Signature1 objects are interesting.
#
# Initialize with
#

module Chariwt
  class CoseSign1
    attr_accessor :binary, :sha256, :digest
    attr_accessor :parsed, :validated, :valid, :signature, :signature_bytes
    attr_accessor :protected_bucket, :encoded_protected_bucket
    attr_accessor :unprotected_bucket, :content

    #
    # This creats a new signature object from a binary blob.  It does not
    # validate it until it is told to.
    #
    # @param binary (A CBOR encoded object)
    def initialize(binary)
      @binary = binary
      @protected_bucket   ||= Hash.new
      @unprotected_bucket ||= Hash.new
    end

    def parse
      return if @parsed
      unpacker = CBOR::Unpacker.new(StringIO.new(@binary))
      unpacker.each { |req|

        return unless req.value.length==4

        # protected hash
        @protected_bucket = nil
        @encoded_protected_bucket = req.value[0]
        CBOR::Unpacker.new(StringIO.new(@encoded_protected_bucket)).each { |thing|
          @protected_bucket = thing
        }

        if(req.value[1].class == Hash)
          @unprotected_bucket = req.value[1]
        end

        @contents        = req.value[2]
        @signature_bytes = req.value[3]
      }
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

    def validate(pubkey)
      sig_struct = ["Signature1", @encoded_protected_bucket, empty_bstr, @contents]
      @digest     = sig_struct.to_cbor

      @sha256 = Digest::SHA256.digest(@digest)
      @valid = ECDSA.valid_signature?(pubkey, sha256, signature)
    end


    def basic_validation
      # verify that it is ECDSA with SHA-256.
      @protected_bucket[Cose::Msg::ALG] == Cose::Msg::ES256
    end

    def kid
      @unprotected[Cose::Msg::KID]
    end
  end

end
