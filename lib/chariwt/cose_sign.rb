#
# this class presents a COSE (RFCXXXX) multiple signature object.
#
# Initialize with the decode req structure, and then when ready, call parse
# to get the details extracted.
#

module Chariwt
  class InvalidDigestAlgorith < Exception
  end
  class CoseSignature
    attr_accessor :pbucket, :protected, :unprotected, :signature_bytes
  end

  class CoseSign < CoseSign0
    attr_accessor :binary, :sha256, :digest
    attr_accessor :parsed, :validated, :valid
    attr_accessor :protected_bucket, :encoded_protected_bucket
    attr_accessor :unprotected_bucket, :content
    attr_accessor :signatures

    #
    # This creats a new signature object from a binary blob.  It does not
    # validate it until it is told to.
    #
    # @param binary (A CBOR encoded object)
    def initialize(request)
      @req = request
      @protected_bucket   ||= Hash.new
      @unprotected_bucket ||= Hash.new
    end

    def parse
      return if @parsed

      return unless @req.value.length==4

      # protected hash
      @protected_bucket = nil
      @encoded_protected_bucket = @req.value[0]
      CBOR::Unpacker.new(StringIO.new(@encoded_protected_bucket)).each { |thing|
        @protected_bucket = thing
      }

      if(@req.value[1].class == Hash)
        @unprotected_bucket = @req.value[1]
      end

      @contents         = @req.value[2]
      @signature_blocks = @req.value[3]
      @signatures = []
      @signature_blocks.each { |sigblock|
        signature = CoseSignature.new

        CBOR::Unpacker.new(StringIO.new(sigblock[0])).each { |thing|
          signature.protected = thing unless signature.protected
        }
        signature.pbucket         = sigblock[0]
        signature.unprotected     = sigblock[1]
        signature.signature_bytes = sigblock[2]
        @signatures << signature
      }
      @parsed = true
    end

    def empty_bstr
      self.class.empty_bstr
    end
    def self.empty_bstr
      @empty_bstr ||= "".force_encoding('ASCII-8BIT')
    end

    def extract_signature(signature, publen)
      r = ECDSA::Format::IntegerOctetString.decode(signature.signature_bytes[0..(publen-1)])
      s = ECDSA::Format::IntegerOctetString.decode(signature.signature_bytes[(publen)..(publen*2 - 1)])
      ECDSA::Signature.new(r, s)
    end

    def validate(pubkey)
      @valid = false
      @signatures.each { |signature|
        sig_struct = ["Signature", @encoded_protected_bucket, signature.pbucket, empty_bstr, @contents]
        @digest     = sig_struct.to_cbor

        case signature.protected[1]
        when -7
          digested = Digest::SHA256.digest(@digest)
        when -35
          # P384
          digested = Digest::SHA384.digest(@digest)
        else
          raise InvalidDigestAlgorith
        end

        valid = ECDSA.valid_signature?(pubkey, digested, extract_signature(signature, pubkey.group.byte_length))
        if valid
          @valid = true
        end
      }
      @valid
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
