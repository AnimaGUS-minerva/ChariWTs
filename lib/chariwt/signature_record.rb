# this implements a hash (JSON structure) that can be used with
#   https://github.com/cose-wg/Examples
# to verify signatures and the like.

module Chariwt
  class SignatureRecord
    attr_accessor :record

    def initialize
      @record ||= Hash.new
    end

    def to_s
      @record.to_json
    end

    def title=(x)
      @record['title']=x
    end
    def input
      @record['input'] ||= Hash.new
    end
    def intermediates
      @record['intermediates'] ||= Hash.new
    end
    def output
      @record['output'] ||= Hash.new
    end
    def tobe_signed
      intermediates['ToBeSign_hex']
    end

    def hexify(x)
      x.unpack("H*").first
    end

    def plaintext=(x)
      input['plaintext_hex'] = hexify(x)
    end

    def tobe_signed=(x)
      intermediates['ToBeSign_hex'] = hexify(x)
    end
    def output_cbor=(x)
      output['cbor'] = hexify(x)
    end

  end
end
