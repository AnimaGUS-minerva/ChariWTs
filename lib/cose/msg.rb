# these magic numbers come from the IANA considerations of RFCXXXX (ietf-cose-msg-24)

module Cose
  class Msg
    # from table 2: Common Header Paramters, page 15.
    # https://www.iana.org/assignments/cose/cose.xhtml#header-parameters
    ALG = 1
    CRIT = 2
    CONTENT_TYPE = 3
    KID  = 4
    IV   = 5
    PARTIAL_IV = 6
    COUNTER_SIGNATURE = 7
    X5BAG             = 32
    VOUCHER_PUBKEY    = 60299    # private value, remove it.

    # from table 5, ECDSA Algorithm Values
    ES256 = -7
    ES384 = -35
    ES512 = -36
    ES256K = -47

    def self.alg_from_int(algno)
      case algno
      when ES256
        :ES256
      when ES384
        :ES384
      when ES512
        :ES512
      when ES256K
        :ES256k
      else
        algno
      end
    end
  end
end

