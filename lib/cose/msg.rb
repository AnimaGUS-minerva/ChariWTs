# these magic numbers come from the IANA considerations of RFCXXXX (ietf-cose-msg-24)

module Cose
  class Msg
    # from table 2: Common Header Paramters, page 15.
    ALG = 1
    CRIT = 2
    CONTENT_TYPE = 3
    KID  = 4
    IV   = 5
    PARTIAL_IV = 6
    COUNTER_SIGNATURE = 7

    # from table 5, ECDSA Algorithm Values
    ES256 = -7
    ES384 = -35
    ES512 = -36
  end
end

