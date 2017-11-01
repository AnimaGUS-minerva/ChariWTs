module Testkeys
  def sig01_key_base64
    {
        kty:"EC",
        kid:"11",
        crv:"P-256",
        x:"usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
        y:"IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
        d:"V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM"
    }
  end

  def sig02_key_base64
    {
      "kty":"EC",
     "kid":"P384",
     "crv":"P-384",
     "x":"kTJyP2KSsBBhnb4kjWmMF7WHVsY55xUPgb7k64rDcjatChoZ1nvjKmYmPh5STRKc",
     "y":"mM0weMVU2DKsYDxDJkEP9hZiRZtB8fPfXbzINZj_fF7YQRynNWedHEyzAJOX2e8s",
     "d":"ok3Nq97AXlpEusO7jIy1FZATlBP9PNReMU7DWbkLQ5dU90snHuuHVDjEPmtV0fTo"
    }
  end

  def sig01_rng_stream
    [
      "20DB1328B01EBB78122CE86D5B1A3A097EC44EAC603FD5F60108EDF98EA81393"
    ]
  end

  def create_point_from_example(example, px, py)
    crv = example[:crv] || example["crv"]

    case crv
    when 'P-256'
      ECDSA::Group::Nistp256.new_point([px, py])
    when 'P-384'
      ECDSA::Group::Nistp384.new_point([px, py])
    end
  end

  # this temporary_key is a random number that is passed into the signer
  # this should be random, but for testing must be kept static.
  def temporary_key
    ECDSA::Format::IntegerOctetString.decode(["20DB1328B01EBB78122CE86D5B1A3A097EC44EAC603FD5F60108EDF98EA81393"].pack("H*"))
  end

  def sig01_decode_private_key(example)
    bd = ECDSA::Format::IntegerOctetString.decode(Base64.urlsafe_decode64(sig01_key_base64[:d]))

    #create_point_from_example(example, bd)
    return bd
  end

  def decode_pub_key_from_example(example)
    x = example[:x] || example["x"]
    y = example[:y] || example["y"]
    bx=ECDSA::Format::IntegerOctetString.decode(Base64.urlsafe_decode64(x))
    by=ECDSA::Format::IntegerOctetString.decode(Base64.urlsafe_decode64(y))

    create_point_from_example(example, bx, by)
  end

  def sig01_priv_key
    @sig01_priv_key ||= sig01_decode_private_key(sig01_key_base64)
  end

  def sig01_pub_key
    @sig01_pub_key ||= decode_pub_key_from_example(sig01_key_base64)
  end
end
