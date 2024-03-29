module Chariwt
  class VoucherSIDClass
    class MissingSIDMapping < Exception
      attr_reader :mapping

      def initialize(msg, mapping)
        @mapping = mapping
        super(msg)
      end
    end

    def self.calc_sidkeys(sidkeys)
      rev = Hash.new
      sidkeys.each {|k,v|
        case v
        when Array
          v.each {|str|
            rev[str] = k
          }
        else
          rev[v]=k
        end
      }
      rev
    end

    def self.sid4key(key)
      case key
      when String
        sidkeys[key.downcase]
      when Number
        key
      else
        byebug
        puts "bad key: #{key}"
      end
    end

    def self.translate_assertion_fromsid(assertion)
      case assertion
      when 0
        :verified
      when 1
        :logged
      when 2
        :proximity
      else
        assertion.to_sym
      end
    end

    def self.translate_assertion_tosid(assertion)
      case assertion.to_s
      when "verified"
        0
      when "logged"
        1
      when "proximity"
        2
      else
        assertion
      end
    end

    # This method rewrites a hash based upon deltas against the parent
    # SID, which is not modified.
    # It is used when mapping into constrained SID based YANG.
    # The input has should look like:
    #
    #   { NUM1 => { NUM2 => 'stuff' }}
    # and results in:
    #   { NUM1 => { (NUM2-NUM1) => 'stuff' }}
    #
    def self.mapkeys(base, hash)
      raise MissingSIDMapping.new("bad base id", base) unless base
      nhash = Hash.new
      hash.each { |k,v|
        kn = sid4key(k)
        #byebug unless kn
        raise MissingSIDMapping.new("missing mapping", k) unless kn
        sidkey = kn - base

        case k.to_s
        when "assertion"
          v = translate_assertion_tosid(v)
        when "nonce"
          # this forces nonce to be a bstr rather than a tstr
          v = v.force_encoding('ASCII-8BIT')
        end

        if v.is_a? DateTime
          v = v.iso8601(0)  # this turns it into a string.
        end

        case v
        when Hash
          nhash[sidkey] = mapkeys(sidkey, v)
        else
          nhash[sidkey] = v
        end
      }
      nhash
    end

    def self.hash2yangsid(hash)
      nhash = Hash.new
      hash.each { |k,v|
        sidkey = sid4key(k)
        raise MissingSIDMapping.new("missing base object", k) unless sidkey
        nhash[sidkey] = mapkeys(sidkey,v)
      }
      nhash
    end

    def self.yangsid2hash(hash)
      nhash = Hash.new
      return nil unless hash.kind_of? Hash
      hash.each { |k,v|
        basenum = k
        v.each { |relk,v|

          if relk.is_a? Integer
            abskey = basenum+relk
            yangkey = hashkeys[abskey]

            if yangkey
              if(abskey == 2502 || abskey == 2452)
                v = translate_assertion_fromsid(v)
              end
              nhash[yangkey] = v
            else
              nhash['unknown'] ||= []
              nhash['unknown'] << [abskey,v]
            end
          else
            nhash[relk] = v
          end
        }
      }
      nhash
    end
  end

  class VoucherSID < VoucherSIDClass
    SIDKeys = {
      2451 => ['ietf-cwt-voucher', 'ietf-voucher:voucher'],
      2452 => 'assertion',
      2453 => 'created-on',
      2454 => 'domain-cert-revocation-checks',
      2455 => 'expires-on',
      2456 => 'idevid-issuer',
      2457 => 'last-renewal-date',
      2458 => 'nonce',
      2459 => 'pinned-domain-cert',
      2460 => 'pinned-domain-subject-public-key-info',
      2461 => 'pinned-sha256-of-subject-public-key-info',
      2462 => 'serial-number',
    }

    def self.hashkeys
      SIDKeys
    end

    def self.sidkeys
      @sidkeys_voucher ||= calc_sidkeys(SIDKeys)
    end
  end

  class VoucherRequestSID < VoucherSIDClass
    SIDKeys = {
      2501    => ['ietf-cwt-voucher-request',
                  'ietf-cwt-voucher-request:voucher',
                  'ietf-voucher-request:voucher'],
      2502    => 'assertion',
      2503    => 'created-on',
      2504    => 'domain-cert-revocation-checks',
      2505    => 'expires-on',
      2506    => 'idevid-issuer',
      2507    => 'last-renewal-date',
      2508    => 'nonce',
      2509    => 'pinned-domain-cert',
      2510    => 'prior-signed-voucher-request',
      2511    => 'proximity-registrar-cert',
      2512    => 'proximity-registrar-sha256-of-subject-public-key-info',
      2513    => 'proximity-registrar-subject-public-key-info',
      2514    => 'serial-number',
    }

    def self.hashkeys
      SIDKeys
    end

    def self.sidkeys
      @sidkeys_voucher_request ||= calc_sidkeys(SIDKeys)
    end
  end
end
