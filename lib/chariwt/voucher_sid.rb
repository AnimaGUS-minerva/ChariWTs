module Chariwt
  class VoucherSIDClass
    cattr_accessor :sidkeys

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

    # this method rewrites a hash based upon deltas against the parent
    # SID, which is not modified.  The input has should look like:
    #
    #   { NUM1 => { NUM2 => 'stuff' }}
    # and results in:
    #   { NUM1 => { (NUM2-NUM1) => 'stuff' }}
    #
    def self.mapkeys(base, hash)
      nhash = Hash.new
      hash.each { |k,v|
        kn = sid4key(k)
        #byebug unless kn
        raise MissingSIDMapping.new("missing mapping", k) unless kn
        sidkey = kn - base
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
        nhash[sidkey] = mapkeys(sidkey,v)
      }
      nhash
    end

    def self.yangsid2hash(hash)
      nhash = Hash.new
      hash.each { |k,v|
        basenum = k
        v.each { |k,v|
          val = hashkeys[basenum+k]
          if val
            nhash[val] = v
          else
            nhash['unknown'] ||= []
            nhash['unknown'] << [basenum+k,v]
          end
        }
      }
      nhash
    end
  end

  class VoucherSID < VoucherSIDClass
    SIDKeys = {
      1001100 => ['ietf-cwt-voucher', 'ietf-voucher:voucher'],
      1001105 => 'assertion',
      1001106 => 'created-on',
      1001107 => 'domain-cert-revocation-checks',
      1001108 => 'expires-on',
      1001109 => 'idevid-issuer',
      1001110 => 'last-renewal-date',
      1001111 => 'nonce',
      1001112 => 'pinned-domain-cert',
      1001113 => 'pinned-domain-subject-public-key-info',
      1001114 => 'serial-number',
    }

    # also Cose::Msg::VoucherPubkey
    VoucherPubkey = 60299

    def self.hashkeys
      SIDKeys
    end

    def self.sidkeys
      @@sidkeys ||= calc_sidkeys(SIDKeys)
    end
  end

  class VoucherRequestSID < VoucherSIDClass
    SIDKeys = {
      1001154 => ['ietf-cwt-voucher-request',
                  'ietf-cwt-voucher-request:voucher',
                  'ietf-voucher-request:voucher'],
      1001155 => 'assertion',
      1001156 => 'created-on',
      1001157 => 'domain-cert-revocation-checks',
      1001158 => 'expires-on',
      1001159 => 'idevid-issuer',
      1001160 => 'last-renewal-date',
      1001161 => 'nonce',
      1001162 => 'pinned-domain-cert',
      1001163 => 'proximity-registrar-subject-public-key-info',
      1001164 => 'serial-number',
      1001165 => 'prior-signed-voucher-request',
    }

    # also Cose::Msg::VoucherPubkey
    VoucherPubkey = 60299

    def self.hashkeys
      SIDKeys
    end

    def self.sidkeys
      @@sidkeys ||= calc_sidkeys(SIDKeys)
    end
  end
end
