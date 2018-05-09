module Chariwt
  class VoucherSID
    cattr_accessor :sidkeys

    class MissingSIDMapping < Exception
      attr_reader :mapping

      def initialize(msg, mapping)
        @mapping = mapping
        super(msg)
      end
    end

    VoucherSIDKeys = {
      60100 => ['ietf-cwt-voucher', 'ietf-voucher:voucher'],
      60101 => 'assertion',
      60102 => 'created-on',
      60103 => 'domain-cert-revocation-checks',
      60104 => 'expires-on',
      60105 => 'idevid-issuer',
      60106 => 'last-renewal-date',
      60107 => 'nonce',
      60108 => 'pinned-domain-cert',
      60109 => 'pinned-domain-subject-public-key-info',
      60110 => 'prior-signed-voucher',
      60111 => 'serial-number',
      60112 => 'proximity-registrar-cert',
      60113 => 'proximity-registrar-public-key',
      60200 => ['ietf-cwt-voucher-request', 'ietf-voucher-request:voucher']
    }

    def self.calc_sidkeys
      rev = Hash.new
      VoucherSIDKeys.each {|k,v|
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

    def self.sidkeys
      @@sidkeys ||= calc_sidkeys
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
          nhash[VoucherSIDKeys[basenum+k]] = v
        }
      }
      nhash
    end
  end
end
