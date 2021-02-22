require 'c_hex'
require 'chariwt'
require 'cbor'
require 'base64'
require 'ecdsa'
require 'byebug'
require 'json'
require 'model/test_keys'

RSpec.describe CHex do
  include Testkeys

    it "should sign SPDX object with ECDSA key from PEM" do
      signed = Chariwt::CoseSign1.new

      signed.content = File.read("spec/inputs/SAG-PM.spdx")
      x509privkey    = File.open(File.join('spec','files', 'sbom_sag.key'),'r') do |f|
        OpenSSL::PKey.read(f)
      end

      signed.protected_bucket[1] = -7

      (privkey,group) = ECDSA::Format::PrivateKey.decode(x509privkey)
      signed.generate_signature(group, privkey, temporary_key)

      #expect(signed.digested.unpack("H*")[0]).to eq(coseobject02_digest)
      #expect(signed.digest.unpack("H*")[0]).to   eq(coseobject02_sha256)
      expect(signed.signature_bytes.length).to eq(64)

      FileUtils::mkdir_p("tmp")
      File.open("tmp/sbom_signed.bin", "wb") do |f| f.write signed.binary end
      system("cbor2pretty.rb <tmp/sbom_signed.bin >tmp/sbom_signed.ctxt")
      expect(system("diff tmp/sbom_signed.ctxt spec/outputs/sbom_signed.ctxt")).to be true
    end


end
