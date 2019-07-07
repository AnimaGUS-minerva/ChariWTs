module Chariwt
  def self.tmpdir
    # make sure that tmp directory is available for output.
    @tmpdir ||=
      begin
        Rails.root.join("tmp")
      rescue
        "tmp"
      end

    FileUtils::mkdir_p(@tmpdir)
    @tmpdir
  end

  def self.cmp_pkcs_file(smime, base, certfile=nil)
    ofile = File.join(tmpdir, base + ".pkcs")
    otfile = File.join(tmpdir, base+ ".txt")

    File.open(ofile, "wb") do |f|     f.write smime      end

    location = File.dirname(__FILE__) + "/../../bin"
    #puts "Location is: #{location}, wrote to #{ofile}, #{otfile}, #{base}"
    system("#{location}/pkcs2json #{ofile} #{otfile} #{certfile}")
    cmd = "diff #{otfile} spec/files/#{base}.txt"
    #puts cmd
    system(cmd)
  end

  def self.cmp_vch_voucher(basename)
    diffcmd = sprintf("cbor2diag.rb tmp/%s.vch >tmp/%s.diag",
                      basename, basename)
    system(diffcmd)

    cmd = sprintf("diff tmp/%s.diag spec/files/%s.diag",
                  basename, basename)
    #puts cmd
    exitcode = system(cmd)
    unless exitcode==0
      puts cmd
    end
  end

  def self.cmp_vch_pretty_voucher(basename)
    diffcmd = sprintf("cbor2pretty.rb tmp/%s.vch >tmp/%s.pretty",
                      basename, basename)
    system(diffcmd)

    cmd = sprintf("diff tmp/%s.pretty spec/files/%s.pretty",
                  basename, basename)
    exitcode = system(cmd)
    unless exitcode==0
      puts cmd
    end
  end

  def self.cmp_vch_detailed_voucher(basename)
    pretty = sprintf("tmp/%s.pretty", basename)
    cvtcmd = sprintf("cbor2pretty.rb tmp/%s.vch >%s",
                      basename, pretty)
    system(cvtcmd)
    diffcmd = sprintf("diff %s spec/files/%s.pretty",
                      pretty, basename)
    exitcode = system(cmd)
    unless exitcode==0
      puts cmd
      return exitcode
    end

    # grab the tenth line, and convert it back to cbor, for decoding.
    n=0
    signedcbor=nil
    IO.readlines(pretty).each { |line|
      n += 1
      next unless n==10
      signedcbor = line.sub(/#.*/, '').scan(/[0-9a-fA-F][0-9a-fA-F]/).map {|b| b.to_i(16).chr(Encoding::BINARY)}.join
      break
    }
    outfile=sprintf("tmp/%s.bag", basename)
    bag2pretty=sprintf("tmp/%s.bag.pretty", basename)
    open(outfile, "wb") {|f| f.syswrite signedcbor }
    bagdcode = sprintf("cbor2pretty.rb %s >%s", outfile, bag2pretty)
    system(bagdcode)
    diff2cmd= sprintf("diff %s spec/files/%s.bag.pretty",
                      bag2pretty, basename)
    exitcode = system(diff2cmd)
    unless exitcode==0
      puts diff2cmd
      return exitcode
    end
  end

  def self.cmp_vch_file(token, basename)
    ofile = File.join(tmpdir, basename + ".vch")
    File.open(ofile, "wb") do |f|     f.write token      end
    return cmp_vch_voucher(basename)
  end


end


