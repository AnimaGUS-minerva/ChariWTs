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
    cmd0 = "#{location}/pkcs2json #{ofile} #{otfile} #{certfile}"
    puts cmd0
    system(cmd0)
    cmd = "diff #{otfile} spec/files/#{base}.txt"
    puts cmd
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
    unless exitcode
      puts cmd
    end
    return exitcode
  end

  def self.cmp_vch_pretty_voucher(basename)
    cvtcmd = sprintf("cbor2pretty.rb tmp/%s.vch >tmp/%s.pretty",
                      basename, basename)
    unless system(cvtcmd)
      puts cvtcmd
      return false
    end

    diffcmd = sprintf("diff tmp/%s.pretty spec/files/%s.pretty",
                  basename, basename)
    exitcode = system(diffcmd)
    unless exitcode
      puts diffcmd
    end
    return exitcode
  end

  def self.cmp_vch_detailed_voucher(basename)
    pretty = sprintf("tmp/%s.pretty", basename)
    cvtcmd = sprintf("cbor2pretty.rb tmp/%s.vch >%s",
                      basename, pretty)
    system(cvtcmd)
    unless system(cvtcmd)
      puts cvtcmd
      return false
    end

    diffcmd = sprintf("diff %s spec/files/%s.pretty",
                      pretty, basename)
    exitcode = system(diffcmd)
    unless exitcode
      puts diffcmd
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

    if signedcbor
      outfile=sprintf("tmp/%s.bag", basename)
      bag2pretty=sprintf("tmp/%s.bag.pretty", basename)
      open(outfile, "wb") {|f| f.syswrite signedcbor }
      bagdcode = sprintf("cbor2pretty.rb %s >%s", outfile, bag2pretty)
      unless system(bagdcode)
        puts bagdcode
        return false
      end
      diff2cmd= sprintf("diff %s spec/files/%s.bag.pretty",
                        bag2pretty, basename)
      exitcode = system(diff2cmd)
      unless exitcode
        puts diff2cmd
      end
      return exitcode
    else
      return true
    end
  end

  def self.cmp_vch_file(token, basename)
    ofile = File.join(tmpdir, basename + ".vch")
    File.open(ofile, "wb") do |f|     f.write token      end
    return cmp_vch_detailed_voucher(basename)
  end

  def self.cmp_signing_record(record, basename)
    outname="#{basename}.example.json"
    File.open("tmp/#{outname}", "w") {|f|
      out=record.to_s.gsub(",",",\n")
      f.puts out
    }
    diffcmd = sprintf("diff tmp/%s spec/files/%s",outname,outname)
    exitcode = system(diffcmd)
    unless exitcode
      puts diffcmd
    end
    return exitcode
  end

end


