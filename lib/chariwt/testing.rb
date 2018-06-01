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

    File.open(ofile, "w") do |f|     f.write smime      end

    location = File.dirname(__FILE__) + "/../../bin"
    #puts "Location is: #{location}, wrote to #{ofile}, #{otfile}, #{base}"
    system("#{location}/pkcs2json #{ofile} #{otfile} #{certfile}")
    cmd = "diff #{otfile} spec/files/#{base}.txt"
    #puts cmd
    system(cmd)
  end

  def cmp_vch_voucher(basename)
    diffcmd = sprintf("cbor2diag.rb tmp/%s.vch >tmp/%s.diag",
                      basename, basename)
    system(diffcmd)

    cmd = sprintf("diff tmp/%s.diag spec/files/%s.diag",
                  basename, basename)
    #puts cmd
    system(cmd)
  end


end


