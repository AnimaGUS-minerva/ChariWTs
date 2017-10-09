module Chariwt
  def self.cmp_pkcs_file(smime, base)
    ofile = File.join("tmp", base + ".pkcs")
    otfile = File.join("tmp", base+ ".txt")

    File.open(ofile, "w") do |f|     f.puts smime      end

    location = File.dirname(__FILE__) + "/../bin"
    #puts "Location is: #{location}"
    system("#{location}/pkcs2json #{ofile} #{otfile}")
    cmd = "diff #{otfile} spec/files/#{base}.txt"
    puts cmd
    system(cmd)
  end
end


